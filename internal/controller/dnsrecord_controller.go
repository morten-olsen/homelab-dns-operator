/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	dnsv1alpha1 "github.com/mortenolsen/dns-operator/api/v1alpha1"
	"github.com/mortenolsen/dns-operator/pkg/dnsclient"
	"github.com/mortenolsen/dns-operator/pkg/secret"
)

const (
	// FinalizerName is the finalizer name for DNSRecord
	FinalizerName = "dns.homelab.mortenolsen.pro/finalizer"

	// DefaultRetryBaseDelay is the default base delay for exponential backoff
	DefaultRetryBaseDelay = 5 * time.Second
	// DefaultRetryMaxDelay is the default maximum delay between retries
	DefaultRetryMaxDelay = 60 * time.Second
	// DefaultRetryMaxAttempts is the default maximum number of retry attempts
	DefaultRetryMaxAttempts = 5

	// EnvRetryBaseDelay is the environment variable for retry base delay
	EnvRetryBaseDelay = "DNS_RECORD_RETRY_BASE_DELAY"
	// EnvRetryMaxDelay is the environment variable for retry max delay
	EnvRetryMaxDelay = "DNS_RECORD_RETRY_MAX_DELAY"
	// EnvRetryMaxAttempts is the environment variable for retry max attempts
	EnvRetryMaxAttempts = "DNS_RECORD_RETRY_MAX_ATTEMPTS"
)

// DNSRecordReconciler reconciles a DNSRecord object
type DNSRecordReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=dns.homelab.mortenolsen.pro,resources=dnsrecords,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dns.homelab.mortenolsen.pro,resources=dnsrecords/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dns.homelab.mortenolsen.pro,resources=dnsrecords/finalizers,verbs=update
// +kubebuilder:rbac:groups=dns.homelab.mortenolsen.pro,resources=dnsclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *DNSRecordReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	dnsRecord := &dnsv1alpha1.DNSRecord{}
	if err := r.Get(ctx, req.NamespacedName, dnsRecord); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion
	if !dnsRecord.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, dnsRecord)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(dnsRecord, FinalizerName) {
		controllerutil.AddFinalizer(dnsRecord, FinalizerName)
		if err := r.Update(ctx, dnsRecord); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Get DNSClass
	dnsClass := &dnsv1alpha1.DNSClass{}
	if err := r.Get(ctx, types.NamespacedName{Name: dnsRecord.Spec.DNSClassRef.Name}, dnsClass); err != nil {
		log.Error(err, "failed to get DNSClass")
		fqdn := r.buildFQDN(dnsRecord.Spec.Domain, dnsRecord.Spec.Subdomain)
		r.updateStatusWithError(ctx, dnsRecord, "DNSClassNotFound", fmt.Sprintf("DNSClass %s not found: %v", dnsRecord.Spec.DNSClassRef.Name, err), "DNS_CLASS_NOT_FOUND", err.Error(), fqdn)
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Get HMAC secret if configured
	hmacSecret, hmacAlgorithm, err := secret.GetHMACSecret(ctx, r.Client, dnsClass.Spec.HMACAuth)
	if err != nil {
		log.Error(err, "failed to get HMAC secret")
		fqdn := r.buildFQDN(dnsRecord.Spec.Domain, dnsRecord.Spec.Subdomain)
		r.updateStatusWithError(ctx, dnsRecord, "SecretNotFound", fmt.Sprintf("Failed to get HMAC secret: %v", err), "SECRET_NOT_FOUND", err.Error(), fqdn)
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Create DNS client
	timeout := 30 * time.Second
	if dnsClass.Spec.TimeoutSeconds != nil {
		timeout = time.Duration(*dnsClass.Spec.TimeoutSeconds) * time.Second
	}

	var dnsClient *dnsclient.Client
	if len(hmacSecret) > 0 {
		dnsClient = dnsclient.NewClient(dnsClass.Spec.Server, timeout, hmacSecret, hmacAlgorithm)
	} else {
		dnsClient = dnsclient.NewClient(dnsClass.Spec.Server, timeout, nil, "")
	}

	// Build FQDN
	fqdn := r.buildFQDN(dnsRecord.Spec.Domain, dnsRecord.Spec.Subdomain)

	// Prepare record request
	recordReq := dnsclient.RecordRequest{
		Type:      string(dnsRecord.Spec.Type),
		Domain:    dnsRecord.Spec.Domain,
		Subdomain: dnsRecord.Spec.Subdomain,
		Values:    dnsRecord.Spec.Values,
	}

	// Use TTL from DNSRecord if specified, otherwise use DNSClass default
	if dnsRecord.Spec.TTL != nil {
		recordReq.TTL = dnsRecord.Spec.TTL
	} else if dnsClass.Spec.DefaultTTL != nil {
		recordReq.TTL = dnsClass.Spec.DefaultTTL
	}

	// Upsert record with retry logic
	_, err = r.upsertRecordWithRetry(ctx, dnsClient, recordReq)
	if err != nil {
		log.Error(err, "failed to upsert DNS record")
		dnsErr, ok := err.(*dnsclient.Error)
		if ok {
			var reason string
			switch dnsErr.Status {
			case 400:
				reason = "ValidationFailed"
			case 401:
				reason = "AuthenticationFailed"
			case 500:
				reason = serverErrorReason
			default:
				reason = "ServerUnreachable"
			}
			r.updateStatusWithError(ctx, dnsRecord, reason, fmt.Sprintf("Failed to upsert record: %s", dnsErr.Message), dnsErr.Code, dnsErr.Message, fqdn)
			// Retry with exponential backoff
			return r.calculateRetryResult(), nil
		}
		r.updateStatusWithError(ctx, dnsRecord, serverErrorReason, fmt.Sprintf("Failed to upsert record: %v", err), "SERVER_ERROR", err.Error(), fqdn)
		return r.calculateRetryResult(), nil
	}

	// Update status on success
	state := dnsv1alpha1.RecordStateCreated
	if dnsRecord.Status.State == dnsv1alpha1.RecordStateCreated || dnsRecord.Status.State == dnsv1alpha1.RecordStateUpdated {
		state = dnsv1alpha1.RecordStateUpdated
	}
	r.updateStatus(ctx, dnsRecord, true, "RecordUpdated", "Record created/updated successfully", nil, state, fqdn)

	return ctrl.Result{}, nil
}

// handleDeletion handles DNSRecord deletion
func (r *DNSRecordReconciler) handleDeletion(ctx context.Context, dnsRecord *dnsv1alpha1.DNSRecord) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Get DNSClass
	dnsClass := &dnsv1alpha1.DNSClass{}
	if err := r.Get(ctx, types.NamespacedName{Name: dnsRecord.Spec.DNSClassRef.Name}, dnsClass); err != nil {
		// If DNSClass not found, just remove finalizer
		if client.IgnoreNotFound(err) == nil {
			log.Info("DNSClass not found during deletion, removing finalizer")
			controllerutil.RemoveFinalizer(dnsRecord, FinalizerName)
			return ctrl.Result{}, r.Update(ctx, dnsRecord)
		}
		return ctrl.Result{}, err
	}

	// Get HMAC secret if configured
	hmacSecret, hmacAlgorithm, err := secret.GetHMACSecret(ctx, r.Client, dnsClass.Spec.HMACAuth)
	if err != nil {
		log.Error(err, "failed to get HMAC secret during deletion")
		// Continue with deletion even if secret not found
	}

	// Create DNS client
	timeout := 30 * time.Second
	if dnsClass.Spec.TimeoutSeconds != nil {
		timeout = time.Duration(*dnsClass.Spec.TimeoutSeconds) * time.Second
	}

	var dnsClient *dnsclient.Client
	if len(hmacSecret) > 0 {
		dnsClient = dnsclient.NewClient(dnsClass.Spec.Server, timeout, hmacSecret, hmacAlgorithm)
	} else {
		dnsClient = dnsclient.NewClient(dnsClass.Spec.Server, timeout, nil, "")
	}

	// Delete record
	err = dnsClient.DeleteRecord(ctx, string(dnsRecord.Spec.Type), dnsRecord.Spec.Domain, dnsRecord.Spec.Subdomain)
	if err != nil {
		log.Error(err, "failed to delete DNS record")
		// Retry deletion
		return r.calculateRetryResult(), nil
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(dnsRecord, FinalizerName)
	if err := r.Update(ctx, dnsRecord); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("DNS record deleted successfully")
	return ctrl.Result{}, nil
}

// upsertRecordWithRetry performs upsert with exponential backoff retry logic
func (r *DNSRecordReconciler) upsertRecordWithRetry(ctx context.Context, dnsClient *dnsclient.Client, record dnsclient.RecordRequest) (*dnsclient.RecordResponse, error) {
	baseDelay := DefaultRetryBaseDelay
	maxDelay := DefaultRetryMaxDelay
	maxAttempts := DefaultRetryMaxAttempts

	if delayStr := os.Getenv(EnvRetryBaseDelay); delayStr != "" {
		if parsed, err := time.ParseDuration(delayStr); err == nil {
			baseDelay = parsed
		}
	}
	if delayStr := os.Getenv(EnvRetryMaxDelay); delayStr != "" {
		if parsed, err := time.ParseDuration(delayStr); err == nil {
			maxDelay = parsed
		}
	}
	if attemptsStr := os.Getenv(EnvRetryMaxAttempts); attemptsStr != "" {
		if parsed, err := strconv.Atoi(attemptsStr); err == nil && parsed > 0 {
			maxAttempts = parsed
		}
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		recordResp, err := dnsClient.UpsertRecord(ctx, record)
		if err == nil {
			return recordResp, nil
		}

		lastErr = err
		dnsErr, ok := err.(*dnsclient.Error)
		if ok {
			// Don't retry on validation errors
			if dnsErr.Status == 400 {
				return nil, err
			}
		}

		if attempt < maxAttempts-1 {
			delay := time.Duration(math.Min(float64(baseDelay)*math.Pow(2, float64(attempt)), float64(maxDelay)))
			time.Sleep(delay)
		}
	}

	return nil, lastErr
}

// calculateRetryResult calculates the retry result with exponential backoff
func (r *DNSRecordReconciler) calculateRetryResult() ctrl.Result {
	baseDelay := DefaultRetryBaseDelay

	if delayStr := os.Getenv(EnvRetryBaseDelay); delayStr != "" {
		if parsed, err := time.ParseDuration(delayStr); err == nil {
			baseDelay = parsed
		}
	}

	// Use base delay for first retry
	return ctrl.Result{RequeueAfter: baseDelay}
}

// buildFQDN builds the FQDN from domain and subdomain
func (r *DNSRecordReconciler) buildFQDN(domain, subdomain string) string {
	if subdomain == "@" {
		return domain
	}
	return fmt.Sprintf("%s.%s", subdomain, domain)
}

// updateStatus updates the DNSRecord status
func (r *DNSRecordReconciler) updateStatus(ctx context.Context, dnsRecord *dnsv1alpha1.DNSRecord, ready bool, reason, message string, error *dnsv1alpha1.RecordError, state dnsv1alpha1.RecordState, fqdn string) {
	log := logf.FromContext(ctx)

	now := metav1.Now()
	generation := dnsRecord.Generation

	// Update conditions
	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		ObservedGeneration: generation,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}

	if ready {
		condition.Status = metav1.ConditionTrue
	}

	// Find existing Ready condition
	found := false
	for i, c := range dnsRecord.Status.Conditions {
		if c.Type == "Ready" {
			// Only update LastTransitionTime if status changed
			if c.Status == condition.Status {
				condition.LastTransitionTime = c.LastTransitionTime
			}
			dnsRecord.Status.Conditions[i] = condition
			found = true
			break
		}
	}

	if !found {
		dnsRecord.Status.Conditions = append(dnsRecord.Status.Conditions, condition)
	}

	// Update other status fields
	dnsRecord.Status.State = state
	dnsRecord.Status.LastSyncTime = &now
	dnsRecord.Status.FQDN = fqdn
	dnsRecord.Status.ObservedGeneration = generation
	if error != nil && error.Code != "" {
		dnsRecord.Status.Error = error
	} else {
		dnsRecord.Status.Error = nil
	}

	if err := r.Status().Update(ctx, dnsRecord); err != nil {
		log.Error(err, "failed to update DNSRecord status")
	}
}

// updateStatusWithError updates the DNSRecord status with error details
func (r *DNSRecordReconciler) updateStatusWithError(ctx context.Context, dnsRecord *dnsv1alpha1.DNSRecord, reason, message, errorCode, errorMessage, fqdn string) {
	now := metav1.Now()
	error := &dnsv1alpha1.RecordError{
		Code:      errorCode,
		Message:   errorMessage,
		Timestamp: &now,
	}
	r.updateStatus(ctx, dnsRecord, false, reason, message, error, dnsv1alpha1.RecordStateError, fqdn)
}

// SetupWithManager sets up the controller with the Manager.
func (r *DNSRecordReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dnsv1alpha1.DNSRecord{}).
		Named("dnsrecord").
		Complete(r)
}
