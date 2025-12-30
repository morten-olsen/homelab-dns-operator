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
	"net/http"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	dnsv1alpha1 "github.com/mortenolsen/dns-operator/api/v1alpha1"
	"github.com/mortenolsen/dns-operator/pkg/dnsclient"
	"github.com/mortenolsen/dns-operator/pkg/secret"
)

const (
	// DefaultHealthCheckInterval is the default interval for health checks
	DefaultHealthCheckInterval = 10 * time.Minute
	// EnvHealthCheckInterval is the environment variable for health check interval
	EnvHealthCheckInterval = "DNS_CLASS_HEALTH_CHECK_INTERVAL"
	// serverErrorReason is the reason for server errors
	serverErrorReason = "ServerError"
)

// DNSClassReconciler reconciles a DNSClass object
type DNSClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=dns.homelab.mortenolsen.pro,resources=dnsclasses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dns.homelab.mortenolsen.pro,resources=dnsclasses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dns.homelab.mortenolsen.pro,resources=dnsclasses/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *DNSClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	dnsClass := &dnsv1alpha1.DNSClass{}
	if err := r.Get(ctx, req.NamespacedName, dnsClass); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Get health check interval from environment variable
	healthCheckInterval := DefaultHealthCheckInterval
	if intervalStr := os.Getenv(EnvHealthCheckInterval); intervalStr != "" {
		if parsed, err := time.ParseDuration(intervalStr); err == nil {
			healthCheckInterval = parsed
		} else {
			log.Error(err, "failed to parse health check interval, using default", "interval", intervalStr)
		}
	}

	// Get HMAC secret if configured
	hmacSecret, hmacAlgorithm, err := secret.GetHMACSecret(ctx, r.Client, dnsClass.Spec.HMACAuth)
	if err != nil {
		log.Error(err, "failed to get HMAC secret")
		// Update status with error
		r.updateStatus(ctx, dnsClass, false, "SecretNotFound", fmt.Sprintf("Failed to get HMAC secret: %v", err), nil)
		// Retry after a short delay
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

	// Perform health check
	healthResp, err := dnsClient.CheckHealth(ctx)
	now := metav1.Now()
	var healthStatus dnsv1alpha1.HealthStatus
	var healthMessage string
	var ready bool
	var reason string
	var message string

	if err != nil {
		log.Error(err, "health check failed")
		healthStatus = dnsv1alpha1.HealthStatusUnhealthy
		healthMessage = err.Error()
		reason = "ServerUnreachable"
		if dnsErr, ok := err.(*dnsclient.Error); ok {
			if dnsErr.Status == http.StatusServiceUnavailable {
				reason = "ServerUnhealthy"
			} else if dnsErr.Status >= 500 {
				reason = serverErrorReason
			}
		}
		message = fmt.Sprintf("Health check failed: %v", err)
	} else {
		if healthResp.Status == "healthy" {
			healthStatus = dnsv1alpha1.HealthStatusHealthy
			healthMessage = healthResp.Message
			ready = true
			reason = "ServerHealthy"
			message = "DNS server is healthy and reachable"
		} else {
			healthStatus = dnsv1alpha1.HealthStatusUnhealthy
			healthMessage = healthResp.Message
			reason = "ServerUnhealthy"
			message = fmt.Sprintf("DNS server is unhealthy: %s", healthResp.Message)
		}
	}

	// Update status
	r.updateStatus(ctx, dnsClass, ready, reason, message, &dnsv1alpha1.Health{
		Status:    healthStatus,
		LastCheck: &now,
		Message:   healthMessage,
	})

	// Requeue after health check interval
	return ctrl.Result{RequeueAfter: healthCheckInterval}, nil
}

// updateStatus updates the DNSClass status
func (r *DNSClassReconciler) updateStatus(ctx context.Context, dnsClass *dnsv1alpha1.DNSClass, ready bool, reason, message string, health *dnsv1alpha1.Health) {
	log := logf.FromContext(ctx)

	now := metav1.Now()
	generation := dnsClass.Generation

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
	for i, c := range dnsClass.Status.Conditions {
		if c.Type == "Ready" {
			// Only update LastTransitionTime if status changed
			if c.Status == condition.Status {
				condition.LastTransitionTime = c.LastTransitionTime
			}
			dnsClass.Status.Conditions[i] = condition
			found = true
			break
		}
	}

	if !found {
		dnsClass.Status.Conditions = append(dnsClass.Status.Conditions, condition)
	}

	// Update other status fields
	dnsClass.Status.LastHealthCheck = &now
	dnsClass.Status.Health = health
	dnsClass.Status.ObservedGeneration = generation

	if err := r.Status().Update(ctx, dnsClass); err != nil {
		log.Error(err, "failed to update DNSClass status")
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *DNSClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dnsv1alpha1.DNSClass{}).
		Named("dnsclass").
		Complete(r)
}
