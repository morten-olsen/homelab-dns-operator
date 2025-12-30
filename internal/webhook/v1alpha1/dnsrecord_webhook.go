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

package v1alpha1

import (
	"context"
	"fmt"
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	dnsv1alpha1 "github.com/mortenolsen/dns-operator/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var dnsrecordlog = logf.Log.WithName("dnsrecord-resource")

// SetupDNSRecordWebhookWithManager registers the webhook for DNSRecord in the manager.
func SetupDNSRecordWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&dnsv1alpha1.DNSRecord{}).
		WithValidator(&DNSRecordCustomValidator{}).
		WithDefaulter(&DNSRecordCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-dns-homelab-mortenolsen-pro-v1alpha1-dnsrecord,mutating=true,failurePolicy=fail,sideEffects=None,groups=dns.homelab.mortenolsen.pro,resources=dnsrecords,verbs=create;update,versions=v1alpha1,name=mdnsrecord-v1alpha1.kb.io,admissionReviewVersions=v1

// DNSRecordCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind DNSRecord when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type DNSRecordCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &DNSRecordCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind DNSRecord.
func (d *DNSRecordCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	dnsrecord, ok := obj.(*dnsv1alpha1.DNSRecord)

	if !ok {
		return fmt.Errorf("expected an DNSRecord object but got %T", obj)
	}
	dnsrecordlog.Info("Defaulting for DNSRecord", "name", dnsrecord.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-dns-homelab-mortenolsen-pro-v1alpha1-dnsrecord,mutating=false,failurePolicy=fail,sideEffects=None,groups=dns.homelab.mortenolsen.pro,resources=dnsrecords,verbs=create;update,versions=v1alpha1,name=vdnsrecord-v1alpha1.kb.io,admissionReviewVersions=v1

// DNSRecordCustomValidator struct is responsible for validating the DNSRecord resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type DNSRecordCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &DNSRecordCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type DNSRecord.
func (v *DNSRecordCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	dnsrecord, ok := obj.(*dnsv1alpha1.DNSRecord)
	if !ok {
		return nil, fmt.Errorf("expected a DNSRecord object but got %T", obj)
	}
	dnsrecordlog.Info("Validation for DNSRecord upon creation", "name", dnsrecord.GetName())

	return nil, validateDNSRecord(dnsrecord)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type DNSRecord.
func (v *DNSRecordCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	dnsrecord, ok := newObj.(*dnsv1alpha1.DNSRecord)
	if !ok {
		return nil, fmt.Errorf("expected a DNSRecord object for the newObj but got %T", newObj)
	}
	dnsrecordlog.Info("Validation for DNSRecord upon update", "name", dnsrecord.GetName())

	return nil, validateDNSRecord(dnsrecord)
}

// validateDNSRecord validates DNSRecord spec
func validateDNSRecord(dnsrecord *dnsv1alpha1.DNSRecord) error {
	// Validate required fields
	if dnsrecord.Spec.Type == "" {
		return fmt.Errorf("spec.type is required")
	}

	if dnsrecord.Spec.Domain == "" {
		return fmt.Errorf("spec.domain is required")
	}

	if dnsrecord.Spec.Subdomain == "" {
		return fmt.Errorf("spec.subdomain is required")
	}

	if len(dnsrecord.Spec.Values) == 0 {
		return fmt.Errorf("spec.values must have at least one value")
	}

	if dnsrecord.Spec.DNSClassRef.Name == "" {
		return fmt.Errorf("spec.dnsClassRef.name is required")
	}

	// Validate domain format (basic check)
	if !isValidDomain(dnsrecord.Spec.Domain) {
		return fmt.Errorf("spec.domain must be a valid domain name")
	}

	// Validate subdomain format
	if dnsrecord.Spec.Subdomain != "@" && !isValidSubdomain(dnsrecord.Spec.Subdomain) {
		return fmt.Errorf("spec.subdomain must be '@' or a valid subdomain")
	}

	// Type-specific validation
	switch dnsrecord.Spec.Type {
	case dnsv1alpha1.DNSRecordTypeA:
		return validateARecord(dnsrecord)
	case dnsv1alpha1.DNSRecordTypeAAAA:
		return validateAAAARecord(dnsrecord)
	case dnsv1alpha1.DNSRecordTypeCNAME:
		return validateCNAMERecord(dnsrecord)
	case dnsv1alpha1.DNSRecordTypeTXT:
		return validateTXTRecord(dnsrecord)
	case dnsv1alpha1.DNSRecordTypeMX:
		return validateMXRecord(dnsrecord)
	case dnsv1alpha1.DNSRecordTypeSRV:
		return validateSRVRecord(dnsrecord)
	case dnsv1alpha1.DNSRecordTypeNS:
		return validateNSRecord(dnsrecord)
	default:
		return fmt.Errorf("unsupported record type: %s", dnsrecord.Spec.Type)
	}
}

// validateARecord validates A record values
func validateARecord(dnsrecord *dnsv1alpha1.DNSRecord) error {
	for i, value := range dnsrecord.Spec.Values {
		if net.ParseIP(value) == nil || net.ParseIP(value).To4() == nil {
			return fmt.Errorf("spec.values[%d] must be a valid IPv4 address", i)
		}
	}
	return nil
}

// validateAAAARecord validates AAAA record values
func validateAAAARecord(dnsrecord *dnsv1alpha1.DNSRecord) error {
	for i, value := range dnsrecord.Spec.Values {
		if net.ParseIP(value) == nil || net.ParseIP(value).To16() == nil || net.ParseIP(value).To4() != nil {
			return fmt.Errorf("spec.values[%d] must be a valid IPv6 address", i)
		}
	}
	return nil
}

// validateCNAMERecord validates CNAME record values
func validateCNAMERecord(dnsrecord *dnsv1alpha1.DNSRecord) error {
	if len(dnsrecord.Spec.Values) != 1 {
		return fmt.Errorf("CNAME records must have exactly one value")
	}
	if !isValidDomain(dnsrecord.Spec.Values[0]) {
		return fmt.Errorf("spec.values[0] must be a valid domain name")
	}
	return nil
}

// validateTXTRecord validates TXT record values
func validateTXTRecord(dnsrecord *dnsv1alpha1.DNSRecord) error {
	// TXT records can have any text values, so we just check they're not empty
	for i, value := range dnsrecord.Spec.Values {
		if value == "" {
			return fmt.Errorf("spec.values[%d] cannot be empty", i)
		}
	}
	return nil
}

// validateMXRecord validates MX record values
func validateMXRecord(dnsrecord *dnsv1alpha1.DNSRecord) error {
	if dnsrecord.Spec.Metadata == nil || dnsrecord.Spec.Metadata.Priority == nil {
		return fmt.Errorf("MX records must have spec.metadata.priority")
	}
	for i, value := range dnsrecord.Spec.Values {
		if !isValidDomain(value) {
			return fmt.Errorf("spec.values[%d] must be a valid domain name", i)
		}
	}
	return nil
}

// validateSRVRecord validates SRV record values
func validateSRVRecord(dnsrecord *dnsv1alpha1.DNSRecord) error {
	if dnsrecord.Spec.Metadata == nil {
		return fmt.Errorf("SRV records must have spec.metadata")
	}
	if dnsrecord.Spec.Metadata.Priority == nil {
		return fmt.Errorf("SRV records must have spec.metadata.priority")
	}
	if dnsrecord.Spec.Metadata.Weight == nil {
		return fmt.Errorf("SRV records must have spec.metadata.weight")
	}
	if dnsrecord.Spec.Metadata.Port == nil {
		return fmt.Errorf("SRV records must have spec.metadata.port")
	}
	for i, value := range dnsrecord.Spec.Values {
		if !isValidDomain(value) {
			return fmt.Errorf("spec.values[%d] must be a valid domain name", i)
		}
	}
	return nil
}

// validateNSRecord validates NS record values
func validateNSRecord(dnsrecord *dnsv1alpha1.DNSRecord) error {
	for i, value := range dnsrecord.Spec.Values {
		if !isValidDomain(value) {
			return fmt.Errorf("spec.values[%d] must be a valid domain name", i)
		}
	}
	return nil
}

// isValidDomain performs basic domain name validation
func isValidDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		// Check for valid characters (letters, numbers, hyphens)
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// isValidSubdomain performs basic subdomain validation
func isValidSubdomain(subdomain string) bool {
	if subdomain == "" || len(subdomain) > 253 {
		return false
	}
	// Check for valid characters (letters, numbers, hyphens, underscores, dots)
	// Underscores and dots are allowed for SRV records (e.g., "_service._tcp")
	// Split by dots and validate each part
	parts := strings.Split(subdomain, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		// Check each part for valid characters
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type DNSRecord.
func (v *DNSRecordCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	dnsrecord, ok := obj.(*dnsv1alpha1.DNSRecord)
	if !ok {
		return nil, fmt.Errorf("expected a DNSRecord object but got %T", obj)
	}
	dnsrecordlog.Info("Validation for DNSRecord upon deletion", "name", dnsrecord.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
