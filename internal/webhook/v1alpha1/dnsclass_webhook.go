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
var dnsclasslog = logf.Log.WithName("dnsclass-resource")

// SetupDNSClassWebhookWithManager registers the webhook for DNSClass in the manager.
func SetupDNSClassWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&dnsv1alpha1.DNSClass{}).
		WithValidator(&DNSClassCustomValidator{}).
		WithDefaulter(&DNSClassCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-dns-homelab-mortenolsen-pro-v1alpha1-dnsclass,mutating=true,failurePolicy=fail,sideEffects=None,groups=dns.homelab.mortenolsen.pro,resources=dnsclasses,verbs=create;update,versions=v1alpha1,name=mdnsclass-v1alpha1.kb.io,admissionReviewVersions=v1

// DNSClassCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind DNSClass when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type DNSClassCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &DNSClassCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind DNSClass.
func (d *DNSClassCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	dnsclass, ok := obj.(*dnsv1alpha1.DNSClass)

	if !ok {
		return fmt.Errorf("expected an DNSClass object but got %T", obj)
	}
	dnsclasslog.Info("Defaulting for DNSClass", "name", dnsclass.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-dns-homelab-mortenolsen-pro-v1alpha1-dnsclass,mutating=false,failurePolicy=fail,sideEffects=None,groups=dns.homelab.mortenolsen.pro,resources=dnsclasses,verbs=create;update,versions=v1alpha1,name=vdnsclass-v1alpha1.kb.io,admissionReviewVersions=v1

// DNSClassCustomValidator struct is responsible for validating the DNSClass resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type DNSClassCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &DNSClassCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type DNSClass.
func (v *DNSClassCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	dnsclass, ok := obj.(*dnsv1alpha1.DNSClass)
	if !ok {
		return nil, fmt.Errorf("expected a DNSClass object but got %T", obj)
	}
	dnsclasslog.Info("Validation for DNSClass upon creation", "name", dnsclass.GetName())

	return nil, validateDNSClass(dnsclass)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type DNSClass.
func (v *DNSClassCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	dnsclass, ok := newObj.(*dnsv1alpha1.DNSClass)
	if !ok {
		return nil, fmt.Errorf("expected a DNSClass object for the newObj but got %T", newObj)
	}
	dnsclasslog.Info("Validation for DNSClass upon update", "name", dnsclass.GetName())

	return nil, validateDNSClass(dnsclass)
}

// validateDNSClass validates DNSClass spec
func validateDNSClass(dnsclass *dnsv1alpha1.DNSClass) error {
	// Validate server URL
	if dnsclass.Spec.Server == "" {
		return fmt.Errorf("spec.server is required")
	}

	// Basic URL validation (must start with http:// or https://)
	if !strings.HasPrefix(dnsclass.Spec.Server, "http://") && !strings.HasPrefix(dnsclass.Spec.Server, "https://") {
		return fmt.Errorf("spec.server must be a valid HTTP or HTTPS URL")
	}

	// Validate HMAC auth configuration
	if dnsclass.Spec.HMACAuth != nil {
		hasSecretRef := dnsclass.Spec.HMACAuth.SecretRef != nil
		hasSecret := dnsclass.Spec.HMACAuth.Secret != nil

		if !hasSecretRef && !hasSecret {
			return fmt.Errorf("hmacAuth must have either secretRef or secret")
		}

		if hasSecretRef && hasSecret {
			return fmt.Errorf("hmacAuth cannot have both secretRef and secret")
		}

		if hasSecretRef {
			if dnsclass.Spec.HMACAuth.SecretRef.Name == "" {
				return fmt.Errorf("hmacAuth.secretRef.name is required")
			}
			if dnsclass.Spec.HMACAuth.SecretRef.Namespace == "" {
				return fmt.Errorf("hmacAuth.secretRef.namespace is required")
			}
			if dnsclass.Spec.HMACAuth.SecretRef.Key == "" {
				return fmt.Errorf("hmacAuth.secretRef.key is required")
			}
		}

		// Validate algorithm
		if dnsclass.Spec.HMACAuth.Algorithm != "" {
			if dnsclass.Spec.HMACAuth.Algorithm != "SHA256" && dnsclass.Spec.HMACAuth.Algorithm != "SHA512" {
				return fmt.Errorf("hmacAuth.algorithm must be SHA256 or SHA512")
			}
		}
	}

	return nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type DNSClass.
func (v *DNSClassCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	dnsclass, ok := obj.(*dnsv1alpha1.DNSClass)
	if !ok {
		return nil, fmt.Errorf("expected a DNSClass object but got %T", obj)
	}
	dnsclasslog.Info("Validation for DNSClass upon deletion", "name", dnsclass.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
