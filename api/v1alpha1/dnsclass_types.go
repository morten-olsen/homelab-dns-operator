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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// HMACAuth defines HMAC-based authentication configuration
type HMACAuth struct {
	// SecretRef references a Kubernetes Secret containing the HMAC shared secret
	// +optional
	SecretRef *SecretRef `json:"secretRef,omitempty"`

	// Secret is a direct secret value (less secure, for testing only)
	// +optional
	Secret *string `json:"secret,omitempty"`

	// Algorithm specifies the HMAC algorithm to use (default: SHA256)
	// +kubebuilder:validation:Enum=SHA256;SHA512
	// +kubebuilder:default=SHA256
	// +optional
	Algorithm string `json:"algorithm,omitempty"`
}

// SecretRef references a Kubernetes Secret
type SecretRef struct {
	// Name is the name of the Secret
	// +required
	Name string `json:"name"`

	// Namespace is the namespace containing the Secret
	// +required
	Namespace string `json:"namespace"`

	// Key is the key within the Secret containing the shared secret
	// +required
	Key string `json:"key"`
}

// DNSClassSpec defines the desired state of DNSClass
type DNSClassSpec struct {
	// Server is the URL for the DNS provider webhook service
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https?://.+`
	Server string `json:"server"`

	// DefaultTTL is the default TTL for records using this DNSClass
	// +kubebuilder:validation:Minimum=1
	// +optional
	DefaultTTL *int32 `json:"defaultTTL,omitempty"`

	// TimeoutSeconds is the connection timeout in seconds
	// +kubebuilder:validation:Minimum=1
	// +optional
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`

	// HMACAuth configures HMAC-based authentication for request integrity verification
	// +optional
	HMACAuth *HMACAuth `json:"hmacAuth,omitempty"`
}

// HealthStatus represents the health status of the DNS server
// +kubebuilder:validation:Enum=Healthy;Unhealthy;Unknown
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "Healthy"
	HealthStatusUnhealthy HealthStatus = "Unhealthy"
	HealthStatusUnknown   HealthStatus = "Unknown"
)

// Health represents the health check information
type Health struct {
	// Status is the health status
	// +optional
	Status HealthStatus `json:"status,omitempty"`

	// LastCheck is the timestamp of the last health check
	// +optional
	LastCheck *metav1.Time `json:"lastCheck,omitempty"`

	// Message is an optional health check message
	// +optional
	Message string `json:"message,omitempty"`
}

// DNSClassStatus defines the observed state of DNSClass.
type DNSClassStatus struct {
	// Conditions represent the current state of the DNSClass resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastHealthCheck is the timestamp of the last health check
	// +optional
	LastHealthCheck *metav1.Time `json:"lastHealthCheck,omitempty"`

	// Health represents the server health status (informational, does not block operations)
	// +optional
	Health *Health `json:"health,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed DNSClass
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// DNSClass is the Schema for the dnsclasses API
type DNSClass struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of DNSClass
	// +required
	Spec DNSClassSpec `json:"spec"`

	// status defines the observed state of DNSClass
	// +optional
	Status DNSClassStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// DNSClassList contains a list of DNSClass
type DNSClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []DNSClass `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DNSClass{}, &DNSClassList{})
}
