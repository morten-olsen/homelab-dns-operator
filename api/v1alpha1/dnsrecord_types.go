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

// DNSRecordType represents a DNS record type
// +kubebuilder:validation:Enum=A;AAAA;CNAME;TXT;MX;SRV;NS
type DNSRecordType string

const (
	DNSRecordTypeA     DNSRecordType = "A"
	DNSRecordTypeAAAA  DNSRecordType = "AAAA"
	DNSRecordTypeCNAME DNSRecordType = "CNAME"
	DNSRecordTypeTXT   DNSRecordType = "TXT"
	DNSRecordTypeMX    DNSRecordType = "MX"
	DNSRecordTypeSRV   DNSRecordType = "SRV"
	DNSRecordTypeNS    DNSRecordType = "NS"
)

// DNSClassRef references a DNSClass resource
type DNSClassRef struct {
	// Name is the name of the DNSClass
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// RecordMetadata contains record-specific metadata
type RecordMetadata struct {
	// Priority is used for MX and SRV records
	// +kubebuilder:validation:Minimum=0
	// +optional
	Priority *int32 `json:"priority,omitempty"`

	// Weight is used for SRV records
	// +kubebuilder:validation:Minimum=0
	// +optional
	Weight *int32 `json:"weight,omitempty"`

	// Port is used for SRV records
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port *int32 `json:"port,omitempty"`
}

// DNSRecordSpec defines the desired state of DNSRecord
type DNSRecordSpec struct {
	// Type is the DNS record type (A, CNAME, AAAA, TXT, MX, SRV, NS)
	// +kubebuilder:validation:Required
	Type DNSRecordType `json:"type"`

	// Domain is the domain name (e.g., "example.com")
	// +kubebuilder:validation:Required
	Domain string `json:"domain"`

	// Subdomain is the subdomain (use "@" for root domain, or "www" for www.example.com)
	// +kubebuilder:validation:Required
	Subdomain string `json:"subdomain"`

	// DNSClassRef references the DNSClass to use
	// +kubebuilder:validation:Required
	DNSClassRef DNSClassRef `json:"dnsClassRef"`

	// Values are the record value(s)
	// For A records: IPv4 addresses (array for multiple values)
	// For CNAME: single canonical name
	// For AAAA: IPv6 addresses (array)
	// For TXT: text strings (array)
	// +kubebuilder:validation:MinItems=1
	// +required
	Values []string `json:"values"`

	// TTL overrides the DNSClass default TTL
	// +kubebuilder:validation:Minimum=1
	// +optional
	TTL *int32 `json:"ttl,omitempty"`

	// Description is an optional description/notes
	// +optional
	Description string `json:"description,omitempty"`

	// Metadata contains record-specific metadata
	// For MX records: priority
	// For SRV records: priority, weight, port
	// +optional
	Metadata *RecordMetadata `json:"metadata,omitempty"`
}

// RecordState represents the current state of a DNS record
// +kubebuilder:validation:Enum=Created;Updated;Deleted;Error;Pending
type RecordState string

const (
	RecordStateCreated RecordState = "Created"
	RecordStateUpdated RecordState = "Updated"
	RecordStateDeleted RecordState = "Deleted"
	RecordStateError   RecordState = "Error"
	RecordStatePending RecordState = "Pending"
)

// RecordError represents error details
type RecordError struct {
	// Code is the error code
	// +optional
	Code string `json:"code,omitempty"`

	// Message is the error message
	// +optional
	Message string `json:"message,omitempty"`

	// Timestamp is when the error occurred
	// +optional
	Timestamp *metav1.Time `json:"timestamp,omitempty"`
}

// DNSRecordStatus defines the observed state of DNSRecord.
type DNSRecordStatus struct {
	// Conditions represent the current state of the DNSRecord resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// State is the current state of the record
	// +optional
	State RecordState `json:"state,omitempty"`

	// LastSyncTime is the timestamp of the last sync
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// FQDN is the full DNS name (domain + subdomain)
	// +optional
	FQDN string `json:"fqdn,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed DNSRecord
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Error contains error details if any
	// +optional
	Error *RecordError `json:"error,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced

// DNSRecord is the Schema for the dnsrecords API
type DNSRecord struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of DNSRecord
	// +required
	Spec DNSRecordSpec `json:"spec"`

	// status defines the observed state of DNSRecord
	// +optional
	Status DNSRecordStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// DNSRecordList contains a list of DNSRecord
type DNSRecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []DNSRecord `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DNSRecord{}, &DNSRecordList{})
}
