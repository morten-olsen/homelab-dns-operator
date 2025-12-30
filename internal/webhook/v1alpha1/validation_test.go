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
	"testing"

	dnsv1alpha1 "github.com/mortenolsen/dns-operator/api/v1alpha1"
)

func TestValidateDNSRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  *dnsv1alpha1.DNSRecord
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid A record",
			record: &dnsv1alpha1.DNSRecord{
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeA,
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"192.168.1.100"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing type",
			record: &dnsv1alpha1.DNSRecord{
				Spec: dnsv1alpha1.DNSRecordSpec{
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"192.168.1.100"},
				},
			},
			wantErr: true,
			errMsg:  "spec.type is required",
		},
		{
			name: "invalid IPv4 for A record",
			record: &dnsv1alpha1.DNSRecord{
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeA,
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"invalid-ip"},
				},
			},
			wantErr: true,
			errMsg:  "must be a valid IPv4 address",
		},
		{
			name: "CNAME with multiple values",
			record: &dnsv1alpha1.DNSRecord{
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeCNAME,
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"target1.example.com", "target2.example.com"},
				},
			},
			wantErr: true,
			errMsg:  "exactly one value",
		},
		{
			name: "MX without priority",
			record: &dnsv1alpha1.DNSRecord{
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeMX,
					Domain:    "example.com",
					Subdomain: "@",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"mail.example.com"},
				},
			},
			wantErr: true,
			errMsg:  "spec.metadata.priority",
		},
		{
			name: "valid MX record",
			record: &dnsv1alpha1.DNSRecord{
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeMX,
					Domain:    "example.com",
					Subdomain: "@",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"mail.example.com"},
					Metadata: &dnsv1alpha1.RecordMetadata{
						Priority: int32Ptr(10),
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDNSRecord(tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDNSRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || err.Error() == "" {
					t.Errorf("validateDNSRecord() expected error message containing %q, got nil", tt.errMsg)
					return
				}
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("validateDNSRecord() error = %v, want error message containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

func TestValidateDNSClass(t *testing.T) {
	tests := []struct {
		name     string
		dnsclass *dnsv1alpha1.DNSClass
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid DNSClass",
			dnsclass: &dnsv1alpha1.DNSClass{
				Spec: dnsv1alpha1.DNSClassSpec{
					Server: "http://example.com:7100",
				},
			},
			wantErr: false,
		},
		{
			name: "missing server",
			dnsclass: &dnsv1alpha1.DNSClass{
				Spec: dnsv1alpha1.DNSClassSpec{
					Server: "",
				},
			},
			wantErr: true,
			errMsg:  "spec.server is required",
		},
		{
			name: "invalid server URL",
			dnsclass: &dnsv1alpha1.DNSClass{
				Spec: dnsv1alpha1.DNSClassSpec{
					Server: "invalid-url",
				},
			},
			wantErr: true,
			errMsg:  "must be a valid HTTP or HTTPS URL",
		},
		{
			name: "HMAC auth with both secretRef and secret",
			dnsclass: &dnsv1alpha1.DNSClass{
				Spec: dnsv1alpha1.DNSClassSpec{
					Server: "http://example.com:7100",
					HMACAuth: &dnsv1alpha1.HMACAuth{
						SecretRef: &dnsv1alpha1.SecretRef{
							Name:      "test-secret",
							Namespace: "default",
							Key:       "key",
						},
						Secret: stringPtr("direct-secret"),
					},
				},
			},
			wantErr: true,
			errMsg:  "cannot have both secretRef and secret",
		},
		{
			name: "HMAC auth with invalid algorithm",
			dnsclass: &dnsv1alpha1.DNSClass{
				Spec: dnsv1alpha1.DNSClassSpec{
					Server: "http://example.com:7100",
					HMACAuth: &dnsv1alpha1.HMACAuth{
						Secret:    stringPtr("test-secret"),
						Algorithm: "INVALID",
					},
				},
			},
			wantErr: true,
			errMsg:  "must be SHA256 or SHA512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDNSClass(tt.dnsclass)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDNSClass() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || err.Error() == "" {
					t.Errorf("validateDNSClass() expected error message containing %q, got nil", tt.errMsg)
					return
				}
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("validateDNSClass() error = %v, want error message containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

func int32Ptr(i int32) *int32 {
	return &i
}

func stringPtr(s string) *string {
	return &s
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || len(s) > 0 && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
