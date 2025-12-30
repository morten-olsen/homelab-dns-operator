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
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	dnsv1alpha1 "github.com/mortenolsen/dns-operator/api/v1alpha1"
)

func TestDNSRecordWebhook(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "DNSRecord Webhook Suite")
}

var _ = Describe("DNSRecord Webhook Validation", func() {
	var validator *DNSRecordCustomValidator

	BeforeEach(func() {
		validator = &DNSRecordCustomValidator{}
	})

	Context("Valid DNSRecord", func() {
		It("should accept a valid A record", func() {
			record := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record",
					Namespace: "default",
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeA,
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"192.168.1.100"},
				},
			}

			warnings, err := validator.ValidateCreate(context.Background(), record)
			Expect(err).NotTo(HaveOccurred())
			Expect(warnings).To(BeEmpty())
		})

		It("should accept a valid CNAME record", func() {
			record := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record",
					Namespace: "default",
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeCNAME,
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"target.example.com"},
				},
			}

			warnings, err := validator.ValidateCreate(context.Background(), record)
			Expect(err).NotTo(HaveOccurred())
			Expect(warnings).To(BeEmpty())
		})
	})

	Context("Invalid DNSRecord", func() {
		It("should reject missing type", func() {
			record := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record",
					Namespace: "default",
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"192.168.1.100"},
				},
			}

			_, err := validator.ValidateCreate(context.Background(), record)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.type is required"))
		})

		It("should reject invalid IPv4 address for A record", func() {
			record := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record",
					Namespace: "default",
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeA,
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"invalid-ip"},
				},
			}

			_, err := validator.ValidateCreate(context.Background(), record)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be a valid IPv4 address"))
		})

		It("should reject CNAME with multiple values", func() {
			record := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record",
					Namespace: "default",
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeCNAME,
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"target1.example.com", "target2.example.com"},
				},
			}

			_, err := validator.ValidateCreate(context.Background(), record)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("exactly one value"))
		})

		It("should reject MX record without priority", func() {
			record := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record",
					Namespace: "default",
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeMX,
					Domain:    "example.com",
					Subdomain: "@",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"mail.example.com"},
				},
			}

			_, err := validator.ValidateCreate(context.Background(), record)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.metadata.priority"))
		})

		It("should reject SRV record without required metadata", func() {
			record := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record",
					Namespace: "default",
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeSRV,
					Domain:    "example.com",
					Subdomain: "_service._tcp",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass",
					},
					Values: []string{"target.example.com"},
				},
			}

			_, err := validator.ValidateCreate(context.Background(), record)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.metadata"))
		})
	})
})
