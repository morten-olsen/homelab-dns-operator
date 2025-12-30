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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	dnsv1alpha1 "github.com/mortenolsen/dns-operator/api/v1alpha1"
	"github.com/mortenolsen/dns-operator/pkg/dnsclient"
	"github.com/mortenolsen/dns-operator/pkg/hmac"
)

var _ = Describe("DNSClass Controller Integration", func() {
	var mockServer *dnsclient.MockDNSServer
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
		mockServer = dnsclient.NewMockDNSServer(nil, "")
		DeferCleanup(func() {
			mockServer.Close()
		})
	})

	It("should perform health check and update status", func() {
		dnsClass := &dnsv1alpha1.DNSClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-dnsclass",
			},
			Spec: dnsv1alpha1.DNSClassSpec{
				Server: mockServer.URL(),
			},
		}

		Expect(k8sClient.Create(ctx, dnsClass)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, dnsClass)
		})

		reconciler := &DNSClassReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}

		// Reconcile
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test-dnsclass"},
		})
		Expect(err).NotTo(HaveOccurred())

		// Wait for status update
		Eventually(func() bool {
			updated := &dnsv1alpha1.DNSClass{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: "test-dnsclass"}, updated)
			if err != nil {
				return false
			}
			return updated.Status.Health != nil && updated.Status.Health.Status == dnsv1alpha1.HealthStatusHealthy
		}, 5*time.Second, 500*time.Millisecond).Should(BeTrue())
	})
})

var _ = Describe("DNSRecord Controller Integration", func() {
	var mockServer *dnsclient.MockDNSServer
	var dnsClass *dnsv1alpha1.DNSClass
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
		mockServer = dnsclient.NewMockDNSServer(nil, "")
		DeferCleanup(func() {
			mockServer.Close()
		})

		// Create DNSClass
		dnsClass = &dnsv1alpha1.DNSClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-dnsclass",
			},
			Spec: dnsv1alpha1.DNSClassSpec{
				Server: mockServer.URL(),
			},
		}
		Expect(k8sClient.Create(ctx, dnsClass)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, dnsClass)
		})
	})

	It("should create DNS record", func() {
		dnsRecord := &dnsv1alpha1.DNSRecord{
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

		Expect(k8sClient.Create(ctx, dnsRecord)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, dnsRecord)
		})

		reconciler := &DNSRecordReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}

		// Reconcile multiple times to ensure status is updated
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-record",
				Namespace: "default",
			},
		}

		// First reconcile to create the record
		_, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		// Reconcile again to update status
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		// Verify status was updated
		updated := &dnsv1alpha1.DNSRecord{}
		err = k8sClient.Get(ctx, types.NamespacedName{
			Name:      "test-record",
			Namespace: "default",
		}, updated)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated.Status.State).To(BeElementOf(dnsv1alpha1.RecordStateCreated, dnsv1alpha1.RecordStateUpdated, dnsv1alpha1.RecordStatePending))

		// Verify record exists in mock server
		stored := mockServer.GetRecord("A", "example.com", "www")
		Expect(stored).NotTo(BeNil())
		Expect(stored.Values).To(ContainElement("192.168.1.100"))
	})

	It("should delete DNS record when resource is deleted", func() {
		dnsRecord := &dnsv1alpha1.DNSRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-record-delete",
				Namespace: "default",
			},
			Spec: dnsv1alpha1.DNSRecordSpec{
				Type:      dnsv1alpha1.DNSRecordTypeA,
				Domain:    "example.com",
				Subdomain: "delete",
				DNSClassRef: dnsv1alpha1.DNSClassRef{
					Name: "test-dnsclass",
				},
				Values: []string{"192.168.1.100"},
			},
		}

		Expect(k8sClient.Create(ctx, dnsRecord)).To(Succeed())

		reconciler := &DNSRecordReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-record-delete",
				Namespace: "default",
			},
		}

		// Reconcile to create record
		_, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		// Reconcile again to ensure record is created
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		// Verify record exists
		stored := mockServer.GetRecord("A", "example.com", "delete")
		Expect(stored).NotTo(BeNil())

		// Delete the resource
		Expect(k8sClient.Delete(ctx, dnsRecord)).To(Succeed())

		// Reconcile deletion
		_, err = reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-record-delete",
				Namespace: "default",
			},
		})
		Expect(err).NotTo(HaveOccurred())

		// Wait for record to be deleted from mock server
		Eventually(func() bool {
			return mockServer.GetRecord("A", "example.com", "delete") == nil
		}, 5*time.Second, 500*time.Millisecond).Should(BeTrue())
	})

	It("should work with HMAC authentication", func() {
		secret := []byte("test-hmac-secret")
		mockServer.Close()
		mockServer = dnsclient.NewMockDNSServer(secret, hmac.AlgorithmSHA256)

		// Update DNSClass with new server URL and HMAC auth
		dnsClass.Spec.Server = mockServer.URL()
		dnsClass.Spec.HMACAuth = &dnsv1alpha1.HMACAuth{
			Secret:    stringPtr("test-hmac-secret"),
			Algorithm: "SHA256",
		}
		Expect(k8sClient.Update(ctx, dnsClass)).To(Succeed())

		dnsRecord := &dnsv1alpha1.DNSRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-record-hmac",
				Namespace: "default",
			},
			Spec: dnsv1alpha1.DNSRecordSpec{
				Type:      dnsv1alpha1.DNSRecordTypeA,
				Domain:    "example.com",
				Subdomain: "hmac",
				DNSClassRef: dnsv1alpha1.DNSClassRef{
					Name: "test-dnsclass",
				},
				Values: []string{"192.168.1.100"},
			},
		}

		Expect(k8sClient.Create(ctx, dnsRecord)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, dnsRecord)
		})

		reconciler := &DNSRecordReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-record-hmac",
				Namespace: "default",
			},
		}

		// Reconcile
		_, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		// Reconcile again to ensure record is created
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		// Verify record exists
		stored := mockServer.GetRecord("A", "example.com", "hmac")
		Expect(stored).NotTo(BeNil())
	})
})

func stringPtr(s string) *string {
	return &s
}
