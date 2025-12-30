//go:build e2e
// +build e2e

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

package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	dnsv1alpha1 "github.com/mortenolsen/dns-operator/api/v1alpha1"
	"github.com/mortenolsen/dns-operator/pkg/dnsclient"
	"github.com/mortenolsen/dns-operator/pkg/hmac"
	"github.com/mortenolsen/dns-operator/test/utils"
)

var _ = Describe("DNS Operator E2E", func() {
	var k8sClient client.Client
	var mockServer *dnsclient.MockDNSServer
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()

		// Create Kubernetes client with scheme
		scheme := runtime.NewScheme()
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		utilruntime.Must(dnsv1alpha1.AddToScheme(scheme))

		cfg, err := config.GetConfig()
		Expect(err).NotTo(HaveOccurred())

		k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
		Expect(err).NotTo(HaveOccurred())

		// Start mock DNS server
		mockServer = dnsclient.NewMockDNSServer(nil, "")
		DeferCleanup(func() {
			mockServer.Close()
		})
	})

	Context("DNSClass", func() {
		It("should create and reconcile DNSClass", func() {
			dnsClass := &dnsv1alpha1.DNSClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dnsclass-e2e",
				},
				Spec: dnsv1alpha1.DNSClassSpec{
					Server: mockServer.URL(),
				},
			}

			By("creating DNSClass")
			err := k8sClient.Create(ctx, dnsClass)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				k8sClient.Delete(ctx, dnsClass)
			})

			By("waiting for DNSClass to be reconciled")
			Eventually(func() bool {
				updated := &dnsv1alpha1.DNSClass{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: "test-dnsclass-e2e"}, updated)
				if err != nil {
					return false
				}
				// Check if health status is set
				return updated.Status.Health != nil
			}, 2*time.Minute, 5*time.Second).Should(BeTrue())

			By("verifying DNSClass status")
			updated := &dnsv1alpha1.DNSClass{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "test-dnsclass-e2e"}, updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.Status.Health).NotTo(BeNil())
			Expect(updated.Status.Health.Status).To(Equal(dnsv1alpha1.HealthStatusHealthy))
		})

		It("should handle DNSClass with HMAC authentication", func() {
			secret := []byte("e2e-test-secret")
			mockServer.Close()
			mockServer = dnsclient.NewMockDNSServer(secret, hmac.AlgorithmSHA256)

			// Create secret for HMAC auth
			By("creating HMAC secret")
			secretYAML := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: dns-hmac-secret
  namespace: %s
type: Opaque
stringData:
  hmac-secret: %s
`, namespace, string(secret))

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(secretYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				exec.Command("kubectl", "delete", "secret", "dns-hmac-secret", "-n", namespace).Run()
			})

			dnsClass := &dnsv1alpha1.DNSClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dnsclass-hmac-e2e",
				},
				Spec: dnsv1alpha1.DNSClassSpec{
					Server: mockServer.URL(),
					HMACAuth: &dnsv1alpha1.HMACAuth{
						SecretRef: &dnsv1alpha1.SecretRef{
							Name:      "dns-hmac-secret",
							Namespace: namespace,
							Key:       "hmac-secret",
						},
						Algorithm: "SHA256",
					},
				},
			}

			By("creating DNSClass with HMAC auth")
			err = k8sClient.Create(ctx, dnsClass)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				k8sClient.Delete(ctx, dnsClass)
			})

			By("waiting for DNSClass to be reconciled")
			Eventually(func() bool {
				updated := &dnsv1alpha1.DNSClass{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: "test-dnsclass-hmac-e2e"}, updated)
				if err != nil {
					return false
				}
				return updated.Status.Health != nil && updated.Status.Health.Status == dnsv1alpha1.HealthStatusHealthy
			}, 2*time.Minute, 5*time.Second).Should(BeTrue())
		})
	})

	Context("DNSRecord", func() {
		var dnsClass *dnsv1alpha1.DNSClass

		BeforeEach(func() {
			dnsClass = &dnsv1alpha1.DNSClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dnsclass-record-e2e",
				},
				Spec: dnsv1alpha1.DNSClassSpec{
					Server: mockServer.URL(),
				},
			}

			err := k8sClient.Create(ctx, dnsClass)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				k8sClient.Delete(ctx, dnsClass)
			})

			// Wait for DNSClass to be ready
			Eventually(func() bool {
				updated := &dnsv1alpha1.DNSClass{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: "test-dnsclass-record-e2e"}, updated)
				return err == nil && updated.Status.Health != nil
			}, 1*time.Minute, 2*time.Second).Should(BeTrue())
		})

		It("should create and reconcile DNSRecord", func() {
			dnsRecord := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record-e2e",
					Namespace: namespace,
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeA,
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass-record-e2e",
					},
					Values: []string{"192.168.1.100"},
				},
			}

			By("creating DNSRecord")
			err := k8sClient.Create(ctx, dnsRecord)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				k8sClient.Delete(ctx, dnsRecord)
			})

			By("waiting for DNSRecord to be reconciled")
			Eventually(func() bool {
				updated := &dnsv1alpha1.DNSRecord{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-record-e2e",
					Namespace: namespace,
				}, updated)
				if err != nil {
					return false
				}
				return updated.Status.State == dnsv1alpha1.RecordStateCreated || updated.Status.State == dnsv1alpha1.RecordStateUpdated
			}, 2*time.Minute, 5*time.Second).Should(BeTrue())

			By("verifying DNSRecord status")
			updated := &dnsv1alpha1.DNSRecord{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      "test-record-e2e",
				Namespace: namespace,
			}, updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.Status.FQDN).To(Equal("www.example.com"))
			Expect(updated.Status.State).To(BeElementOf(dnsv1alpha1.RecordStateCreated, dnsv1alpha1.RecordStateUpdated))

			By("verifying record exists in mock server")
			stored := mockServer.GetRecord("A", "example.com", "www")
			Expect(stored).NotTo(BeNil())
			Expect(stored.Values).To(ContainElement("192.168.1.100"))
		})

		It("should delete DNSRecord and clean up", func() {
			dnsRecord := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record-delete-e2e",
					Namespace: namespace,
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Type:      dnsv1alpha1.DNSRecordTypeA,
					Domain:    "example.com",
					Subdomain: "delete",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass-record-e2e",
					},
					Values: []string{"192.168.1.100"},
				},
			}

			By("creating DNSRecord")
			err := k8sClient.Create(ctx, dnsRecord)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for DNSRecord to be created")
			Eventually(func() bool {
				return mockServer.GetRecord("A", "example.com", "delete") != nil
			}, 2*time.Minute, 5*time.Second).Should(BeTrue())

			By("deleting DNSRecord")
			err = k8sClient.Delete(ctx, dnsRecord)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for DNSRecord to be deleted from mock server")
			Eventually(func() bool {
				return mockServer.GetRecord("A", "example.com", "delete") == nil
			}, 2*time.Minute, 5*time.Second).Should(BeTrue())
		})

		It("should validate DNSRecord webhook", func() {
			By("creating invalid DNSRecord (missing type)")
			invalidRecord := &dnsv1alpha1.DNSRecord{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-record-invalid",
					Namespace: namespace,
				},
				Spec: dnsv1alpha1.DNSRecordSpec{
					Domain:    "example.com",
					Subdomain: "www",
					DNSClassRef: dnsv1alpha1.DNSClassRef{
						Name: "test-dnsclass-record-e2e",
					},
					Values: []string{"192.168.1.100"},
				},
			}

			err := k8sClient.Create(ctx, invalidRecord)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.type is required"))
		})
	})
})
