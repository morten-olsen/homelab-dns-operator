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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/mortenolsen/dns-operator/test/utils"
)

var (
	// Optional Environment Variables:
	// - CERT_MANAGER_INSTALL_SKIP=true: Skips CertManager installation during test setup.
	// These variables are useful if CertManager is already installed, avoiding
	// re-installation and conflicts.
	skipCertManagerInstall = os.Getenv("CERT_MANAGER_INSTALL_SKIP") == "true"
	// isCertManagerAlreadyInstalled will be set true when CertManager CRDs be found on the cluster
	isCertManagerAlreadyInstalled = false

	// projectImage is the name of the image which will be build and loaded
	// with the code source changes to be tested.
	projectImage      = "example.com/dns-operator:v0.0.1"
	controllerPodName string
	kindGateway       string
	suiteOwnsCluster  bool
)

// TestE2E runs the end-to-end (e2e) test suite for the project. These tests execute in an isolated,
// temporary environment to validate project changes with the purpose of being used in CI jobs.
// The default setup requires Kind, builds/loads the Manager Docker image locally, and installs
// CertManager.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting dns-operator integration test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	// Refuse to mutate a context other than the explicitly selected disposable Kind cluster.
	cluster := os.Getenv("KIND_CLUSTER")
	Expect(cluster).NotTo(BeEmpty(), "Use make test-e2e with an isolated Kind cluster")
	suiteConfig, _ := GinkgoConfiguration()
	Expect(suiteConfig.ParallelTotal).To(Equal(1), "This suite shares one Kind fixture; run seeds in separate clusters")
	currentContext, err := utils.Run(exec.Command("kubectl", "config", "current-context"))
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(currentContext)).To(Equal("kind-" + cluster))
	suiteOwnsCluster = true

	By("finding the runner address reachable from Kind pods")
	gateway, err := utils.Run(exec.Command("docker", "network", "inspect", "kind",
		"--format", "{{(index .IPAM.Config 0).Gateway}}"))
	Expect(err).NotTo(HaveOccurred())
	kindGateway = strings.TrimSpace(gateway)
	Expect(kindGateway).NotTo(BeEmpty())

	By("building the manager(Operator) image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")

	// TODO(user): If you want to change the e2e test vendor from Kind, ensure the image is
	// built and available before running the tests. Also, remove the following block.
	By("loading the manager(Operator) image on Kind")
	err = utils.LoadImageToKindClusterWithName(projectImage)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager(Operator) image into Kind")

	// The tests-e2e are intended to run on a temporary cluster that is created and destroyed for testing.
	// To prevent errors when tests run in environments with CertManager already installed,
	// we check for its presence before execution.
	// Setup CertManager before the suite if not skipped and if not already installed
	if !skipCertManagerInstall {
		By("checking if cert manager is installed already")
		isCertManagerAlreadyInstalled = utils.IsCertManagerCRDsInstalled()
		if !isCertManagerAlreadyInstalled {
			_, _ = fmt.Fprintf(GinkgoWriter, "Installing CertManager...\n")
			Expect(utils.InstallCertManager()).To(Succeed(), "Failed to install CertManager")
		} else {
			_, _ = fmt.Fprintf(GinkgoWriter, "WARNING: CertManager is already installed. Skipping installation...\n")
		}
	}

	By("creating manager namespace with the restricted security policy")
	runFixtureCommand("kubectl", "create", "ns", namespace)
	runFixtureCommand("kubectl", "label", "--overwrite", "ns", namespace,
		"pod-security.kubernetes.io/enforce=restricted")

	By("installing and waiting for CRDs")
	runFixtureCommand("make", "install")
	runFixtureCommand("kubectl", "wait", "--for=condition=Established", "--timeout=2m",
		"crd/dnsclasses.dns.homelab.mortenolsen.pro", "crd/dnsrecords.dns.homelab.mortenolsen.pro")

	By("deploying and waiting for the controller-manager")
	runFixtureCommand("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
	runFixtureCommand("kubectl", "wait", "-n", namespace, "--for=condition=Ready", "--timeout=3m",
		"certificate/dns-operator-serving-cert")
	runFixtureCommand("kubectl", "rollout", "status", "deployment/dns-operator-controller-manager",
		"-n", namespace, "--timeout=3m")
	pod, err := utils.Run(exec.Command("kubectl", "get", "pods", "-n", namespace,
		"-l", "control-plane=controller-manager", "-o", "jsonpath={.items[0].metadata.name}"))
	Expect(err).NotTo(HaveOccurred())
	controllerPodName = pod
	Expect(controllerPodName).NotTo(BeEmpty())

	By("waiting for admission through both DNS webhooks, including CA injection")
	// A successful server dry-run exercises admission from the API server, beyond pod readiness.
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "apply", "--dry-run=server", "-f", "-")
		cmd.Stdin = strings.NewReader(fmt.Sprintf(`apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSClass
metadata:
  name: suite-readiness
spec:
  server: http://192.0.2.1
---
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSRecord
metadata:
  name: suite-readiness
  namespace: %s
spec:
  type: A
  domain: example.com
  subdomain: readiness
  dnsClassRef:
    name: suite-readiness
  values: ["192.0.2.1"]
`, namespace))
		_, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
	}, 3*time.Minute, time.Second).Should(Succeed())

})

var _ = AfterSuite(func() {
	if !suiteOwnsCluster {
		return
	}
	// Keep the controller alive while DNSRecord finalizers remove mock records.
	for _, args := range [][]string{
		{"kubectl", "delete", "dnsrecords", "--all", "-A", "--ignore-not-found", "--timeout=60s"},
		{"kubectl", "delete", "dnsclasses", "--all", "--ignore-not-found", "--timeout=60s"},
		{"make", "undeploy", "ignore-not-found=true"},
		{"make", "uninstall", "ignore-not-found=true"},
		{"kubectl", "delete", "ns", namespace, "--ignore-not-found", "--timeout=60s"},
	} {
		_, err := utils.Run(exec.Command(args[0], args[1:]...))
		Expect(err).NotTo(HaveOccurred())
	}

	// Teardown CertManager after the suite if not skipped and if it was not already installed
	if !skipCertManagerInstall && !isCertManagerAlreadyInstalled {
		_, _ = fmt.Fprintf(GinkgoWriter, "Uninstalling CertManager...\n")
		utils.UninstallCertManager()
	}
})

func runFixtureCommand(name string, args ...string) {
	_, err := utils.Run(exec.Command(name, args...))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
}
