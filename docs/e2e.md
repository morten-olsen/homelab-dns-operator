# Isolated Kind E2E tests

Run `make test-e2e E2E_SEED=1793298486` with Go, Docker, Kind and kubectl
available on a Linux runner. The target creates a temporary kubeconfig, selects
only `KIND_CLUSTER` (default `dns-operator-test-e2e`), runs all specs shuffled,
and deletes the disposable cluster and kubeconfig even when a spec fails.
Never point the suite at the homelab. BeforeSuite also refuses a context other
than `kind-$KIND_CLUSTER` or Ginkgo parallel processes sharing one fixture.

The suite owns the image, cert-manager installation, restricted namespace,
CRDs, controller deployment and webhook readiness. It waits for established
CRDs, the serving certificate, deployment rollout and server-side dry-run
admission of both DNS kinds before any spec starts. AfterSuite removes custom
resources while their controller is available, undeploys the operator, removes
CRDs/the namespace and removes cert-manager when the suite installed it.
Manager and DNS specs have no execution-order dependency. Per-spec DNS objects
finish deletion before their mock server shuts down.

The existing `dnsclient.MockDNSServer` stays on runner loopback for unit tests.
An E2E-only reverse proxy listens on an ephemeral port of the `kind` Docker
network's IPv4 gateway address, selected from `docker network inspect kind`
IPAM entries (which can list IPv6 first). The default Kind pod network uses
IPv4; choosing the first Docker gateway can advertise unreachable IPv6. Pods
use that address, not their own loopback. It exposes only the test mock on the
runner's Docker bridge; no runtime manifests, home network policies or operator
code change. Linux bridge networking is required. Healthy DNSClass status and
record creation/deletion in the mock prove controller-to-mock reachability,
including signed HMAC requests. An invalid IPv4 value proves webhook validation
rather than CRD required-field validation. Metrics requests avoid verbose curl
or command logging so the temporary bearer token is not printed.

The mirror's E2E workflow runs seeds `1793298486` (the seed from failed run
40930814560), `1`, and `42` in separate runner jobs with `fail-fast: false`.
Each job runs all ten specs against a fresh cluster. To reproduce another
shuffle, set `E2E_SEED`; to run jobs locally concurrently, also choose distinct
`KIND_CLUSTER` names. The repository's Woodpecker workflow is Renovate-only;
acceptance runs on the existing GitHub mirror Actions runners, with all source
changes pushed to Forgejo.
