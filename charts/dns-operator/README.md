# DNS Operator Helm Chart

This Helm chart deploys the DNS Operator on a Kubernetes cluster.

## Prerequisites

- Kubernetes 1.11.3+
- Helm 3.0+
- CRDs must be installed separately (see installation instructions)

## Installation

### Install CRDs

Before installing the operator, you must install the Custom Resource Definitions:

```bash
# Using kubectl
kubectl apply -f https://raw.githubusercontent.com/mortenolsen/dns-operator/main/config/crd/bases/dns.homelab.mortenolsen.pro_dnsclasses.yaml
kubectl apply -f https://raw.githubusercontent.com/mortenolsen/dns-operator/main/config/crd/bases/dns.homelab.mortenolsen.pro_dnsrecords.yaml

# Or using make (from the repository root)
make install
```

### Install the Operator

```bash
# Add the repository (if using a Helm repository)
helm repo add dns-operator https://mortenolsen.github.io/dns-operator
helm repo update

# Install from repository
helm install dns-operator dns-operator/dns-operator \
  --namespace dns-operator-system \
  --create-namespace \
  --set image.repository=your-registry/dns-operator \
  --set image.tag=v0.1.0

# Or install from local chart
helm install dns-operator ./charts/dns-operator \
  --namespace dns-operator-system \
  --create-namespace \
  --set image.repository=your-registry/dns-operator \
  --set image.tag=v0.1.0
```

## Configuration

The following table lists the configurable parameters and their default values:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image repository | `controller` |
| `image.tag` | Container image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `namespace.create` | Create namespace | `true` |
| `namespace.name` | Namespace name | `dns-operator-system` |
| `replicaCount` | Number of replicas | `1` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `leaderElection.enabled` | Enable leader election | `true` |
| `metrics.enabled` | Enable metrics | `true` |
| `metrics.service.create` | Create metrics service | `true` |
| `webhook.enabled` | Enable webhooks | `true` |
| `webhook.service.create` | Create webhook service | `true` |
| `webhook.certManager.enabled` | Enable cert-manager integration | `true` |
| `webhook.certManager.issuer.name` | Cert-manager issuer name | `""` |
| `webhook.certManager.issuer.kind` | Cert-manager issuer kind | `""` |
| `env.DNS_CLASS_HEALTH_CHECK_INTERVAL` | Health check interval | `10m` |
| `env.DNS_RECORD_RETRY_BASE_DELAY` | Retry base delay | `5s` |
| `env.DNS_RECORD_RETRY_MAX_DELAY` | Retry max delay | `60s` |
| `env.DNS_RECORD_RETRY_MAX_ATTEMPTS` | Retry max attempts | `5` |

### Example: Custom Configuration

```yaml
image:
  repository: myregistry/dns-operator
  tag: v0.1.0

namespace:
  name: dns-system

resources:
  limits:
    cpu: 1000m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

webhook:
  certManager:
    enabled: true
    issuer:
      name: letsencrypt-prod
      kind: ClusterIssuer

env:
  DNS_CLASS_HEALTH_CHECK_INTERVAL: "5m"
  DNS_RECORD_RETRY_MAX_ATTEMPTS: "10"
```

Install with custom values:

```bash
helm install dns-operator ./charts/dns-operator \
  --namespace dns-operator-system \
  --create-namespace \
  -f custom-values.yaml
```

## Cert-Manager Integration

If you're using cert-manager for webhook certificates, configure it:

```yaml
webhook:
  certManager:
    enabled: true
    issuer:
      name: your-issuer-name
      kind: Issuer  # or ClusterIssuer
```

The certificate will be automatically created and injected into the webhook configurations.

## Uninstallation

```bash
# Uninstall the operator
helm uninstall dns-operator --namespace dns-operator-system

# Delete CRDs (optional, removes all DNSClass and DNSRecord resources)
kubectl delete -f https://raw.githubusercontent.com/mortenolsen/dns-operator/main/config/crd/bases/dns.homelab.mortenolsen.pro_dnsclasses.yaml
kubectl delete -f https://raw.githubusercontent.com/mortenolsen/dns-operator/main/config/crd/bases/dns.homelab.mortenolsen.pro_dnsrecords.yaml
```

## Upgrading

```bash
# Upgrade the operator
helm upgrade dns-operator ./charts/dns-operator \
  --namespace dns-operator-system \
  --set image.tag=v0.2.0
```

## Troubleshooting

### Check Operator Status

```bash
kubectl get pods -n dns-operator-system
kubectl logs -n dns-operator-system deployment/dns-operator-controller-manager
```

### Check Webhook Configuration

```bash
kubectl get mutatingwebhookconfiguration
kubectl get validatingwebhookconfiguration
```

### Check Certificates

```bash
kubectl get certificate -n dns-operator-system
kubectl describe certificate -n dns-operator-system
```

## Support

For issues and questions, please open an issue on the [GitHub repository](https://github.com/mortenolsen/dns-operator).
