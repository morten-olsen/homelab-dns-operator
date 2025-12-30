# DNS Operator

A Kubernetes operator that provides declarative DNS management through external DNS providers via a webhook-based protocol. The operator allows Kubernetes resources to manage DNS records (A, CNAME, AAAA, TXT, MX, SRV, NS) across multiple DNS providers.

## Overview

The DNS Operator provides a generic DNS management system for Kubernetes clusters. It uses a webhook-based protocol to communicate with DNS provider backends, allowing you to:

- Declaratively manage DNS records as Kubernetes resources
- Support multiple DNS providers through a unified interface
- Use HMAC-based authentication for secure communication
- Monitor DNS provider health and record status
- Validate DNS record configurations before creation

## Architecture

The operator consists of two main custom resources:

- **DNSClass** (cluster-scoped): Represents a DNS provider backend configuration
- **DNSRecord** (namespace-scoped): Represents a DNS record to be managed

### Resource Scope

- **DNSClass**: Cluster-scoped resource (DNS providers are cluster-wide infrastructure)
- **DNSRecord**: Namespace-scoped resource (DNS records can be managed per namespace)

## Features

- **Multiple Record Types**: Supports A, CNAME, AAAA, TXT, MX, SRV, and NS records
- **HMAC Authentication**: Optional HMAC-based authentication for request integrity verification
- **Health Monitoring**: Automatic health checks for DNS provider backends
- **Webhook Validation**: Validates DNS record configurations before creation
- **Retry Logic**: Configurable exponential backoff for failed operations
- **Finalizers**: Ensures DNS records are properly cleaned up when deleted
- **Status Tracking**: Comprehensive status conditions and error reporting

## Getting Started

### Prerequisites

- Go version v1.24.6+
- Docker version 17.03+
- kubectl version v1.11.3+
- Access to a Kubernetes v1.11.3+ cluster
- A DNS provider backend implementing the webhook protocol (see [DNS Server Webhook Protocol](#dns-server-webhook-protocol))

### Installation

**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/dns-operator:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don't work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/dns-operator:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**

You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### Uninstallation

**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Usage

### Creating a DNSClass

A DNSClass represents a DNS provider backend. Here's an example:

```yaml
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSClass
metadata:
  name: cloudflare
spec:
  # Server URL for the DNS provider webhook service
  server: "http://cloudflare-dns.dns.svc:7100"
  
  # Optional: Default TTL for records using this DNSClass
  defaultTTL: 300
  
  # Optional: Connection timeout in seconds
  timeoutSeconds: 30
  
  # Optional: HMAC-based authentication for request integrity verification
  hmacAuth:
    # Option 1: Reference to Kubernetes Secret (preferred)
    secretRef:
      name: cloudflare-dns-secret
      namespace: dns-system
      key: hmac-secret  # Key within the secret containing the shared secret
    
    # Optional: HMAC algorithm (default: SHA256)
    algorithm: "SHA256"  # or "SHA512"
```

**With HMAC Authentication:**

First, create a Kubernetes Secret containing the HMAC shared secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloudflare-dns-secret
  namespace: dns-system
type: Opaque
stringData:
  hmac-secret: "your-shared-secret-key"
```

Then reference it in the DNSClass:

```yaml
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSClass
metadata:
  name: cloudflare
spec:
  server: "http://cloudflare-dns.dns.svc:7100"
  hmacAuth:
    secretRef:
      name: cloudflare-dns-secret
      namespace: dns-system
      key: hmac-secret
    algorithm: "SHA256"
```

### Creating a DNSRecord

A DNSRecord represents a DNS record to be managed. Here are examples for different record types:

**A Record:**

```yaml
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSRecord
metadata:
  name: web-app
  namespace: production
spec:
  type: A
  domain: "example.com"
  subdomain: "www"
  dnsClassRef:
    name: cloudflare
  values:
    - "192.168.1.100"
    - "192.168.1.101"
  ttl: 600  # Optional: overrides DNSClass default
  description: "Web application load balancer IPs"
```

**CNAME Record:**

```yaml
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSRecord
metadata:
  name: api-cname
  namespace: production
spec:
  type: CNAME
  domain: "example.com"
  subdomain: "api"
  dnsClassRef:
    name: cloudflare
  values:
    - "api.example.com"
```

**MX Record:**

```yaml
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSRecord
metadata:
  name: mail-exchange
  namespace: production
spec:
  type: MX
  domain: "example.com"
  subdomain: "@"  # Root domain
  dnsClassRef:
    name: cloudflare
  values:
    - "mail.example.com"
  metadata:
    priority: 10
```

**SRV Record:**

```yaml
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSRecord
metadata:
  name: service-discovery
  namespace: production
spec:
  type: SRV
  domain: "example.com"
  subdomain: "_service._tcp"
  dnsClassRef:
    name: cloudflare
  values:
    - "target.example.com"
  metadata:
    priority: 10
    weight: 100
    port: 443
```

### Supported Record Types

- **A**: IPv4 address records (supports multiple values)
- **AAAA**: IPv6 address records (supports multiple values)
- **CNAME**: Canonical name records (single value only)
- **TXT**: Text records (supports multiple values)
- **MX**: Mail exchange records (requires `metadata.priority`)
- **SRV**: Service records (requires `metadata.priority`, `metadata.weight`, `metadata.port`)
- **NS**: Name server records

### Status and Conditions

Both DNSClass and DNSRecord resources include comprehensive status information:

**DNSClass Status:**

```yaml
status:
  conditions:
    - type: Ready
      status: "True"
      lastTransitionTime: "2025-12-30T10:00:00Z"
      observedGeneration: 1
      reason: "ServerHealthy"
      message: "DNS server is healthy and reachable"
  lastHealthCheck: "2025-12-30T10:00:00Z"
  health:
    status: "Healthy"
    lastCheck: "2025-12-30T10:00:00Z"
    message: "DNS server is operational"
  observedGeneration: 1
```

**DNSRecord Status:**

```yaml
status:
  conditions:
    - type: Ready
      status: "True"
      lastTransitionTime: "2025-12-30T10:00:00Z"
      observedGeneration: 1
      reason: "RecordCreated"
      message: "Record created successfully"
  state: "Created"
  lastSyncTime: "2025-12-30T10:00:00Z"
  fqdn: "www.example.com"
  observedGeneration: 1
```

## DNS Server Webhook Protocol

The operator communicates with DNS provider backends via HTTP/HTTPS using a standardized webhook protocol. DNS providers must implement the following endpoints:

### Endpoints

1. **GET `/health`** - Health check endpoint
2. **POST `/records`** - Create or update a DNS record (idempotent)
3. **DELETE `/records/{type}/{domain}/{subdomain}`** - Delete a DNS record
4. **GET `/records/{type}/{domain}/{subdomain}`** - Get current state of a DNS record (optional)

### Authentication

When HMAC authentication is configured, the operator includes the following headers in all requests:

- `X-DNS-Timestamp`: RFC3339 formatted timestamp
- `X-DNS-Nonce`: Unique random value (UUID v4 or random 32-byte hex string)
- `X-DNS-Signature`: HMAC signature as hexadecimal string

The HMAC is calculated over (in order, newline-separated):

- HTTP method
- Request path
- RFC3339 timestamp
- Nonce
- Request body (JSON payload, if present)

DNS servers must:

1. Verify timestamp freshness (allow ±5 minutes for clock skew)
2. Check nonce uniqueness (reject if nonce has been used within the timestamp window)
3. Recalculate HMAC and compare with provided signature
4. Reject requests with invalid signatures, stale timestamps, or reused nonces

See the [specification document](spec/2025-12-30-dns-operator-spec.md) for detailed protocol documentation.

## Configuration

The operator can be configured via environment variables:

- `DNS_CLASS_HEALTH_CHECK_INTERVAL`: Health check interval for DNSClass (default: "10m")
- `DNS_RECORD_RETRY_BASE_DELAY`: Base delay for exponential backoff (default: "5s")
- `DNS_RECORD_RETRY_MAX_DELAY`: Maximum delay between retries (default: "60s")
- `DNS_RECORD_RETRY_MAX_ATTEMPTS`: Maximum number of retry attempts (default: 5)

## Validation

The operator includes webhook validation to ensure DNS records are correctly configured:

- **Required Fields**: Type, domain, subdomain, values, and dnsClassRef are required
- **Type-Specific Validation**:
  - A records: Values must be valid IPv4 addresses
  - AAAA records: Values must be valid IPv6 addresses
  - CNAME records: Must have exactly one value, must be valid domain name
  - MX records: Must have `metadata.priority`
  - SRV records: Must have `metadata.priority`, `metadata.weight`, and `metadata.port`
- **DNSClass Validation**: Server URL format, HMAC auth configuration

Invalid configurations are rejected before they're persisted to the cluster.

## Testing

The operator includes comprehensive test coverage:

- **Unit Tests**: Controller logic, webhook validation, DNS client, HMAC utilities
- **Integration Tests**: Controller reconciliation with mock DNS server (included in `make test`)
- **E2E Tests**: Full end-to-end tests with Kubernetes cluster

Run tests:

```sh
# Unit and integration tests
make test

# E2E tests (requires running cluster)
make test-e2e
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/dns-operator:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

1. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/dns-operator/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
kubebuilder edit --plugins=helm/v2-alpha
```

1. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## Contributing

Contributions are welcome! Please ensure that:

- All tests pass (`make test`)
- Code follows Go best practices
- New features include appropriate tests
- Documentation is updated

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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
