# DNS Operator Specification

**Date:** 2025-12-30  
**Domain:** homelab.mortenolsen.pro  
**Group:** dns.homelab.mortenolsen.pro

## Overview

A Kubernetes operator built with kubebuilder that provides a generic DNS management system. The operator allows Kubernetes resources to declaratively manage DNS records through external DNS providers via a webhook-based protocol.

## Design Decisions

### Resource Scope

- **DNSClass**: Cluster-scoped resource (DNS providers are cluster-wide infrastructure)
- **DNSRecord**: Namespace-scoped resource (DNS records can be managed per namespace)

### Single DNSRecord Resource

Instead of separate `ARecord` and `CNAME` resources, we'll use a unified `DNSRecord` resource with a `type` field. This design:

- Reduces code duplication
- Makes it easier to add new record types in the future
- Provides consistent behavior across all record types
- Simplifies the controller logic

### Record Types

Initially supported:

- `A` - IPv4 address records
- `CNAME` - Canonical name records

Future extensibility for:

- `AAAA` - IPv6 address records
- `TXT` - Text records
- `MX` - Mail exchange records
- `SRV` - Service records
- `NS` - Name server records

## Custom Resource Definitions

### DNSClass

**Scope:** Cluster  
**Group:** `dns.homelab.mortenolsen.pro`  
**Version:** `v1alpha1`  
**Kind:** `DNSClass`

DNSClass represents a DNS provider backend that can be used to manage DNS records.

#### Spec

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
    
    # Option 2: Direct secret value (less secure, for testing only)
    # secret: "my-shared-secret-key"
    
    # Optional: HMAC algorithm (default: SHA256)
    algorithm: "SHA256"  # or "SHA512"
```

#### Status

```yaml
status:
  # Conditions array (Kubernetes standard)
  conditions:
    - type: Ready
      status: "True" | "False" | "Unknown"
      lastTransitionTime: "2025-12-30T10:00:00Z"
      observedGeneration: 1
      reason: "ServerHealthy" | "ServerUnreachable" | "ServerError"
      message: "Human-readable message"
  
  # Last health check timestamp
  lastHealthCheck: "2025-12-30T10:00:00Z"
  
  # Server health status (informational, does not block operations)
  health:
    status: "Healthy" | "Unhealthy" | "Unknown"
    lastCheck: "2025-12-30T10:00:00Z"
    message: "Optional health check message"
  
  # Observed generation for status tracking
  observedGeneration: 1
```

### DNSRecord

**Scope:** Namespace  
**Group:** `dns.homelab.mortenolsen.pro`  
**Version:** `v1alpha1`  
**Kind:** `DNSRecord`

DNSRecord represents a DNS record to be managed by the operator.

#### Spec

```yaml
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSRecord
metadata:
  name: web-app
  namespace: production
spec:
  # Record type: A, CNAME, AAAA, TXT, MX, SRV, NS
  type: A
  
  # Domain name (e.g., "example.com")
  domain: "example.com"
  
  # Subdomain (use "@" for root domain, or "www" for www.example.com)
  subdomain: "www"
  
  # Reference to DNSClass
  dnsClassRef:
    name: cloudflare
  
  # Record value(s)
  # For A records: IPv4 addresses (array for multiple values)
  # For CNAME: single canonical name
  # For AAAA: IPv6 addresses (array)
  # For TXT: text strings (array)
  values:
    - "192.168.1.100"
    - "192.168.1.101"
  
  # Optional: TTL override (overrides DNSClass default)
  ttl: 600
  
  # Optional: Description/notes
  description: "Web application load balancer IPs"
  
  # Optional: Record-specific metadata
  # For MX records: priority
  # For SRV records: priority, weight, port
  metadata:
    priority: 10  # For MX/SRV
    weight: 100   # For SRV
    port: 443     # For SRV
```

#### Status

```yaml
status:
  # Conditions array (Kubernetes standard)
  conditions:
    - type: Ready
      status: "True" | "False" | "Unknown"
      lastTransitionTime: "2025-12-30T10:00:00Z"
      observedGeneration: 1
      reason: "RecordCreated" | "RecordUpdated" | "RecordDeleted" | 
              "DNSClassNotFound" | "SecretNotFound" | "ServerUnreachable" | 
              "ServerError" | "AuthenticationFailed" | "InvalidConfiguration" | 
              "ValidationFailed"
      message: "Human-readable message"
  
  # Current state of the record
  state: "Created" | "Updated" | "Deleted" | "Error" | "Pending"
  
  # Last sync timestamp
  lastSyncTime: "2025-12-30T10:00:00Z"
  
  # Full DNS name (domain + subdomain)
  fqdn: "www.example.com"
  
  # Observed generation
  observedGeneration: 1
  
  # Error details (if any)
  error:
    code: "SERVER_ERROR"
    message: "Failed to connect to DNS server"
    timestamp: "2025-12-30T10:00:00Z"
```

## DNS Server Webhook Protocol Specification

### Base URL

The DNS server URL is specified in the DNSClass `spec.server` field.

### Authentication

The operator supports optional HMAC (Hash-based Message Authentication Code) based authentication for request integrity verification.

#### HMAC Authentication

When `hmacAuth` is configured in a DNSClass, the operator will:

1. Read the shared secret from either:
   - A Kubernetes Secret (preferred, via `secretRef`)
   - A direct value in the spec (for testing only)
2. Calculate an HMAC signature over the request data
3. Include the signature and timestamp in HTTP headers
4. The DNS server verifies the signature using the same shared secret

#### HMAC Calculation

The HMAC is calculated over the following components (in order, newline-separated):

- HTTP method (e.g., "POST", "DELETE")
- Request path (e.g., "/records")
- RFC3339 timestamp (e.g., "2025-12-30T10:00:00Z")
- Nonce (unique random value per request)
- Request body (JSON payload, if present)

The resulting HMAC is sent as a hexadecimal string in the `X-DNS-Signature` header.

#### Request Headers

When HMAC authentication is enabled, the following headers are included:

- `X-DNS-Timestamp`: RFC3339 formatted timestamp
- `X-DNS-Nonce`: Unique random value (e.g., UUID v4 or random 32-byte hex string)
- `X-DNS-Signature`: HMAC signature as hexadecimal string

#### Nonce Generation

The operator generates a unique nonce for each request:

- Must be cryptographically random
- Recommended: UUID v4 or 32-byte random hex string
- Must be unique within the timestamp window (typically 5 minutes)

#### DNS Server Verification

The DNS server must:

1. Extract `X-DNS-Timestamp`, `X-DNS-Nonce`, and `X-DNS-Signature` headers
2. Verify timestamp freshness (allow ±5 minutes for clock skew)
3. Check nonce uniqueness (reject if nonce has been used within the timestamp window)
4. Recalculate HMAC using the same secret and request data (including nonce)
5. Compare calculated HMAC with provided signature
6. Reject requests with invalid signatures, stale timestamps, or reused nonces
7. Store used nonces (within the timestamp window) to prevent replay attacks

#### Security Considerations

- **Secret Storage**: Prefer `secretRef` over direct values to avoid exposing secrets in the spec
- **Secret Rotation**: Both operator and DNS server must be updated simultaneously
- **Clock Skew**: Allow ±5 minutes timestamp window to account for clock differences
- **Replay Protection**:
  - Timestamp validation prevents replay attacks outside the time window
  - Nonce validation prevents replay attacks within the time window
  - DNS server must track used nonces and reject duplicates
- **Nonce Storage**: DNS server should maintain a cache of used nonces (within the timestamp window) and periodically clean up expired entries

### Endpoints

#### 1. Health Check

**GET** `/health`

Check if the DNS server is healthy and reachable.

**Request:**

```
GET /health HTTP/1.1
Host: cloudflare-dns.dns.svc:7100
X-DNS-Timestamp: 2025-12-30T10:00:00Z
X-DNS-Nonce: 550e8400-e29b-41d4-a716-446655440000
X-DNS-Signature: a1b2c3d4e5f6...  # HMAC signature (if hmacAuth configured)
```

**Response:**

```json
{
  "status": "healthy",
  "message": "DNS server is operational",
  "timestamp": "2025-12-30T10:00:00Z"
}
```

**Status Codes:**

- `200 OK`: Server is healthy
- `503 Service Unavailable`: Server is unhealthy
- `500 Internal Server Error`: Server error

#### 2. Create/Update Record

**POST** `/records`

Create or update a DNS record (idempotent operation).

**Request:**

```
POST /records HTTP/1.1
Host: cloudflare-dns.dns.svc:7100
Content-Type: application/json
X-DNS-Timestamp: 2025-12-30T10:00:00Z
X-DNS-Nonce: 550e8400-e29b-41d4-a716-446655440000
X-DNS-Signature: a1b2c3d4e5f6...  # HMAC signature (if hmacAuth configured)

{
  "record": {
    "type": "A",
    "domain": "example.com",
    "subdomain": "www",
    "values": ["192.168.1.100", "192.168.1.101"],
    "ttl": 600
  },
  "operation": "upsert"
}
```

**Response (Success):**

```json
{
  "success": true,
  "record": {
    "type": "A",
    "domain": "example.com",
    "subdomain": "www",
    "fqdn": "www.example.com",
    "values": ["192.168.1.100", "192.168.1.101"],
    "ttl": 600
  },
  "message": "Record created successfully"
}
```

**Response (Error):**

```json
{
  "success": false,
  "error": {
    "code": "INVALID_RECORD",
    "message": "Invalid IP address format",
    "details": {}
  }
}
```

**Status Codes:**

- `200 OK`: Record created/updated successfully
- `400 Bad Request`: Invalid request (validation error)
- `401 Unauthorized`: HMAC signature verification failed, timestamp is stale, or nonce has been reused
- `500 Internal Server Error`: Server error

#### 3. Delete Record

**DELETE** `/records/{type}/{domain}/{subdomain}`

Delete a DNS record.

**Request:**

```
DELETE /records/A/example.com/www HTTP/1.1
Host: cloudflare-dns.dns.svc:7100
X-DNS-Timestamp: 2025-12-30T10:00:00Z
X-DNS-Nonce: 550e8400-e29b-41d4-a716-446655440000
X-DNS-Signature: a1b2c3d4e5f6...  # HMAC signature (if hmacAuth configured)
```

**Response (Success):**

```json
{
  "success": true,
  "message": "Record deleted successfully"
}
```

**Response (Error):**

```json
{
  "success": false,
  "error": {
    "code": "RECORD_NOT_FOUND",
    "message": "Record does not exist",
    "details": {}
  }
}
```

**Status Codes:**

- `200 OK`: Record deleted successfully (or doesn't exist)
- `401 Unauthorized`: HMAC signature verification failed, timestamp is stale, or nonce has been reused
- `404 Not Found`: Record not found (treated as success for idempotency)
- `500 Internal Server Error`: Server error

#### 4. Get Record

**GET** `/records/{type}/{domain}/{subdomain}`

Get current state of a DNS record (optional, for reconciliation).

**Request:**

```
GET /records/A/example.com/www HTTP/1.1
Host: cloudflare-dns.dns.svc:7100
X-DNS-Timestamp: 2025-12-30T10:00:00Z
X-DNS-Nonce: 550e8400-e29b-41d4-a716-446655440000
X-DNS-Signature: a1b2c3d4e5f6...  # HMAC signature (if hmacAuth configured)
```

**Response (Success):**

```json
{
  "success": true,
  "record": {
    "type": "A",
    "domain": "example.com",
    "subdomain": "www",
    "fqdn": "www.example.com",
    "values": ["192.168.1.100", "192.168.1.101"],
    "ttl": 600
  }
}
```

**Response (Not Found):**

```json
{
  "success": false,
  "error": {
    "code": "RECORD_NOT_FOUND",
    "message": "Record does not exist"
  }
}
```

**Status Codes:**

- `200 OK`: Record found
- `401 Unauthorized`: HMAC signature verification failed, timestamp is stale, or nonce has been reused
- `404 Not Found`: Record does not exist
- `500 Internal Server Error`: Server error

### Error Codes

Standard error codes that DNS servers should return:

- `INVALID_RECORD`: Record validation failed
- `INVALID_DOMAIN`: Invalid domain name format
- `INVALID_VALUE`: Invalid record value (e.g., invalid IP for A record)
- `RECORD_NOT_FOUND`: Record does not exist
- `SERVER_ERROR`: Internal server error
- `AUTH_FAILED`: HMAC signature verification failed
- `TIMESTAMP_STALE`: Request timestamp is outside acceptable window
- `NONCE_REUSED`: Nonce has already been used (replay attack detected)
- `RATE_LIMITED`: Rate limit exceeded
- `QUOTA_EXCEEDED`: Quota exceeded

## Controller Behavior

### DNSClass Controller

1. **Reconciliation Loop:**
   - Periodically check DNS server health via `/health` endpoint
   - Update DNSClass status with health information
   - Set `Ready` condition based on health check results
   - Health status is informational only and does not block DNSRecord operations

2. **Health Check Frequency:**
   - Every 10 minutes by default
   - Configurable via environment variable: `DNS_CLASS_HEALTH_CHECK_INTERVAL` (duration string, e.g., "10m")

3. **Error Handling:**
   - On health check failure, mark DNSClass as `NotReady` (for monitoring purposes)
   - Set appropriate condition reason (`ServerUnreachable`, `ServerError`)
   - Continue retrying health checks on schedule
   - Unhealthy DNSClass does not prevent DNSRecord reconciliation attempts

### DNSRecord Controller

1. **Reconciliation Loop:**
   - Watch DNSRecord resources
   - Validate DNSClass reference exists and is Ready
   - Call DNS server webhook to create/update/delete records
   - Update DNSRecord status with operation results

2. **Create/Update Flow:**
   - Validate DNSRecord spec
   - Check DNSClass exists (but do not require it to be Ready - unhealthy servers don't block operations)
   - Call `POST /records` with upsert operation
   - Update status on success/failure

3. **Delete Flow:**
   - When DNSRecord is deleted, call `DELETE /records/{type}/{domain}/{subdomain}`
   - Use finalizer to ensure cleanup completes
   - Remove finalizer after successful deletion

4. **Error Handling:**
   - If DNSClass not found: Set condition `Ready=False`, reason `DNSClassNotFound`
   - If HMAC secret not found: Set condition `Ready=False`, reason `SecretNotFound`
   - If server unreachable: Set condition `Ready=False`, reason `ServerUnreachable`, retry with backoff
   - If server error: Set condition `Ready=False`, reason `ServerError`, retry with backoff
   - If authentication fails (401): Set condition `Ready=False`, reason `AuthenticationFailed`, retry with backoff
   - Store error details in `status.error`
   - Use Kubernetes standard condition format with `observedGeneration` field

5. **Retry Logic:**
   - Exponential backoff with configurable base delay and max delay
   - Configurable max retry attempts
   - Environment variables:
     - `DNS_RECORD_RETRY_BASE_DELAY`: Base delay for exponential backoff (default: "5s")
     - `DNS_RECORD_RETRY_MAX_DELAY`: Maximum delay between retries (default: "60s")
     - `DNS_RECORD_RETRY_MAX_ATTEMPTS`: Maximum number of retry attempts (default: 5)
   - Backoff calculation: delay = min(baseDelay * 2^attempt, maxDelay)

6. **Finalizers:**
   - Add finalizer `dns.homelab.mortenolsen.pro/finalizer` to DNSRecord
   - Ensure DNS record is deleted from provider before removing Kubernetes resource

## Validation

### DNSRecord Validation

1. **Required Fields:**
   - `spec.type`: Must be valid DNS record type
   - `spec.domain`: Must be valid domain name format
   - `spec.subdomain`: Must be valid subdomain or "@"
   - `spec.values`: Must be non-empty array
   - `spec.dnsClassRef.name`: Must reference existing DNSClass

2. **Type-Specific Validation:**
   - **A**: Values must be valid IPv4 addresses
   - **AAAA**: Values must be valid IPv6 addresses
   - **CNAME**: Must have exactly one value, must be valid domain name
   - **TXT**: Values must be valid text strings
   - **MX**: Must have `metadata.priority`, values must be valid domain names
   - **SRV**: Must have `metadata.priority`, `metadata.weight`, `metadata.port`

3. **Webhook Validation:**
   - Implement ValidatingAdmissionWebhook for DNSRecord
   - Reject invalid configurations before they're persisted

### DNSClass Validation

1. **Required Fields:**
   - `spec.server`: Must be valid URL (http/https)

2. **Webhook Validation:**
   - Implement ValidatingAdmissionWebhook for DNSClass
   - Validate server URL format
   - Validate hmacAuth configuration:
     - Either `secretRef` or `secret` must be provided (not both)
     - If `secretRef` is used, validate namespace and key exist
     - Validate algorithm is SHA256 or SHA512

## Status Conditions

Status conditions follow Kubernetes best practices:

- Use standard condition types (`Ready`)
- Include `status`, `lastTransitionTime`, `observedGeneration`, `reason`, and `message` fields
- `observedGeneration` matches `metadata.generation` when condition reflects current spec

### DNSClass Conditions

- **Ready**: Indicates whether the DNSClass server is healthy (informational only)
  - `True`: Server is healthy and reachable
  - `False`: Server is unhealthy or unreachable
  - `Unknown`: Health check hasn't completed yet
  - Note: Unhealthy DNSClass does not block DNSRecord operations

### DNSRecord Conditions

- **Ready**: Indicates whether the DNS record has been successfully created/updated
  - `True`: Record exists and matches desired state
  - `False`: Record creation/update failed
  - `Unknown`: Reconciliation hasn't completed yet

## Configuration

### Environment Variables

The operator can be configured via environment variables:

- `DNS_CLASS_HEALTH_CHECK_INTERVAL`: Health check interval for DNSClass (default: "10m")
- `DNS_RECORD_RETRY_BASE_DELAY`: Base delay for exponential backoff (default: "5s")
- `DNS_RECORD_RETRY_MAX_DELAY`: Maximum delay between retries (default: "60s")
- `DNS_RECORD_RETRY_MAX_ATTEMPTS`: Maximum number of retry attempts (default: 5)

## Future Enhancements

1. **Additional Record Types:**
   - AAAA, TXT, MX, SRV, NS, PTR

2. **Additional Authentication Methods:**
   - Kubernetes ServiceAccount token authentication
   - mTLS authentication

3. **Batch Operations:**
   - Support for bulk record updates via webhook protocol

4. **Record Ownership:**
   - Track which DNSRecord owns which DNS provider record
   - Handle conflicts if multiple records try to manage same FQDN

5. **DNS Zone Management:**
   - DNSZone resource for managing entire DNS zones

6. **Provider-Specific Features:**
   - Support for provider-specific features via annotations or extensions

7. **Metrics and Observability:**
   - Prometheus metrics for reconciliation loops, webhook calls, errors
   - Distributed tracing for webhook calls

8. **Multi-Value Support:**
   - Better handling of multiple A/AAAA records for load balancing

9. **Record Validation:**
   - Pre-flight checks before creating records
   - DNS lookup validation

## Implementation Notes

1. **Kubebuilder Setup:**
   - Initialize project with domain `homelab.mortenolsen.pro` and group `dns`
   - Create API definitions for DNSClass and DNSRecord
   - Generate CRDs, controllers, and webhooks

2. **Controller Structure:**
   - `controllers/dnsclass_controller.go`: Manages DNSClass resources and health checks
   - `controllers/dnsrecord_controller.go`: Manages DNSRecord resources and DNS operations
   - `pkg/dnsclient/`: HTTP client for DNS server webhook communication with HMAC support
   - `pkg/validation/`: Validation logic for DNS records
   - `pkg/hmac/`: HMAC signature generation and verification utilities

3. **Testing:**
   - Unit tests for controllers
   - Integration tests with mock DNS server
   - E2E tests with real DNS provider

4. **Documentation:**
   - API documentation
   - User guide
   - DNS server implementation guide

## Open Questions / Assumptions

1. **Confirmed:** DNSClass is cluster-scoped, DNSRecord is namespace-scoped
2. **Confirmed:** Health check interval is 10 minutes (configurable via env var)
3. **Confirmed:** Default TTL is 300 seconds if not specified
4. **Confirmed:** HMAC-based authentication is supported (optional)
5. **Confirmed:** Webhook protocol uses JSON over HTTP/HTTPS
6. **Confirmed:** Single unified DNSRecord resource instead of separate ARecord/CNAME resources
7. **Confirmed:** Unhealthy DNSClass does not block DNSRecord operations (monitoring only)
8. **Confirmed:** Retry logic configurable via environment variables
9. **Confirmed:** Status conditions follow Kubernetes best practices with observedGeneration

## Next Steps

1. Initialize kubebuilder project
2. Define API types for DNSClass and DNSRecord
3. Implement controllers
4. Implement webhook validation
5. Create DNS client package
6. Write tests
7. Create example DNS server implementation
8. Write documentation
