# DNS Provider Backend Implementation Guide

This guide provides detailed instructions on how to build a DNS provider backend that implements the DNS Operator webhook protocol. The guide includes a complete example implementation using the Cloudflare SDK.

## Table of Contents

1. [Overview](#overview)
2. [Protocol Specification](#protocol-specification)
3. [Required Endpoints](#required-endpoints)
4. [HMAC Authentication](#hmac-authentication)
5. [Complete Cloudflare Example](#complete-cloudflare-example)
6. [Testing](#testing)
7. [Deployment](#deployment)
8. [Best Practices](#best-practices)

## Overview

A DNS provider backend is an HTTP/HTTPS service that implements the DNS Operator webhook protocol. The operator communicates with your backend to create, update, delete, and query DNS records.

### Key Requirements

- **HTTP/HTTPS Server**: Must expose REST endpoints over HTTP or HTTPS
- **JSON API**: All requests and responses use JSON format
- **HMAC Authentication**: Optional but recommended for production use
- **Idempotent Operations**: All operations should be idempotent
- **Error Handling**: Proper error codes and messages

### Architecture

```
┌─────────────────┐         HTTP/HTTPS         ┌──────────────────┐
│  DNS Operator   │ ──────────────────────────> │ DNS Provider     │
│   (Controller)  │                             │    Backend       │
└─────────────────┘                             └──────────────────┘
                                                         │
                                                         │ Cloudflare API
                                                         ▼
                                                  ┌──────────────┐
                                                  │  Cloudflare  │
                                                  │     DNS      │
                                                  └──────────────┘
```

## Protocol Specification

### Base URL

The DNS provider backend URL is specified in the `DNSClass` resource:

```yaml
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSClass
metadata:
  name: cloudflare
spec:
  server: "http://cloudflare-dns.dns.svc:7100"
```

### Request/Response Format

All requests use JSON encoding. Responses must include:
- `success`: Boolean indicating operation success
- `record`: DNS record data (when applicable)
- `error`: Error details (when `success` is false)
- `message`: Human-readable message (optional)

## Required Endpoints

### 1. Health Check Endpoint

**GET** `/health`

Returns the health status of the DNS provider backend.

**Request:**
```
GET /health HTTP/1.1
Host: cloudflare-dns.dns.svc:7100
X-DNS-Timestamp: 2025-12-30T10:00:00Z
X-DNS-Nonce: 550e8400-e29b-41d4-a716-446655440000
X-DNS-Signature: a1b2c3d4e5f6...  # If HMAC auth is configured
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "message": "DNS server is operational",
  "timestamp": "2025-12-30T10:00:00Z"
}
```

**Response (503 Service Unavailable):**
```json
{
  "status": "unhealthy",
  "message": "DNS provider API is unavailable",
  "timestamp": "2025-12-30T10:00:00Z"
}
```

### 2. Create/Update Record Endpoint

**POST** `/records`

Creates or updates a DNS record (idempotent operation).

**Request:**
```
POST /records HTTP/1.1
Host: cloudflare-dns.dns.svc:7100
Content-Type: application/json
X-DNS-Timestamp: 2025-12-30T10:00:00Z
X-DNS-Nonce: 550e8400-e29b-41d4-a716-446655440000
X-DNS-Signature: a1b2c3d4e5f6...

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

**Response (200 OK):**
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

**Response (400 Bad Request):**
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

### 3. Delete Record Endpoint

**DELETE** `/records/{type}/{domain}/{subdomain}`

Deletes a DNS record. Should return success even if the record doesn't exist (idempotent).

**Request:**
```
DELETE /records/A/example.com/www HTTP/1.1
Host: cloudflare-dns.dns.svc:7100
X-DNS-Timestamp: 2025-12-30T10:00:00Z
X-DNS-Nonce: 550e8400-e29b-41d4-a716-446655440000
X-DNS-Signature: a1b2c3d4e5f6...
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Record deleted successfully"
}
```

**Response (404 Not Found):**
```json
{
  "success": true,
  "message": "Record does not exist (already deleted)"
}
```

### 4. Get Record Endpoint (Optional)

**GET** `/records/{type}/{domain}/{subdomain}`

Retrieves the current state of a DNS record. This is optional but recommended for reconciliation.

**Request:**
```
GET /records/A/example.com/www HTTP/1.1
Host: cloudflare-dns.dns.svc:7100
X-DNS-Timestamp: 2025-12-30T10:00:00Z
X-DNS-Nonce: 550e8400-e29b-41d4-a716-446655440000
X-DNS-Signature: a1b2c3d4e5f6...
```

**Response (200 OK):**
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

**Response (404 Not Found):**
```json
{
  "success": false,
  "error": {
    "code": "RECORD_NOT_FOUND",
    "message": "Record does not exist"
  }
}
```

## HMAC Authentication

HMAC authentication provides request integrity verification and prevents replay attacks.

### How It Works

1. The operator calculates an HMAC signature over:
   - HTTP method (e.g., "POST", "DELETE")
   - Request path (e.g., "/records")
   - RFC3339 timestamp (e.g., "2025-12-30T10:00:00Z")
   - Nonce (unique random value per request)
   - Request body (JSON payload, if present)

2. Components are joined with newlines (`\n`) in order
3. HMAC is calculated using SHA256 or SHA512
4. Signature is sent as hexadecimal string in `X-DNS-Signature` header

### Verification Steps

Your backend must:

1. **Extract Headers**: Read `X-DNS-Timestamp`, `X-DNS-Nonce`, and `X-DNS-Signature`
2. **Verify Timestamp**: Check timestamp is within ±5 minutes (allow clock skew)
3. **Check Nonce**: Ensure nonce hasn't been used before (within timestamp window)
4. **Recalculate HMAC**: Rebuild the signature using the same secret and components
5. **Compare Signatures**: Reject if signatures don't match
6. **Store Nonce**: Track used nonces to prevent replay attacks

### Security Considerations

- **Secret Storage**: Store HMAC secret securely (environment variable, Kubernetes secret, etc.)
- **Clock Skew**: Allow ±5 minutes timestamp window
- **Nonce Storage**: Maintain cache of used nonces (within timestamp window)
- **Cleanup**: Periodically remove expired nonces from cache
- **Secret Rotation**: Coordinate secret updates between operator and backend

## Complete Cloudflare Example

Here's a complete implementation using the Cloudflare SDK:

### Project Structure

```
cloudflare-dns-backend/
├── go.mod
├── go.sum
├── main.go
├── server.go
├── handlers.go
├── hmac.go
├── cloudflare.go
└── Dockerfile
```

### go.mod

```go
module github.com/example/cloudflare-dns-backend

go 1.24.6

require (
    github.com/cloudflare/cloudflare-go v0.95.0
    github.com/google/uuid v1.6.0
    github.com/gorilla/mux v1.8.1
    go.uber.org/zap v1.27.0
)
```

### main.go

```go
package main

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "go.uber.org/zap"
)

func main() {
    // Initialize logger
    logger, err := zap.NewProduction()
    if err != nil {
        panic(fmt.Sprintf("failed to initialize logger: %v", err))
    }
    defer logger.Sync()

    // Get configuration from environment
    port := getEnv("PORT", "7100")
    hmacSecret := getEnv("HMAC_SECRET", "")
    cloudflareAPIKey := getEnv("CLOUDFLARE_API_KEY", "")
    cloudflareEmail := getEnv("CLOUDFLARE_EMAIL", "")
    cloudflareAccountID := getEnv("CLOUDFLARE_ACCOUNT_ID", "")

    if cloudflareAPIKey == "" || cloudflareEmail == "" {
        logger.Fatal("CLOUDFLARE_API_KEY and CLOUDFLARE_EMAIL must be set")
    }

    // Initialize Cloudflare client
    cfClient, err := NewCloudflareClient(cloudflareAPIKey, cloudflareEmail, cloudflareAccountID, logger)
    if err != nil {
        logger.Fatal("failed to create Cloudflare client", zap.Error(err))
    }

    // Initialize HMAC verifier
    var hmacVerifier *HMACVerifier
    if hmacSecret != "" {
        hmacVerifier = NewHMACVerifier([]byte(hmacSecret), logger)
    }

    // Create server
    server := NewServer(cfClient, hmacVerifier, logger)

    // Setup HTTP server
    httpServer := &http.Server{
        Addr:         ":" + port,
        Handler:      server.Router(),
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    // Start server in goroutine
    go func() {
        logger.Info("starting DNS provider backend", zap.String("port", port))
        if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            logger.Fatal("failed to start server", zap.Error(err))
        }
    }()

    // Wait for interrupt signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    logger.Info("shutting down server")

    // Graceful shutdown
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := httpServer.Shutdown(ctx); err != nil {
        logger.Error("server forced to shutdown", zap.Error(err))
    }

    logger.Info("server exited")
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

### server.go

```go
package main

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/gorilla/mux"
    "go.uber.org/zap"
)

type Server struct {
    cloudflare   *CloudflareClient
    hmacVerifier *HMACVerifier
    logger       *zap.Logger
}

func NewServer(cloudflare *CloudflareClient, hmacVerifier *HMACVerifier, logger *zap.Logger) *Server {
    return &Server{
        cloudflare:   cloudflare,
        hmacVerifier: hmacVerifier,
        logger:       logger,
    }
}

func (s *Server) Router() *mux.Router {
    router := mux.NewRouter()

    // Health check endpoint
    router.HandleFunc("/health", s.handleHealth).Methods("GET")

    // Record endpoints
    router.HandleFunc("/records", s.handleUpsertRecord).Methods("POST")
    router.HandleFunc("/records/{type}/{domain}/{subdomain}", s.handleGetRecord).Methods("GET")
    router.HandleFunc("/records/{type}/{domain}/{subdomain}", s.handleDeleteRecord).Methods("DELETE")

    // Add middleware
    router.Use(s.loggingMiddleware)
    if s.hmacVerifier != nil {
        router.Use(s.hmacMiddleware)
    }

    return router
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        next.ServeHTTP(w, r)
        s.logger.Info("request",
            zap.String("method", r.Method),
            zap.String("path", r.URL.Path),
            zap.Duration("duration", time.Since(start)),
        )
    })
}

func (s *Server) hmacMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if err := s.hmacVerifier.VerifyRequest(r); err != nil {
            s.logger.Warn("HMAC verification failed", zap.Error(err))
            s.writeError(w, http.StatusUnauthorized, "AUTH_FAILED", err.Error())
            return
        }
        next.ServeHTTP(w, r)
    })
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    if err := json.NewEncoder(w).Encode(data); err != nil {
        s.logger.Error("failed to encode response", zap.Error(err))
    }
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
    s.writeJSON(w, status, map[string]interface{}{
        "success": false,
        "error": map[string]interface{}{
            "code":    code,
            "message": message,
        },
    })
}
```

### handlers.go

```go
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "strings"
    "time"

    "github.com/gorilla/mux"
    "go.uber.org/zap"
)

// HealthResponse represents a health check response
type HealthResponse struct {
    Status    string `json:"status"`
    Message   string `json:"message"`
    Timestamp string `json:"timestamp"`
}

// UpsertRecordRequest represents an upsert record request
type UpsertRecordRequest struct {
    Record    RecordRequest `json:"record"`
    Operation string        `json:"operation"`
}

// RecordRequest represents a DNS record in a request
type RecordRequest struct {
    Type      string   `json:"type"`
    Domain    string   `json:"domain"`
    Subdomain string   `json:"subdomain"`
    Values    []string `json:"values"`
    TTL       *int32   `json:"ttl,omitempty"`
}

// RecordResponse represents a DNS record in a response
type RecordResponse struct {
    Type      string   `json:"type"`
    Domain    string   `json:"domain"`
    Subdomain string   `json:"subdomain"`
    FQDN      string   `json:"fqdn"`
    Values    []string `json:"values"`
    TTL       *int32   `json:"ttl,omitempty"`
}

// UpsertRecordResponse represents an upsert record response
type UpsertRecordResponse struct {
    Success bool            `json:"success"`
    Record  *RecordResponse `json:"record,omitempty"`
    Message string          `json:"message,omitempty"`
    Error   *ErrorResponse  `json:"error,omitempty"`
}

// GetRecordResponse represents a get record response
type GetRecordResponse struct {
    Success bool            `json:"success"`
    Record  *RecordResponse `json:"record,omitempty"`
    Error   *ErrorResponse  `json:"error,omitempty"`
}

// DeleteRecordResponse represents a delete record response
type DeleteRecordResponse struct {
    Success bool           `json:"success"`
    Message string         `json:"message,omitempty"`
    Error   *ErrorResponse `json:"error,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
    Code    string                 `json:"code"`
    Message string                 `json:"message"`
    Details map[string]interface{} `json:"details,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    // Check Cloudflare API connectivity
    healthy, err := s.cloudflare.CheckHealth(r.Context())
    if err != nil || !healthy {
        s.writeJSON(w, http.StatusServiceUnavailable, HealthResponse{
            Status:    "unhealthy",
            Message:   "DNS provider API is unavailable",
            Timestamp: time.Now().UTC().Format(time.RFC3339),
        })
        return
    }

    s.writeJSON(w, http.StatusOK, HealthResponse{
        Status:    "healthy",
        Message:   "DNS server is operational",
        Timestamp: time.Now().UTC().Format(time.RFC3339),
    })
}

func (s *Server) handleUpsertRecord(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        s.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to read request body")
        return
    }

    var req UpsertRecordRequest
    if err := json.Unmarshal(body, &req); err != nil {
        s.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON payload")
        return
    }

    // Validate record
    if err := validateRecord(req.Record); err != nil {
        s.writeError(w, http.StatusBadRequest, "INVALID_RECORD", err.Error())
        return
    }

    // Upsert record via Cloudflare
    record, err := s.cloudflare.UpsertRecord(r.Context(), req.Record)
    if err != nil {
        s.logger.Error("failed to upsert record", zap.Error(err))
        s.writeError(w, http.StatusInternalServerError, "SERVER_ERROR", err.Error())
        return
    }

    s.writeJSON(w, http.StatusOK, UpsertRecordResponse{
        Success: true,
        Record:  record,
        Message: "Record created successfully",
    })
}

func (s *Server) handleGetRecord(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    recordType := vars["type"]
    domain := vars["domain"]
    subdomain := vars["subdomain"]

    record, err := s.cloudflare.GetRecord(r.Context(), recordType, domain, subdomain)
    if err != nil {
        s.logger.Error("failed to get record", zap.Error(err))
        s.writeJSON(w, http.StatusNotFound, GetRecordResponse{
            Success: false,
            Error: &ErrorResponse{
                Code:    "RECORD_NOT_FOUND",
                Message: "Record does not exist",
            },
        })
        return
    }

    s.writeJSON(w, http.StatusOK, GetRecordResponse{
        Success: true,
        Record:  record,
    })
}

func (s *Server) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    recordType := vars["type"]
    domain := vars["domain"]
    subdomain := vars["subdomain"]

    err := s.cloudflare.DeleteRecord(r.Context(), recordType, domain, subdomain)
    if err != nil {
        // 404 is treated as success for idempotency
        if isNotFound(err) {
            s.writeJSON(w, http.StatusOK, DeleteRecordResponse{
                Success: true,
                Message: "Record does not exist (already deleted)",
            })
            return
        }

        s.logger.Error("failed to delete record", zap.Error(err))
        s.writeError(w, http.StatusInternalServerError, "SERVER_ERROR", err.Error())
        return
    }

    s.writeJSON(w, http.StatusOK, DeleteRecordResponse{
        Success: true,
        Message: "Record deleted successfully",
    })
}

func validateRecord(record RecordRequest) error {
    if record.Type == "" {
        return fmt.Errorf("record type is required")
    }
    if record.Domain == "" {
        return fmt.Errorf("domain is required")
    }
    if len(record.Values) == 0 {
        return fmt.Errorf("values are required")
    }

    // Type-specific validation
    switch record.Type {
    case "A":
        for _, value := range record.Values {
            if !isValidIPv4(value) {
                return fmt.Errorf("invalid IPv4 address: %s", value)
            }
        }
    case "AAAA":
        for _, value := range record.Values {
            if !isValidIPv6(value) {
                return fmt.Errorf("invalid IPv6 address: %s", value)
            }
        }
    case "CNAME":
        if len(record.Values) != 1 {
            return fmt.Errorf("CNAME records must have exactly one value")
        }
        if !isValidDomain(record.Values[0]) {
            return fmt.Errorf("invalid CNAME value: %s", record.Values[0])
        }
    }

    return nil
}

func isValidIPv4(ip string) bool {
    // Use net.ParseIP for production validation
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return false
    }
    // Check if it's IPv4 (not IPv6)
    return parsedIP.To4() != nil
}

func isValidIPv6(ip string) bool {
    // Use net.ParseIP for production validation
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return false
    }
    // Check if it's IPv6
    return parsedIP.To4() == nil && parsedIP.To16() != nil
}

func isValidDomain(domain string) bool {
    // Simple validation - use proper DNS validation library for production
    return len(domain) > 0 && len(domain) <= 253
}

func isNotFound(err error) bool {
    // Check if error indicates record not found
    return strings.Contains(err.Error(), "not found") ||
        strings.Contains(err.Error(), "RECORD_NOT_FOUND")
}
```

### hmac.go

```go
package main

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "sync"
    "time"

    "go.uber.org/zap"
)

const (
    HeaderTimestamp = "X-DNS-Timestamp"
    HeaderNonce     = "X-DNS-Nonce"
    HeaderSignature = "X-DNS-Signature"
)

// HMACVerifier verifies HMAC signatures on incoming requests
type HMACVerifier struct {
    secret     []byte
    logger     *zap.Logger
    usedNonces map[string]time.Time
    mutex      sync.RWMutex
}

// NewHMACVerifier creates a new HMAC verifier
func NewHMACVerifier(secret []byte, logger *zap.Logger) *HMACVerifier {
    verifier := &HMACVerifier{
        secret:     secret,
        logger:     logger,
        usedNonces: make(map[string]time.Time),
    }

    // Start cleanup goroutine for expired nonces
    go verifier.cleanupExpiredNonces()

    return verifier
}

// VerifyRequest verifies the HMAC signature on an HTTP request
func (v *HMACVerifier) VerifyRequest(r *http.Request) error {
    // Extract headers
    timestamp := r.Header.Get(HeaderTimestamp)
    nonce := r.Header.Get(HeaderNonce)
    signature := r.Header.Get(HeaderSignature)

    if timestamp == "" || nonce == "" || signature == "" {
        return fmt.Errorf("missing HMAC headers")
    }

    // Verify timestamp freshness (±5 minutes)
    reqTime, err := time.Parse(time.RFC3339, timestamp)
    if err != nil {
        return fmt.Errorf("invalid timestamp format: %w", err)
    }

    now := time.Now().UTC()
    diff := now.Sub(reqTime)
    if diff < -5*time.Minute || diff > 5*time.Minute {
        return fmt.Errorf("timestamp is stale: %v", diff)
    }

    // Check nonce reuse
    if v.isNonceUsed(nonce, reqTime) {
        return fmt.Errorf("nonce has been reused")
    }

    // Read request body
    body, err := io.ReadAll(r.Body)
    if err != nil {
        return fmt.Errorf("failed to read request body: %w", err)
    }
    r.Body = io.NopCloser(bytes.NewReader(body)) // Restore body for handler

    // Rebuild components for HMAC calculation
    components := []string{
        r.Method,
        r.URL.Path,
        timestamp,
        nonce,
    }
    if len(body) > 0 {
        components = append(components, string(body))
    }

    // Calculate expected HMAC
    // Note: Algorithm should match the one configured in DNSClass (SHA256 or SHA512)
    expectedSig, err := v.calculateHMAC(components...)
    if err != nil {
        return fmt.Errorf("failed to calculate HMAC: %w", err)
    }

    // Compare signatures (constant-time comparison)
    if !hmac.Equal([]byte(expectedSig), []byte(signature)) {
        return fmt.Errorf("HMAC signature mismatch")
    }

    // Store nonce
    v.storeNonce(nonce, reqTime)

    return nil
}

func (v *HMACVerifier) calculateHMAC(components ...string) (string, error) {
    // Use SHA256 by default - you may want to make this configurable
    // to support both SHA256 and SHA512 as specified in the protocol
    mac := hmac.New(sha256.New, v.secret)
    for i, component := range components {
        if i > 0 {
            mac.Write([]byte("\n"))
        }
        mac.Write([]byte(component))
    }
    signature := mac.Sum(nil)
    return hex.EncodeToString(signature), nil
}

func (v *HMACVerifier) isNonceUsed(nonce string, timestamp time.Time) bool {
    v.mutex.RLock()
    defer v.mutex.RUnlock()

    if usedTime, exists := v.usedNonces[nonce]; exists {
        // Check if within timestamp window
        diff := timestamp.Sub(usedTime)
        if diff >= -5*time.Minute && diff <= 5*time.Minute {
            return true
        }
    }
    return false
}

func (v *HMACVerifier) storeNonce(nonce string, timestamp time.Time) {
    v.mutex.Lock()
    defer v.mutex.Unlock()
    v.usedNonces[nonce] = timestamp
}

func (v *HMACVerifier) cleanupExpiredNonces() {
    ticker := time.NewTicker(10 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        v.mutex.Lock()
        now := time.Now().UTC()
        for nonce, timestamp := range v.usedNonces {
            // Remove nonces older than 10 minutes
            if now.Sub(timestamp) > 10*time.Minute {
                delete(v.usedNonces, nonce)
            }
        }
        v.mutex.Unlock()
        v.logger.Debug("cleaned up expired nonces", zap.Int("remaining", len(v.usedNonces)))
    }
}
```

### cloudflare.go

```go
package main

import (
    "context"
    "fmt"
    "strings"
    "time"

    "github.com/cloudflare/cloudflare-go"
    "go.uber.org/zap"
)

type CloudflareClient struct {
    api    *cloudflare.API
    logger *zap.Logger
}

func NewCloudflareClient(apiKey, email, accountID string, logger *zap.Logger) (*CloudflareClient, error) {
    api, err := cloudflare.New(apiKey, email)
    if err != nil {
        return nil, fmt.Errorf("failed to create Cloudflare API client: %w", err)
    }

    if accountID != "" {
        api.AccountID = accountID
    }

    return &CloudflareClient{
        api:    api,
        logger: logger,
    }, nil
}

func (c *CloudflareClient) CheckHealth(ctx context.Context) (bool, error) {
    // Simple health check - verify API connectivity
    _, err := c.api.ListZones(ctx)
    if err != nil {
        return false, err
    }
    return true, nil
}

func (c *CloudflareClient) UpsertRecord(ctx context.Context, record RecordRequest) (*RecordResponse, error) {
    // Get zone ID
    zoneID, err := c.api.ZoneIDByName(record.Domain)
    if err != nil {
        return nil, fmt.Errorf("failed to get zone ID for domain %s: %w", record.Domain, err)
    }

    // Build DNS record name
    name := c.buildRecordName(record.Domain, record.Subdomain)

    // Check if record exists
    records, err := c.api.DNSRecords(ctx, zoneID, cloudflare.DNSRecord{
        Type: record.Type,
        Name: name,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to list DNS records: %w", err)
    }

    // Set TTL (default to 300 if not specified)
    ttl := int(300)
    if record.TTL != nil {
        ttl = int(*record.TTL)
    }

    // Prepare record data
    dnsRecord := cloudflare.DNSRecord{
        Type: record.Type,
        Name: name,
        TTL:  ttl,
    }

    // Set content based on record type
    switch record.Type {
    case "A", "AAAA":
        // For A/AAAA records, Cloudflare expects comma-separated values
        dnsRecord.Content = strings.Join(record.Values, ",")
    case "CNAME":
        if len(record.Values) != 1 {
            return nil, fmt.Errorf("CNAME records must have exactly one value")
        }
        dnsRecord.Content = record.Values[0]
    default:
        return nil, fmt.Errorf("unsupported record type: %s", record.Type)
    }

    var recordID string
    if len(records) > 0 {
        // Update existing record
        recordID = records[0].ID
        dnsRecord.ID = recordID
        err = c.api.UpdateDNSRecord(ctx, zoneID, recordID, dnsRecord)
        if err != nil {
            return nil, fmt.Errorf("failed to update DNS record: %w", err)
        }
        c.logger.Info("updated DNS record",
            zap.String("zone", zoneID),
            zap.String("record", name),
            zap.String("type", record.Type),
        )
    } else {
        // Create new record
        resp, err := c.api.CreateDNSRecord(ctx, zoneID, dnsRecord)
        if err != nil {
            return nil, fmt.Errorf("failed to create DNS record: %w", err)
        }
        recordID = resp.Result.ID
        c.logger.Info("created DNS record",
            zap.String("zone", zoneID),
            zap.String("record", name),
            zap.String("type", record.Type),
        )
    }

    // Build response
    fqdn := c.buildFQDN(record.Domain, record.Subdomain)
    return &RecordResponse{
        Type:      record.Type,
        Domain:    record.Domain,
        Subdomain: record.Subdomain,
        FQDN:      fqdn,
        Values:    record.Values,
        TTL:       record.TTL,
    }, nil
}

func (c *CloudflareClient) GetRecord(ctx context.Context, recordType, domain, subdomain string) (*RecordResponse, error) {
    // Get zone ID
    zoneID, err := c.api.ZoneIDByName(domain)
    if err != nil {
        return nil, fmt.Errorf("failed to get zone ID for domain %s: %w", domain, err)
    }

    // Build DNS record name
    name := c.buildRecordName(domain, subdomain)

    // Get records
    records, err := c.api.DNSRecords(ctx, zoneID, cloudflare.DNSRecord{
        Type: recordType,
        Name: name,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to list DNS records: %w", err)
    }

    if len(records) == 0 {
        return nil, fmt.Errorf("record not found")
    }

    // Parse values from Cloudflare record
    record := records[0]
    values := c.parseValues(recordType, record.Content)

    ttl := int32(record.TTL)

    fqdn := c.buildFQDN(domain, subdomain)
    return &RecordResponse{
        Type:      recordType,
        Domain:    domain,
        Subdomain: subdomain,
        FQDN:      fqdn,
        Values:    values,
        TTL:       &ttl,
    }, nil
}

func (c *CloudflareClient) DeleteRecord(ctx context.Context, recordType, domain, subdomain string) error {
    // Get zone ID
    zoneID, err := c.api.ZoneIDByName(domain)
    if err != nil {
        return fmt.Errorf("failed to get zone ID for domain %s: %w", domain, err)
    }

    // Build DNS record name
    name := c.buildRecordName(domain, subdomain)

    // Get records
    records, err := c.api.DNSRecords(ctx, zoneID, cloudflare.DNSRecord{
        Type: recordType,
        Name: name,
    })
    if err != nil {
        return fmt.Errorf("failed to list DNS records: %w", err)
    }

    if len(records) == 0 {
        return fmt.Errorf("record not found")
    }

    // Delete record
    err = c.api.DeleteDNSRecord(ctx, zoneID, records[0].ID)
    if err != nil {
        return fmt.Errorf("failed to delete DNS record: %w", err)
    }

    c.logger.Info("deleted DNS record",
        zap.String("zone", zoneID),
        zap.String("record", name),
        zap.String("type", recordType),
    )

    return nil
}

func (c *CloudflareClient) buildRecordName(domain, subdomain string) string {
    if subdomain == "@" || subdomain == "" {
        return domain
    }
    return fmt.Sprintf("%s.%s", subdomain, domain)
}

func (c *CloudflareClient) buildFQDN(domain, subdomain string) string {
    if subdomain == "@" || subdomain == "" {
        return domain
    }
    return fmt.Sprintf("%s.%s", subdomain, domain)
}

func (c *CloudflareClient) parseValues(recordType, content string) []string {
    switch recordType {
    case "A", "AAAA":
        // Cloudflare may return comma-separated values
        return strings.Split(content, ",")
    case "CNAME":
        return []string{content}
    default:
        return []string{content}
    }
}
```

### Dockerfile

```dockerfile
FROM golang:1.24.6-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cloudflare-dns-backend .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /build/cloudflare-dns-backend .

EXPOSE 7100

CMD ["./cloudflare-dns-backend"]
```

## Testing

### Manual Testing

Test your backend using `curl`:

```bash
# Health check
curl http://localhost:7100/health

# Create A record (without HMAC)
curl -X POST http://localhost:7100/records \
  -H "Content-Type: application/json" \
  -d '{
    "record": {
      "type": "A",
      "domain": "example.com",
      "subdomain": "www",
      "values": ["192.168.1.100"],
      "ttl": 600
    },
    "operation": "upsert"
  }'

# Get record
curl http://localhost:7100/records/A/example.com/www

# Delete record
curl -X DELETE http://localhost:7100/records/A/example.com/www
```

### Unit Tests

Create test files for each component:

```go
// cloudflare_test.go
package main

import (
    "context"
    "testing"
)

func TestCloudflareClient_UpsertRecord(t *testing.T) {
    // Mock Cloudflare API or use test account
    // Test record creation and updates
}

func TestHMACVerifier_VerifyRequest(t *testing.T) {
    // Test HMAC verification logic
    // Test timestamp validation
    // Test nonce reuse detection
}
```

## Deployment

### Kubernetes Deployment

Create a Kubernetes deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudflare-dns-backend
  namespace: dns-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cloudflare-dns-backend
  template:
    metadata:
      labels:
        app: cloudflare-dns-backend
    spec:
      containers:
      - name: backend
        image: your-registry/cloudflare-dns-backend:latest
        ports:
        - containerPort: 7100
        env:
        - name: PORT
          value: "7100"
        - name: HMAC_SECRET
          valueFrom:
            secretKeyRef:
              name: cloudflare-dns-secret
              key: hmac-secret
        - name: CLOUDFLARE_API_KEY
          valueFrom:
            secretKeyRef:
              name: cloudflare-credentials
              key: api-key
        - name: CLOUDFLARE_EMAIL
          valueFrom:
            secretKeyRef:
              name: cloudflare-credentials
              key: email
        - name: CLOUDFLARE_ACCOUNT_ID
          valueFrom:
            secretKeyRef:
              name: cloudflare-credentials
              key: account-id
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: cloudflare-dns
  namespace: dns-system
spec:
  selector:
    app: cloudflare-dns-backend
  ports:
  - port: 7100
    targetPort: 7100
  type: ClusterIP
```

### DNSClass Configuration

Create a DNSClass resource:

```yaml
apiVersion: dns.homelab.mortenolsen.pro/v1alpha1
kind: DNSClass
metadata:
  name: cloudflare
spec:
  server: "http://cloudflare-dns.dns-system.svc:7100"
  defaultTTL: 300
  timeoutSeconds: 30
  hmacAuth:
    secretRef:
      name: cloudflare-dns-secret
      namespace: dns-system
      key: hmac-secret
    algorithm: "SHA256"
```

## Best Practices

### Security

1. **Use HTTPS**: Always use HTTPS in production
2. **HMAC Authentication**: Enable HMAC authentication for production deployments
3. **Secret Management**: Store secrets in Kubernetes secrets or secret management systems
4. **Least Privilege**: Use API keys with minimal required permissions
5. **Rate Limiting**: Implement rate limiting to prevent abuse

### Reliability

1. **Idempotency**: Ensure all operations are idempotent
2. **Error Handling**: Return proper error codes and messages
3. **Retries**: Handle transient failures gracefully
4. **Health Checks**: Implement comprehensive health checks
5. **Logging**: Log all operations for debugging and auditing

### Performance

1. **Connection Pooling**: Reuse HTTP connections
2. **Caching**: Cache zone IDs and other frequently accessed data
3. **Timeouts**: Set appropriate timeouts for API calls
4. **Concurrency**: Handle concurrent requests efficiently
5. **Monitoring**: Add metrics and monitoring

### Code Quality

1. **Validation**: Validate all inputs
2. **Error Messages**: Provide clear, actionable error messages
3. **Testing**: Write comprehensive unit and integration tests
4. **Documentation**: Document API endpoints and behavior
5. **Versioning**: Consider API versioning for future changes

## Additional Resources

- [DNS Operator Specification](../spec/2025-12-30-dns-operator-spec.md)
- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)
- [Cloudflare Go SDK](https://github.com/cloudflare/cloudflare-go)

## Troubleshooting

### Common Issues

1. **HMAC Verification Fails**
   - Check secret matches between operator and backend
   - Verify timestamp is within ±5 minutes
   - Ensure nonce is unique

2. **Record Not Found**
   - Verify zone exists in Cloudflare
   - Check domain name matches exactly
   - Ensure API key has proper permissions

3. **Rate Limiting**
   - Implement exponential backoff
   - Cache frequently accessed data
   - Consider request batching

4. **Connection Issues**
   - Check network connectivity
   - Verify service endpoints
   - Review firewall rules

## Conclusion

This guide provides a complete foundation for building a DNS provider backend. The Cloudflare example demonstrates all required endpoints and best practices. Adapt the code to your specific DNS provider's API while maintaining compatibility with the DNS Operator webhook protocol.
