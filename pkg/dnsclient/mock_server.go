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

package dnsclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/mortenolsen/dns-operator/pkg/hmac"
)

// MockDNSServer is a mock DNS server for testing
type MockDNSServer struct {
	server     *httptest.Server
	records    map[string]*RecordResponse
	mu         sync.RWMutex
	hmacSecret []byte
	algorithm  hmac.Algorithm
	nonces     map[string]time.Time
	nonceMu    sync.RWMutex
}

// NewMockDNSServer creates a new mock DNS server
func NewMockDNSServer(hmacSecret []byte, algorithm hmac.Algorithm) *MockDNSServer {
	m := &MockDNSServer{
		records:    make(map[string]*RecordResponse),
		hmacSecret: hmacSecret,
		algorithm:  algorithm,
		nonces:     make(map[string]time.Time),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", m.handleHealth)
	mux.HandleFunc("/records", m.handleRecords)
	mux.HandleFunc("/records/", m.handleRecordOps)

	m.server = httptest.NewServer(mux)
	return m
}

// URL returns the server URL
func (m *MockDNSServer) URL() string {
	return m.server.URL
}

// Close shuts down the server
func (m *MockDNSServer) Close() {
	m.server.Close()
}

// GetRecord returns a record from the mock server
func (m *MockDNSServer) GetRecord(recordType, domain, subdomain string) *RecordResponse {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := fmt.Sprintf("%s/%s/%s", recordType, domain, subdomain)
	return m.records[key]
}

// SetRecord sets a record in the mock server
func (m *MockDNSServer) SetRecord(record *RecordResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s/%s", record.Type, record.Domain, record.Subdomain)
	m.records[key] = record
}

// handleHealth handles health check requests
func (m *MockDNSServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := m.validateHMAC(r, "", ""); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	response := HealthResponse{
		Status:    "healthy",
		Message:   "DNS server is operational",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// handleRecords handles POST /records requests
func (m *MockDNSServer) handleRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UpsertRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	bodyBytes, _ := json.Marshal(req)
	if err := m.validateHMAC(r, "/records", string(bodyBytes)); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Validate record
	if err := m.validateRecord(req.Record); err != nil {
		response := UpsertRecordResponse{
			Success: false,
			Error: &ErrorResponse{
				Code:    "INVALID_RECORD",
				Message: err.Error(),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Store record
	fqdn := req.Record.Subdomain
	if fqdn == "@" {
		fqdn = req.Record.Domain
	} else {
		fqdn = fmt.Sprintf("%s.%s", req.Record.Subdomain, req.Record.Domain)
	}

	record := &RecordResponse{
		Type:      req.Record.Type,
		Domain:    req.Record.Domain,
		Subdomain: req.Record.Subdomain,
		FQDN:      fqdn,
		Values:    req.Record.Values,
		TTL:       req.Record.TTL,
	}

	m.SetRecord(record)

	response := UpsertRecordResponse{
		Success: true,
		Record:  record,
		Message: "Record created successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// handleRecordOps handles GET and DELETE /records/{type}/{domain}/{subdomain} requests
func (m *MockDNSServer) handleRecordOps(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if err := m.validateHMAC(r, path, ""); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Parse path: /records/{type}/{domain}/{subdomain}
	parts := splitPath(path)
	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	recordType := parts[1]
	domain := parts[2]
	subdomain := parts[3]

	key := fmt.Sprintf("%s/%s/%s", recordType, domain, subdomain)

	switch r.Method {
	case http.MethodGet:
		m.mu.RLock()
		record := m.records[key]
		m.mu.RUnlock()

		if record == nil {
			response := GetRecordResponse{
				Success: false,
				Error: &ErrorResponse{
					Code:    "RECORD_NOT_FOUND",
					Message: "Record does not exist",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(response)
			return
		}

		response := GetRecordResponse{
			Success: true,
			Record:  record,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)

	case http.MethodDelete:
		m.mu.Lock()
		delete(m.records, key)
		m.mu.Unlock()

		response := DeleteRecordResponse{
			Success: true,
			Message: "Record deleted successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// validateHMAC validates HMAC authentication if configured
func (m *MockDNSServer) validateHMAC(r *http.Request, path, body string) error {
	if len(m.hmacSecret) == 0 {
		return nil // No HMAC auth required
	}

	timestampStr := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	signature := r.Header.Get(HeaderSignature)

	if timestampStr == "" || nonce == "" || signature == "" {
		return fmt.Errorf("missing HMAC headers")
	}

	// Parse timestamp
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return fmt.Errorf("invalid timestamp format")
	}

	// Check timestamp freshness (±5 minutes)
	now := time.Now().UTC()
	if timestamp.Before(now.Add(-5*time.Minute)) || timestamp.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("timestamp is stale")
	}

	// Check nonce reuse
	m.nonceMu.Lock()
	if usedTime, exists := m.nonces[nonce]; exists {
		// Check if nonce is within timestamp window
		if usedTime.After(timestamp.Add(-5 * time.Minute)) {
			m.nonceMu.Unlock()
			return fmt.Errorf("nonce has been reused")
		}
	}
	m.nonces[nonce] = timestamp
	// Clean up old nonces
	for n, t := range m.nonces {
		if t.Before(now.Add(-10 * time.Minute)) {
			delete(m.nonces, n)
		}
	}
	m.nonceMu.Unlock()

	// Recalculate HMAC
	method := r.Method
	if path == "" {
		path = r.URL.Path
	}

	components := []string{method, path, timestampStr, nonce}
	if body != "" {
		components = append(components, body)
	}

	expectedSig, err := hmac.CalculateHMAC(m.hmacSecret, m.algorithm, components...)
	if err != nil {
		return fmt.Errorf("failed to calculate HMAC: %w", err)
	}

	if expectedSig != signature {
		return fmt.Errorf("HMAC signature mismatch")
	}

	return nil
}

// validateRecord validates a DNS record
func (m *MockDNSServer) validateRecord(record RecordRequest) error {
	if record.Type == "" {
		return fmt.Errorf("record type is required")
	}
	if record.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if len(record.Values) == 0 {
		return fmt.Errorf("values are required")
	}
	return nil
}

// splitPath splits a URL path into parts
func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if start < i {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		parts = append(parts, path[start:])
	}
	return parts
}
