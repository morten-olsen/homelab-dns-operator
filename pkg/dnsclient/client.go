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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/mortenolsen/dns-operator/pkg/hmac"
)

const (
	// HeaderTimestamp is the HTTP header for the request timestamp
	HeaderTimestamp = "X-DNS-Timestamp"
	// HeaderNonce is the HTTP header for the request nonce
	HeaderNonce = "X-DNS-Nonce"
	// HeaderSignature is the HTTP header for the HMAC signature
	HeaderSignature = "X-DNS-Signature"
)

// Client is a DNS server webhook client
type Client struct {
	baseURL       string
	httpClient    *http.Client
	hmacSecret   []byte
	hmacAlgorithm hmac.Algorithm
}

// NewClient creates a new DNS client
func NewClient(baseURL string, timeout time.Duration, hmacSecret []byte, hmacAlgorithm hmac.Algorithm) *Client {
	return &Client{
		baseURL:       baseURL,
		httpClient:    &http.Client{Timeout: timeout},
		hmacSecret:   hmacSecret,
		hmacAlgorithm: hmacAlgorithm,
	}
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// RecordRequest represents a DNS record in a request
type RecordRequest struct {
	Type     string   `json:"type"`
	Domain   string   `json:"domain"`
	Subdomain string  `json:"subdomain"`
	Values   []string `json:"values"`
	TTL      *int32   `json:"ttl,omitempty"`
}

// UpsertRecordRequest represents an upsert record request
type UpsertRecordRequest struct {
	Record    RecordRequest `json:"record"`
	Operation string        `json:"operation"`
}

// RecordResponse represents a DNS record in a response
type RecordResponse struct {
	Type     string   `json:"type"`
	Domain   string   `json:"domain"`
	Subdomain string  `json:"subdomain"`
	FQDN     string   `json:"fqdn"`
	Values   []string `json:"values"`
	TTL      *int32   `json:"ttl,omitempty"`
}

// UpsertRecordResponse represents an upsert record response
type UpsertRecordResponse struct {
	Success bool          `json:"success"`
	Record  *RecordResponse `json:"record,omitempty"`
	Message string        `json:"message,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
}

// GetRecordResponse represents a get record response
type GetRecordResponse struct {
	Success bool          `json:"success"`
	Record  *RecordResponse `json:"record,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
}

// DeleteRecordResponse represents a delete record response
type DeleteRecordResponse struct {
	Success bool          `json:"success"`
	Message string        `json:"message,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// Error represents a client error
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string {
	return fmt.Sprintf("dns client error [%s]: %s (status: %d)", e.Code, e.Message, e.Status)
}

// prepareRequest prepares an HTTP request with HMAC authentication if configured
func (c *Client) prepareRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, path)
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for POST requests
	if method == http.MethodPost && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add HMAC authentication headers if configured
	if len(c.hmacSecret) > 0 {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		nonce := uuid.New().String()

		req.Header.Set(HeaderTimestamp, timestamp)
		req.Header.Set(HeaderNonce, nonce)

		// Calculate HMAC signature
		components := []string{
			method,
			path,
			timestamp,
			nonce,
		}
		if body != nil {
			components = append(components, string(body))
		}

		signature, err := hmac.CalculateHMAC(c.hmacSecret, c.hmacAlgorithm, components...)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate HMAC: %w", err)
		}

		req.Header.Set(HeaderSignature, signature)
	}

	return req, nil
}

// doRequest performs an HTTP request and returns the response
func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	return resp, nil
}

// CheckHealth checks if the DNS server is healthy
func (c *Client) CheckHealth(ctx context.Context) (*HealthResponse, error) {
	req, err := c.prepareRequest(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &Error{
			Code:    "HEALTH_CHECK_FAILED",
			Message: fmt.Sprintf("health check failed: %s", string(body)),
			Status:  resp.StatusCode,
		}
	}

	var healthResp HealthResponse
	if err := json.Unmarshal(body, &healthResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal health response: %w", err)
	}

	return &healthResp, nil
}

// UpsertRecord creates or updates a DNS record
func (c *Client) UpsertRecord(ctx context.Context, record RecordRequest) (*RecordResponse, error) {
	reqBody := UpsertRecordRequest{
		Record:    record,
		Operation: "upsert",
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := c.prepareRequest(ctx, http.MethodPost, "/records", bodyBytes)
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var upsertResp UpsertRecordResponse
	if err := json.Unmarshal(body, &upsertResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !upsertResp.Success {
		code := "SERVER_ERROR"
		message := "unknown error"
		if upsertResp.Error != nil {
			code = upsertResp.Error.Code
			message = upsertResp.Error.Message
		}
		return nil, &Error{
			Code:    code,
			Message: message,
			Status:  resp.StatusCode,
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &Error{
			Code:    "UPSERT_FAILED",
			Message: fmt.Sprintf("upsert failed: %s", string(body)),
			Status:  resp.StatusCode,
		}
	}

	return upsertResp.Record, nil
}

// GetRecord retrieves a DNS record
func (c *Client) GetRecord(ctx context.Context, recordType, domain, subdomain string) (*RecordResponse, error) {
	path := fmt.Sprintf("/records/%s/%s/%s", recordType, domain, subdomain)
	req, err := c.prepareRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var getResp GetRecordResponse
	if err := json.Unmarshal(body, &getResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !getResp.Success {
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil // Record not found is not an error
		}
		code := "SERVER_ERROR"
		message := "unknown error"
		if getResp.Error != nil {
			code = getResp.Error.Code
			message = getResp.Error.Message
		}
		return nil, &Error{
			Code:    code,
			Message: message,
			Status:  resp.StatusCode,
		}
	}

	return getResp.Record, nil
}

// DeleteRecord deletes a DNS record
func (c *Client) DeleteRecord(ctx context.Context, recordType, domain, subdomain string) error {
	path := fmt.Sprintf("/records/%s/%s/%s", recordType, domain, subdomain)
	req, err := c.prepareRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var deleteResp DeleteRecordResponse
	if err := json.Unmarshal(body, &deleteResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !deleteResp.Success {
		// 404 is treated as success for idempotency
		if resp.StatusCode == http.StatusNotFound {
			return nil
		}
		code := "SERVER_ERROR"
		message := "unknown error"
		if deleteResp.Error != nil {
			code = deleteResp.Error.Code
			message = deleteResp.Error.Message
		}
		return &Error{
			Code:    code,
			Message: message,
			Status:  resp.StatusCode,
		}
	}

	return nil
}
