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
	"context"
	"testing"
	"time"

	"github.com/mortenolsen/dns-operator/pkg/hmac"
)

func TestClient_HealthCheck(t *testing.T) {
	server := NewMockDNSServer(nil, "")
	defer server.Close()

	client := NewClient(server.URL(), 5*time.Second, nil, "")

	ctx := context.Background()
	health, err := client.CheckHealth(ctx)
	if err != nil {
		t.Fatalf("CheckHealth failed: %v", err)
	}

	if health.Status != "healthy" {
		t.Errorf("expected status 'healthy', got %q", health.Status)
	}
}

func TestClient_UpsertRecord(t *testing.T) {
	server := NewMockDNSServer(nil, "")
	defer server.Close()

	client := NewClient(server.URL(), 5*time.Second, nil, "")

	ctx := context.Background()
	record := RecordRequest{
		Type:      "A",
		Domain:    "example.com",
		Subdomain: "www",
		Values:    []string{"192.168.1.100"},
		TTL:       int32Ptr(300),
	}

	result, err := client.UpsertRecord(ctx, record)
	if err != nil {
		t.Fatalf("UpsertRecord failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected record result, got nil")
	}

	if result.Type != "A" {
		t.Errorf("expected type 'A', got %q", result.Type)
	}

	if result.FQDN != "www.example.com" {
		t.Errorf("expected FQDN 'www.example.com', got %q", result.FQDN)
	}

	// Verify record was stored
	stored := server.GetRecord("A", "example.com", "www")
	if stored == nil {
		t.Fatal("record was not stored")
	}
}

func TestClient_GetRecord(t *testing.T) {
	server := NewMockDNSServer(nil, "")
	defer server.Close()

	client := NewClient(server.URL(), 5*time.Second, nil, "")

	// First create a record
	ctx := context.Background()
	record := RecordRequest{
		Type:      "A",
		Domain:    "example.com",
		Subdomain: "www",
		Values:    []string{"192.168.1.100"},
	}

	_, err := client.UpsertRecord(ctx, record)
	if err != nil {
		t.Fatalf("UpsertRecord failed: %v", err)
	}

	// Now get it
	result, err := client.GetRecord(ctx, "A", "example.com", "www")
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected record, got nil")
	}

	if result.Type != "A" {
		t.Errorf("expected type 'A', got %q", result.Type)
	}
}

func TestClient_GetRecord_NotFound(t *testing.T) {
	server := NewMockDNSServer(nil, "")
	defer server.Close()

	client := NewClient(server.URL(), 5*time.Second, nil, "")

	ctx := context.Background()
	result, err := client.GetRecord(ctx, "A", "example.com", "nonexistent")
	if err != nil {
		t.Fatalf("GetRecord should not return error for not found: %v", err)
	}

	if result != nil {
		t.Error("expected nil for not found record")
	}
}

func TestClient_DeleteRecord(t *testing.T) {
	server := NewMockDNSServer(nil, "")
	defer server.Close()

	client := NewClient(server.URL(), 5*time.Second, nil, "")

	// First create a record
	ctx := context.Background()
	record := RecordRequest{
		Type:      "A",
		Domain:    "example.com",
		Subdomain: "www",
		Values:    []string{"192.168.1.100"},
	}

	_, err := client.UpsertRecord(ctx, record)
	if err != nil {
		t.Fatalf("UpsertRecord failed: %v", err)
	}

	// Verify it exists
	stored := server.GetRecord("A", "example.com", "www")
	if stored == nil {
		t.Fatal("record should exist before deletion")
	}

	// Delete it
	err = client.DeleteRecord(ctx, "A", "example.com", "www")
	if err != nil {
		t.Fatalf("DeleteRecord failed: %v", err)
	}

	// Verify it's gone
	stored = server.GetRecord("A", "example.com", "www")
	if stored != nil {
		t.Error("record should be deleted")
	}
}

func TestClient_HMACAuth(t *testing.T) {
	secret := []byte("test-secret-key")
	server := NewMockDNSServer(secret, hmac.AlgorithmSHA256)
	defer server.Close()

	client := NewClient(server.URL(), 5*time.Second, secret, hmac.AlgorithmSHA256)

	ctx := context.Background()

	// Test health check with HMAC
	health, err := client.CheckHealth(ctx)
	if err != nil {
		t.Fatalf("CheckHealth with HMAC failed: %v", err)
	}

	if health.Status != "healthy" {
		t.Errorf("expected status 'healthy', got %q", health.Status)
	}

	// Test upsert with HMAC
	record := RecordRequest{
		Type:      "A",
		Domain:    "example.com",
		Subdomain: "www",
		Values:    []string{"192.168.1.100"},
	}

	result, err := client.UpsertRecord(ctx, record)
	if err != nil {
		t.Fatalf("UpsertRecord with HMAC failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected record result, got nil")
	}
}

func TestClient_HMACAuth_InvalidSecret(t *testing.T) {
	serverSecret := []byte("server-secret")
	clientSecret := []byte("wrong-secret")
	server := NewMockDNSServer(serverSecret, hmac.AlgorithmSHA256)
	defer server.Close()

	client := NewClient(server.URL(), 5*time.Second, clientSecret, hmac.AlgorithmSHA256)

	ctx := context.Background()
	_, err := client.CheckHealth(ctx)
	if err == nil {
		t.Fatal("expected error for invalid HMAC secret")
	}

	// Check it's an authentication error
	if dnsErr, ok := err.(*Error); ok {
		if dnsErr.Status != 401 {
			t.Errorf("expected status 401, got %d", dnsErr.Status)
		}
	}
}

func int32Ptr(i int32) *int32 {
	return &i
}
