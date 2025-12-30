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

package hmac

import (
	"testing"
)

func TestCalculateHMAC_SHA256(t *testing.T) {
	secret := []byte("test-secret")
	components := []string{"POST", "/records", "2025-12-30T10:00:00Z", "nonce-123", `{"test":"data"}`}

	signature, err := CalculateHMAC(secret, AlgorithmSHA256, components...)
	if err != nil {
		t.Fatalf("CalculateHMAC failed: %v", err)
	}

	if signature == "" {
		t.Error("signature should not be empty")
	}

	// Verify signature is hex-encoded
	if len(signature) != 64 { // SHA256 produces 32 bytes = 64 hex chars
		t.Errorf("expected signature length 64, got %d", len(signature))
	}

	// Verify same input produces same signature
	signature2, err := CalculateHMAC(secret, AlgorithmSHA256, components...)
	if err != nil {
		t.Fatalf("CalculateHMAC failed: %v", err)
	}

	if signature != signature2 {
		t.Error("same input should produce same signature")
	}
}

func TestCalculateHMAC_SHA512(t *testing.T) {
	secret := []byte("test-secret")
	components := []string{"POST", "/records", "2025-12-30T10:00:00Z", "nonce-123", `{"test":"data"}`}

	signature, err := CalculateHMAC(secret, AlgorithmSHA512, components...)
	if err != nil {
		t.Fatalf("CalculateHMAC failed: %v", err)
	}

	if signature == "" {
		t.Error("signature should not be empty")
	}

	// Verify signature is hex-encoded
	if len(signature) != 128 { // SHA512 produces 64 bytes = 128 hex chars
		t.Errorf("expected signature length 128, got %d", len(signature))
	}
}

func TestCalculateHMAC_InvalidAlgorithm(t *testing.T) {
	secret := []byte("test-secret")
	components := []string{"POST", "/records"}

	_, err := CalculateHMAC(secret, Algorithm("INVALID"), components...)
	if err == nil {
		t.Error("expected error for invalid algorithm")
	}
}

func TestCalculateHMAC_DifferentInputs(t *testing.T) {
	secret := []byte("test-secret")
	components1 := []string{"POST", "/records", "2025-12-30T10:00:00Z"}
	components2 := []string{"GET", "/records", "2025-12-30T10:00:00Z"}

	sig1, err := CalculateHMAC(secret, AlgorithmSHA256, components1...)
	if err != nil {
		t.Fatalf("CalculateHMAC failed: %v", err)
	}

	sig2, err := CalculateHMAC(secret, AlgorithmSHA256, components2...)
	if err != nil {
		t.Fatalf("CalculateHMAC failed: %v", err)
	}

	if sig1 == sig2 {
		t.Error("different inputs should produce different signatures")
	}
}

func TestCalculateHMAC_EmptyComponents(t *testing.T) {
	secret := []byte("test-secret")

	signature, err := CalculateHMAC(secret, AlgorithmSHA256)
	if err != nil {
		t.Fatalf("CalculateHMAC failed: %v", err)
	}

	if signature == "" {
		t.Error("signature should not be empty even with empty components")
	}
}
