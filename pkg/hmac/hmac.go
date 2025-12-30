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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
)

// Algorithm represents the HMAC algorithm to use
type Algorithm string

const (
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

// CalculateHMAC calculates an HMAC signature over the given components.
// Components are joined with newlines in the order provided.
// The resulting HMAC is returned as a hexadecimal string.
func CalculateHMAC(secret []byte, algorithm Algorithm, components ...string) (string, error) {
	var hashFunc func() hash.Hash
	switch algorithm {
	case AlgorithmSHA256:
		hashFunc = sha256.New
	case AlgorithmSHA512:
		hashFunc = sha512.New
	default:
		return "", fmt.Errorf("unsupported HMAC algorithm: %s", algorithm)
	}

	mac := hmac.New(hashFunc, secret)
	for i, component := range components {
		if i > 0 {
			mac.Write([]byte("\n"))
		}
		mac.Write([]byte(component))
	}

	signature := mac.Sum(nil)
	return hex.EncodeToString(signature), nil
}
