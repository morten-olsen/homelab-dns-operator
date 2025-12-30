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

package secret

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dnsv1alpha1 "github.com/mortenolsen/dns-operator/api/v1alpha1"
	"github.com/mortenolsen/dns-operator/pkg/hmac"
)

// GetHMACSecret retrieves the HMAC secret from either a Kubernetes Secret or direct value
func GetHMACSecret(ctx context.Context, k8sClient client.Client, hmacAuth *dnsv1alpha1.HMACAuth) ([]byte, hmac.Algorithm, error) {
	if hmacAuth == nil {
		return nil, "", nil
	}

	algorithm := hmac.AlgorithmSHA256
	if hmacAuth.Algorithm != "" {
		algorithm = hmac.Algorithm(hmacAuth.Algorithm)
	}

	// Check for direct secret value (for testing)
	if hmacAuth.Secret != nil {
		return []byte(*hmacAuth.Secret), algorithm, nil
	}

	// Check for secret reference
	if hmacAuth.SecretRef == nil {
		return nil, "", fmt.Errorf("hmacAuth must have either secretRef or secret")
	}

	secretRef := hmacAuth.SecretRef
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Namespace: secretRef.Namespace,
		Name:      secretRef.Name,
	}

	if err := k8sClient.Get(ctx, secretKey, secret); err != nil {
		return nil, "", fmt.Errorf("failed to get secret %s/%s: %w", secretRef.Namespace, secretRef.Name, err)
	}

	secretValue, exists := secret.Data[secretRef.Key]
	if !exists {
		return nil, "", fmt.Errorf("key %s not found in secret %s/%s", secretRef.Key, secretRef.Namespace, secretRef.Name)
	}

	return secretValue, algorithm, nil
}
