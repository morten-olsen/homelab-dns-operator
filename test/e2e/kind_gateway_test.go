//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
)

// Docker can list IPv6 first even though Kind's default pod network is IPv4.
func selectKindIPv4Gateway(raw string) (string, error) {
	var configs []struct{ Gateway string }
	if err := json.Unmarshal([]byte(raw), &configs); err != nil {
		return "", fmt.Errorf("decode Kind Docker network IPAM: %w", err)
	}
	for _, config := range configs {
		if ip := net.ParseIP(config.Gateway); ip != nil && ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("Kind Docker network has no IPv4 gateway")
}

func TestKindIPv4Gateway(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"IPv6 first", `[{"Gateway":"fc00:f853:ccd:e793::1"},{"Gateway":"172.18.0.1"}]`, "172.18.0.1"},
		{"IPv4 first", `[{"Gateway":"172.19.0.1"},{"Gateway":"fc00:f853:ccd:e793::1"}]`, "172.19.0.1"},
		{"no IPv4", `[{"Gateway":"fc00:f853:ccd:e793::1"}]`, ""},
		{"missing gateway", `[{"Subnet":"172.18.0.0/16"}]`, ""},
		{"malformed", `not-json`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectKindIPv4Gateway(tc.raw)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("gateway = %q, err = %v; want %q", got, err, tc.want)
			}
		})
	}
}
