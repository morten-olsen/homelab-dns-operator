//go:build e2e

package e2e

import (
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"

	. "github.com/onsi/gomega"

	"github.com/mortenolsen/dns-operator/pkg/dnsclient"
	"github.com/mortenolsen/dns-operator/pkg/hmac"
)

// kindMockDNSServer forwards pod requests to the existing in-process mock.
// Only the disposable Kind Docker bridge listens; no homelab endpoint is exposed.
// Keeping this adapter here leaves the application's mock/client API unchanged.
type kindMockDNSServer struct {
	*dnsclient.MockDNSServer
	proxy *httptest.Server
}

func newKindMockDNSServer(secret []byte, algorithm hmac.Algorithm) *kindMockDNSServer {
	mock := dnsclient.NewMockDNSServer(secret, algorithm)
	target, err := url.Parse(mock.URL())
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	listener, err := net.Listen("tcp4", net.JoinHostPort(kindGateway, "0"))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	proxy := httptest.NewUnstartedServer(httputil.NewSingleHostReverseProxy(target))
	_ = proxy.Listener.Close()
	proxy.Listener = listener
	proxy.Start()
	return &kindMockDNSServer{MockDNSServer: mock, proxy: proxy}
}

func (m *kindMockDNSServer) URL() string { return m.proxy.URL }

func (m *kindMockDNSServer) Close() {
	m.proxy.Close()
	m.MockDNSServer.Close()
}
