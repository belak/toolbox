package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/belak/toolbox/httpx"
)

func newReq(remoteAddr, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientIP_DefaultLoopbackTrust(t *testing.T) {
	t.Parallel()
	resolver := httpx.NewIPResolver(nil)

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "loopback peer trusts XFF",
			remoteAddr: "127.0.0.1:54321",
			xff:        "203.0.113.5",
			want:       "203.0.113.5",
		},
		{
			name:       "ipv6 loopback peer trusts XFF",
			remoteAddr: "[::1]:54321",
			xff:        "203.0.113.5",
			want:       "203.0.113.5",
		},
		{
			name:       "private peer NOT trusted by default",
			remoteAddr: "10.0.0.5:54321",
			xff:        "203.0.113.5",
			want:       "10.0.0.5",
		},
		{
			name:       "public peer ignored XFF",
			remoteAddr: "198.51.100.7:443",
			xff:        "203.0.113.5",
			want:       "198.51.100.7",
		},
		{
			name:       "no XFF returns peer",
			remoteAddr: "127.0.0.1:54321",
			xff:        "",
			want:       "127.0.0.1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolver.ClientIP(newReq(tc.remoteAddr, tc.xff))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestClientIP_CustomTrustedProxies(t *testing.T) {
	t.Parallel()
	resolver := httpx.NewIPResolver([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
	})

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "single trusted hop returns client",
			remoteAddr: "10.1.2.3:443",
			xff:        "203.0.113.5",
			want:       "203.0.113.5",
		},
		{
			name:       "chained trusted proxies skip to first untrusted",
			remoteAddr: "10.1.2.3:443",
			xff:        "203.0.113.5, 10.5.5.5, 10.6.6.6",
			want:       "203.0.113.5",
		},
		{
			name:       "untrusted hop in middle stops walk",
			remoteAddr: "10.1.2.3:443",
			xff:        "1.1.1.1, 203.0.113.5, 10.6.6.6",
			want:       "203.0.113.5",
		},
		{
			name:       "all trusted falls back to peer",
			remoteAddr: "10.1.2.3:443",
			xff:        "10.4.4.4, 10.5.5.5",
			want:       "10.1.2.3",
		},
		{
			name:       "untrusted peer ignores XFF entirely",
			remoteAddr: "8.8.8.8:443",
			xff:        "203.0.113.5",
			want:       "8.8.8.8",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolver.ClientIP(newReq(tc.remoteAddr, tc.xff))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestClientIP_MalformedInputs(t *testing.T) {
	t.Parallel()
	resolver := httpx.NewIPResolver(nil)

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "RemoteAddr without port returned verbatim",
			remoteAddr: "127.0.0.1",
			want:       "127.0.0.1",
		},
		{
			name:       "garbage RemoteAddr returned verbatim, XFF ignored",
			remoteAddr: "not-an-addr",
			xff:        "203.0.113.5",
			want:       "not-an-addr",
		},
		{
			name:       "garbage XFF entries are skipped",
			remoteAddr: "127.0.0.1:54321",
			xff:        "garbage, 203.0.113.5",
			want:       "203.0.113.5",
		},
		{
			name:       "all-garbage XFF falls back to peer",
			remoteAddr: "127.0.0.1:54321",
			xff:        "garbage, also-bad",
			want:       "127.0.0.1",
		},
		{
			name:       "ipv6 with brackets parses",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolver.ClientIP(newReq(tc.remoteAddr, tc.xff))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestClientIP_XFFWhitespaceTolerated(t *testing.T) {
	t.Parallel()
	resolver := httpx.NewIPResolver([]netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
	})
	got := resolver.ClientIP(newReq("127.0.0.1:54321", "  203.0.113.5  ,  10.0.0.1  "))
	assert.Equal(t, "203.0.113.5", got)
}
