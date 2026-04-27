package httpx

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// IPResolver extracts the originating client IP from a request,
// honoring X-Forwarded-For only when the immediate peer (and any
// intermediate hops) fall within a configured set of trusted proxy
// ranges. Defaults to loopback only — clients connecting from anywhere
// else are taken at face value via RemoteAddr, ignoring forwarded
// headers.
type IPResolver struct {
	trusted []netip.Prefix
}

// NewIPResolver creates a resolver. If trusted is empty, only loopback
// (127.0.0.0/8 and ::1) is treated as trusted.
func NewIPResolver(trusted []netip.Prefix) *IPResolver {
	if len(trusted) == 0 {
		trusted = []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		}
	}
	return &IPResolver{trusted: trusted}
}

// ClientIP returns the originating client IP for r. If the request's
// immediate peer is a trusted proxy, X-Forwarded-For is walked
// right-to-left and the first untrusted address is returned. Otherwise
// RemoteAddr is used.
func (ir *IPResolver) ClientIP(r *http.Request) string {
	peer := remoteHost(r)
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil || !ir.isTrusted(peerAddr) {
		return peer
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(parts[i])
		addr, err := netip.ParseAddr(hop)
		if err != nil {
			continue
		}
		if !ir.isTrusted(addr) {
			return addr.String()
		}
	}
	return peer
}

func (ir *IPResolver) isTrusted(addr netip.Addr) bool {
	for _, p := range ir.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
