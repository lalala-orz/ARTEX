package traffic

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestValidateProxyURL(t *testing.T) {
	ok := []string{
		"http://127.0.0.1:8080",
		"https://proxy.example.com:3128",
		"socks5://10.0.0.1:1080",
		"socks5://user:pass@10.0.0.1:1080",
	}
	for _, raw := range ok {
		if _, err := ValidateProxyURL(raw); err != nil {
			t.Errorf("ValidateProxyURL(%q) unexpected error: %v", raw, err)
		}
	}
	bad := []string{
		"127.0.0.1:8080",         // no scheme
		"ftp://host:21",          // unsupported scheme
		"http://",                // no host
		"socks4://10.0.0.1:1080", // unsupported scheme
	}
	for _, raw := range bad {
		if _, err := ValidateProxyURL(raw); err == nil {
			t.Errorf("ValidateProxyURL(%q) expected error, got nil", raw)
		}
	}
}

func TestSetUpstreamProxyStoreClear(t *testing.T) {
	tr := &Traffic{dir: t.TempDir()}
	if got := tr.upstreamURL(); got != nil {
		t.Fatalf("initial upstream = %v, want nil", got)
	}
	if err := tr.SetUpstreamProxy("socks5://user:pass@10.0.0.1:1080"); err != nil {
		t.Fatalf("SetUpstreamProxy: %v", err)
	}
	u := tr.upstreamURL()
	if u == nil || u.Scheme != "socks5" || u.Host != "10.0.0.1:1080" {
		t.Fatalf("stored upstream = %v, want socks5://10.0.0.1:1080", u)
	}
	if pw, _ := u.User.Password(); u.User.Username() != "user" || pw != "pass" {
		t.Fatalf("stored upstream lost credentials: %v", u)
	}
	// Empty clears back to direct.
	if err := tr.SetUpstreamProxy("  "); err != nil {
		t.Fatalf("SetUpstreamProxy(clear): %v", err)
	}
	if got := tr.upstreamURL(); got != nil {
		t.Fatalf("after clear upstream = %v, want nil", got)
	}
	// Invalid value is rejected and does not mutate current state.
	if err := tr.SetUpstreamProxy("nope://x"); err == nil {
		t.Fatal("SetUpstreamProxy(invalid) expected error")
	}
	if got := tr.upstreamURL(); got != nil {
		t.Fatalf("invalid set mutated upstream to %v, want nil", got)
	}
}

// labelDialer is an egress that only names itself.
type labelDialer struct{ label string }

func (d labelDialer) Describe() string { return d.label }

func (d labelDialer) Dial(context.Context, string) (net.Conn, error) {
	return nil, errors.New("labelDialer")
}

// TestEgressIsPerIdentity pins the property the per-task egress design rests on:
// re-pointing one identity must never move another's. (The design moved from one
// egress per listener to one per identity; this is that property.)
func TestEgressIsPerIdentity(t *testing.T) {
	tr := &Traffic{}
	tr.SetIdentityEgress("task1", "tok1", 1, labelDialer{label: "tunnel-1"})
	tr.SetIdentityEgress("task2", "tok2", 2, labelDialer{label: "tunnel-2"})
	if got := tr.IdentityEgressLabel("task1"); got != "tunnel-1" {
		t.Errorf("task1 egress = %q，want tunnel-1", got)
	}
	if got := tr.IdentityEgressLabel("task2"); got != "tunnel-2" {
		t.Errorf("task2 egress = %q，want tunnel-2", got)
	}
	// Rebinding the first identity to nothing must leave the second alone.
	tr.SetIdentityEgress("task1", "tok1", 1, nil)
	if got := tr.IdentityEgressLabel("task1"); got != "" {
		t.Errorf("after rebinding task1 egress = %q，want empty", got)
	}
	if got := tr.IdentityEgressLabel("task2"); got != "tunnel-2" {
		t.Errorf("task2 egress moved to %q", got)
	}
}

func TestProxyAddr(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		// Bare :port means "bind all interfaces" — the legacy default. The URL
		// agents consume must still point at loopback so they reach the local proxy.
		{":8788", "http://127.0.0.1:8788"},
		// Explicit loopback — the current default since #129 (open proxy exposure).
		{"127.0.0.1:8788", "http://127.0.0.1:8788"},
		// Explicit all-interface bind is still supported (remote capture via SSH).
		{"0.0.0.0:8788", "http://0.0.0.0:8788"},
	}
	for _, c := range cases {
		if got := (&Traffic{addr: c.addr}).ProxyAddr(); got != c.want {
			t.Errorf("ProxyAddr(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}
