package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
)

// echoOnce accepts one connection, writes payload and closes it.
func echoOnce(t *testing.T, payload string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte(payload))
	}()
	return ln
}

func newTestReq(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// An injected dialer owns the egress: the URL upstream must not be consulted, the
// connection must come from the dialer, and it must be reported as an upstream hop.
func TestDialUpstreamPrefersDialer(t *testing.T) {
	ln := echoOnce(t, "hello")
	defer ln.Close()

	p := &Proxy{Opts: &Options{}}
	urlConsulted := false
	p.SetUpstreamProxy(func(*http.Request) (*url.URL, error) {
		urlConsulted = true
		return url.Parse("socks5://127.0.0.1:1")
	})

	var gotAddress, gotNetwork string
	p.SetUpstreamDialer(func(ctx context.Context, req *http.Request, network, address string) (net.Conn, error) {
		gotAddress, gotNetwork = address, network
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}, "test-tunnel")

	req := newTestReq(t, "http://"+ln.Addr().String()+"/")
	conn, viaUpstream, err := p.dialUpstream(context.Background(), req, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if urlConsulted {
		t.Error("URL upstream was consulted even though a dialer is installed")
	}
	if gotAddress != ln.Addr().String() || gotNetwork != "tcp" {
		t.Errorf("dialer called with (%q, %q), want (%q, \"tcp\")", gotNetwork, gotAddress, ln.Addr().String())
	}
	if !viaUpstream {
		t.Error("viaUpstream must be true so the connection is not recorded as a direct dial")
	}
	buf := make([]byte, len("hello"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Errorf("got %q, want %q", buf, "hello")
	}
}

// Without a dialer the egress falls back to a direct dial, reported as such.
func TestDialUpstreamDirectWithoutDialer(t *testing.T) {
	ln := echoOnce(t, "direct")
	defer ln.Close()

	p := &Proxy{Opts: &Options{}}
	req := newTestReq(t, "http://"+ln.Addr().String()+"/")
	conn, viaUpstream, err := p.dialUpstream(context.Background(), req, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if viaUpstream {
		t.Error("viaUpstream must be false for a direct dial")
	}
	buf := make([]byte, len("direct"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "direct" {
		t.Errorf("got %q, want %q", buf, "direct")
	}
}

// The shared attacker client expresses its egress as Transport.Proxy. That answer
// must become nil once a dialer is installed, otherwise net/http would CONNECT to
// the URL upstream on top of the dialer.
func TestRealUpstreamProxyYieldsToDialer(t *testing.T) {
	p := &Proxy{Opts: &Options{}}
	req := newTestReq(t, "http://example.com/")
	cReq := req.WithContext(context.WithValue(req.Context(), proxyReqCtxKey, req))

	want, _ := url.Parse("http://127.0.0.1:8080")
	p.SetUpstreamProxy(func(*http.Request) (*url.URL, error) { return want, nil })

	got, err := p.realUpstreamProxy()(cReq)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.String() != want.String() {
		t.Errorf("without a dialer got %v, want %v", got, want)
	}

	p.SetUpstreamDialer(func(context.Context, *http.Request, string, string) (net.Conn, error) {
		return nil, nil
	}, "test-tunnel")
	got, err = p.realUpstreamProxy()(cReq)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("with a dialer got %v, want nil", got)
	}
}

// The egress label is resolved per connection: it names the dialer when one is
// installed, the URL upstream without credentials otherwise, and "" for direct.
// Options.EgressLabel wins when it answers, because a dialer that routes per client
// knows the real egress only after looking the connection up.
func TestEgressLabel(t *testing.T) {
	p := &Proxy{Opts: &Options{}}
	req := newTestReq(t, "http://example.com/")

	if got := p.egressLabel(context.Background(), req); got != "" {
		t.Errorf("direct dial label = %q, want empty", got)
	}

	p.SetUpstreamProxy(func(*http.Request) (*url.URL, error) {
		return url.Parse("socks5://user:secret@127.0.0.1:1080")
	})
	if got, want := p.egressLabel(context.Background(), req), "socks5://127.0.0.1:1080"; got != want {
		t.Errorf("URL upstream label = %q, want %q (credentials must not appear)", got, want)
	}

	p.SetUpstreamDialer(func(context.Context, *http.Request, string, string) (net.Conn, error) {
		return nil, nil
	}, "suo5:http://10.1.1.5/x.php")
	if got, want := p.egressLabel(context.Background(), req), "suo5:http://10.1.1.5/x.php"; got != want {
		t.Errorf("dialer label = %q, want %q", got, want)
	}

	p.Opts.EgressLabel = func(context.Context, *http.Request) string { return "per-client" }
	if got, want := p.egressLabel(context.Background(), req), "per-client"; got != want {
		t.Errorf("Options.EgressLabel did not win: got %q, want %q", got, want)
	}
}

// The identity the ingress authenticated rides into the dialer, which is what lets
// one listener pick an egress per client.
func TestDialUpstreamCarriesIdentity(t *testing.T) {
	ln := echoOnce(t, "id")
	defer ln.Close()

	p := &Proxy{Opts: &Options{}}
	req := newTestReq(t, "http://"+ln.Addr().String()+"/")
	req = req.WithContext(context.WithValue(context.Background(), connContextKey, &ConnContext{Identity: "task7"}))

	var got string
	p.SetUpstreamDialer(func(ctx context.Context, r *http.Request, network, address string) (net.Conn, error) {
		got = IdentityFromContext(ctx)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}, "router")

	if _, _, err := p.dialUpstream(context.Background(), req, ln.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if got != "task7" {
		t.Fatalf("dialer saw identity %q, want %q", got, "task7")
	}
}

// A dialer that does not serve a connection hands it back to the upstream path
// instead of failing it: that is how a per-client egress coexists with a
// listener-wide upstream.
func TestDialUpstreamFallsThroughUnhandledEgress(t *testing.T) {
	ln := echoOnce(t, "fallback")
	defer ln.Close()

	p := &Proxy{Opts: &Options{}}
	p.SetUpstreamDialer(func(context.Context, *http.Request, string, string) (net.Conn, error) {
		return nil, ErrEgressNotHandled
	}, "router")

	req := newTestReq(t, "http://"+ln.Addr().String()+"/")
	conn, viaUpstream, err := p.dialUpstream(context.Background(), req, ln.Addr().String())
	if err != nil {
		t.Fatalf("an unhandled egress must fall through to a direct dial: %v", err)
	}
	defer conn.Close()
	if viaUpstream {
		t.Error("the fallback was a direct dial, so viaUpstream must be false")
	}
	buf := make([]byte, len("fallback"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "fallback" {
		t.Errorf("got %q, want %q", buf, "fallback")
	}
}

// Any other dialer error refuses the connection instead of being retried as a
// direct dial, which would send the traffic from this host's own address.
func TestDialUpstreamRefusalIsNotSwallowed(t *testing.T) {
	refuse := errors.New("no egress for this task")
	p := &Proxy{Opts: &Options{}}
	p.SetUpstreamDialer(func(context.Context, *http.Request, string, string) (net.Conn, error) {
		return nil, refuse
	}, "router")

	req := newTestReq(t, "http://example.com/")
	if _, _, err := p.dialUpstream(context.Background(), req, "example.com:80"); !errors.Is(err, refuse) {
		t.Fatalf("dialUpstream error = %v, want %v", err, refuse)
	}
}

func TestProxyBasicAuth(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		header, user, pass string
	}{
		{"", "", ""},
		{"Basic " + b64("task7:tok"), "task7", "tok"},
		{"basic " + b64("task7:tok"), "task7", "tok"}, // scheme is case-insensitive
		{"Basic " + b64("nopass:"), "nopass", ""},
		{"Basic " + b64("has:two:colons"), "has", "two:colons"},
		{"Bearer xyz", "", ""},
		{"Basic !!!not-base64", "", ""},
	}
	for _, c := range cases {
		req := newTestReq(t, "http://example.com/")
		if c.header != "" {
			req.Header.Set("Proxy-Authorization", c.header)
		}
		user, pass := proxyBasicAuth(req)
		if user != c.user || pass != c.pass {
			t.Errorf("proxyBasicAuth(%q) = (%q, %q), want (%q, %q)", c.header, user, pass, c.user, c.pass)
		}
	}
}
