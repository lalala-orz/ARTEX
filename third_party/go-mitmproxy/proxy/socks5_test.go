package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
	log "github.com/sirupsen/logrus"
)

// socks5Hello writes the greeting and returns the chosen method byte.
func socks5Hello(t *testing.T, c net.Conn, methods ...byte) byte {
	t.Helper()
	if _, err := c.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if resp[0] != 0x05 {
		t.Fatalf("reply version 0x%02x", resp[0])
	}
	return resp[1]
}

// socks5Connect sends a CONNECT for host:port (ATYP=domain when non-IP) and
// returns the reply code.
func socks5Connect(t *testing.T, c net.Conn, host string, port int) byte {
	t.Helper()
	var b []byte
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		b = append([]byte{0x05, 0x01, 0x00, 0x01}, ip.To4()...)
	} else {
		b = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	b = append(b, pb[:]...)
	if _, err := c.Write(b); err != nil {
		t.Fatalf("connect: %v", err)
	}
	var rep [4]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if rep[0] != 0x05 {
		t.Fatalf("connect reply version 0x%02x", rep[0])
	}
	// drain the bound address
	if rep[3] == 0x01 {
		io.ReadFull(c, make([]byte, 6))
	} else if rep[3] == 0x03 {
		var l [1]byte
		io.ReadFull(c, l[:])
		io.ReadFull(c, make([]byte, int(l[0])+2))
	}
	return rep[1]
}

// echoAddon implements Addon with only Requestheaders: it answers every
// request with an X-Proxy-Saw echo of method + absolute URL, so the test can
// prove the decrypted request arrived at the recording pipeline.
type echoAddon struct{ BaseAddon }

func (a *echoAddon) Requestheaders(f *Flow) {
	log.Debugf("ECHO ADDON FIRED: %s %s", f.Request.Method, f.Request.URL)
	if f.Request == nil || f.Request.URL == nil {
		return
	}
	f.Response = &Response{
		StatusCode: 200,
		Header:     http.Header{"X-Proxy-Saw": []string{f.Request.Method + " " + f.Request.URL.String()}},
	}
}

func newSocksProxy(t *testing.T, auth func(string, string) (string, bool), meta func(Socks5RawMeta)) (*Proxy, string) {
	t.Helper()
	log.SetLevel(log.DebugLevel)
	// Pick a free port up front: proxy.Start() listens on Options.Addr itself
	// and its listener is internal, so the test needs to know the port in
	// advance to dial it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	p, err := NewProxy(&Options{
		Addr:          addr,
		SslInsecure:   true,
		Authenticate:  auth,
		Socks5RawMeta: meta,
		NewCaFunc:     func() (cert.CA, error) { return cert.NewSelfSignCAMemory() },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	go func() { _ = p.Start() }()
	time.Sleep(100 * time.Millisecond)
	return p, addr
}

// httpSrvStub is unused helper kept for non-SOCKS5 fallbacks in future tests.
func httpSrvStub(c net.Conn) {
	srv := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	})}
	_ = srv.Serve(&singleConnListener{conn: c})
}

type singleConnListener struct {
	conn   net.Conn
	given  bool
	closed bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.given || l.closed {
		<-make(chan struct{}) // block forever (Close below unblocks Serve)
	}
	l.given = true
	return l.conn, nil
}
func (l *singleConnListener) Close() error   { l.closed = true; return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// TestSocks5Handshake covers T1: no-auth, user/pass (accept + reject), command
// rejection and bad version.
func TestSocks5Handshake(t *testing.T) {
	_, addr := newSocksProxy(t, func(u, p2 string) (string, bool) { return u, u == "u" && p2 == "p" }, nil)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if m := socks5Hello(t, c, 0x00, 0x02); m != socks5MethodUserPass {
		t.Fatalf("auth-required server chose method 0x%02x, want 0x02", m)
	}
	// wrong password
	_, _ = c.Write([]byte{0x01, 1, 'u', 1, 'x'})
	var ar [2]byte
	if _, err := io.ReadFull(c, ar[:]); err != nil {
		t.Fatal(err)
	}
	if ar[1] != 0x01 {
		t.Fatalf("wrong password accepted (status 0x%02x)", ar[1])
	}
	c.Close()

	// On the auth-required server a client offering nothing acceptable
	// (GSSAPI only) must get 0xff NO ACCEPTABLE METHODS.
	c2, _ := net.Dial("tcp", addr)
	defer c2.Close()
	if m := socks5Hello(t, c2, 0x01); m != socks5MethodUnaccept {
		t.Fatalf("GSSAPI-only client must be refused, got 0x%02x", m)
	}
	c2.Close()

	// no-auth server accepts a no-auth client
	p2, addr2 := newSocksProxy(t, nil, nil)
	_ = p2
	c3, _ := net.Dial("tcp", addr2)
	defer c3.Close()
	if m := socks5Hello(t, c3, 0x00); m != socks5MethodNoAuth {
		t.Fatalf("no-auth server chose 0x%02x", m)
	}
	// unsupported command (BIND=2)
	if rep := socks5ConnectWithCmd(t, c3, 0x02, "127.0.0.1", 80); rep != socks5RepCmdNotSupp {
		t.Fatalf("BIND reply 0x%02x, want 0x07", rep)
	}
}

func socks5ConnectWithCmd(t *testing.T, c net.Conn, cmd byte, host string, port int) byte {
	t.Helper()
	b := append([]byte{0x05, cmd, 0x00, 0x03, byte(len(host))}, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	b = append(b, pb[:]...)
	c.Write(b)
	var rep [4]byte
	io.ReadFull(c, rep[:])
	return rep[1]
}

// TestSocks5BadVersion covers a client whose first byte is 0x05 but which then
// sends garbage: the server must just drop it (no panic, no reply loop).
func TestSocks5BadVersion(t *testing.T) {
	_, addr := newSocksProxy(t, nil, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{0x05, 0x00}) // nmethods=0, then nothing
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("garbage client must not get a reply")
	}
}

// TestSocks5RawRelay covers T3: a non-TLS CONNECT is relayed both ways and the
// raw-connection metadata reports target, byte counts and via_upstream.
func TestSocks5RawRelay(t *testing.T) {
	payload := "IM-FAKE-MYSQL-HANDSHAKE"
	dst := startEchoServer(t, payload)

	var got Socks5RawMeta
	ready := make(chan struct{})
	_, addr := newSocksProxy(t, nil, func(m Socks5RawMeta) {
		got = m
		close(ready)
	})

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if m := socks5Hello(t, c, 0x00); m != 0 {
		t.Fatalf("method 0x%02x", m)
	}
	h, po, _ := net.SplitHostPort(dst)
	port, _ := net.LookupPort("tcp", po)
	if rep := socks5Connect(t, c, h, port); rep != socks5RepOK {
		t.Fatalf("CONNECT reply 0x%02x", rep)
	}
	// client -> target: the echo server sends payload first; read it back.
	buf := make([]byte, len(payload))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("echo mismatch: %q", buf)
	}
	// client -> target bytes
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, 4)); err != nil {
		t.Fatalf("read echo2: %v", err)
	}
	c.Close()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("no raw metadata reported")
	}
	if got.Host != h || got.Port != port {
		t.Fatalf("meta target = %s:%d, want %s:%d", got.Host, got.Port, h, port)
	}
	if got.BytesDown < int64(len(payload)) || got.BytesUp < 4 {
		t.Fatalf("byte counts: %+v", got)
	}
	if got.ViaUpstream {
		t.Fatal("no upstream configured, via_upstream must be false")
	}
}

// TestSocks5TLSMITM covers T2: a TLS CONNECT through the SOCKS5 ingress is
// MITM'd with the shared CA and the decrypted HTTP request reaches the same
// attacker pipeline an HTTP CONNECT uses (Requestheaders flow hook 鈥?the hook
// the traffic recorder's sink implements).
func TestSocks5TLSMITM(t *testing.T) {
	// A target whose TLS cert is valid for "mitm-socks5.test" 鈥?the MITM'd
	// client talks TLS with SNI mitm-socks5.test, and the attacker pipeline's
	// own TLS to the target verifies against this CA.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cert := makeSelfSignedCert(t)
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	const body = "socks5-mitm-body"
	go http.Serve(tlsLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	host, portS, _ := net.SplitHostPort(ln.Addr().String())
	_ = host
	port, _ := net.LookupPort("tcp", portS)

	p, addr := newSocksProxy(t, nil, nil)
	// The real attacker ServeHTTP is kept 鈥?it is what fills the ConnContext.
	// An addon adds the X-Proxy-Saw echo, proving the decrypted request made it
	// through the whole pipeline (CA cert for the client, attacker server).
	p.AddAddon(&echoAddon{})

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if m := socks5Hello(t, c, 0x00); m != 0 {
		t.Fatalf("method 0x%02x", m)
	}
	if rep := socks5Connect(t, c, "localhost", port); rep != socks5RepOK {
		t.Fatalf("CONNECT reply 0x%02x", rep)
	}
	// TLS handshake against the MITM: with InsecureSkipVerify off this only
	// succeeds if the served cert chains to the proxy's CA (i.e. the SOCKS5
	// CONNECT path really did the MITM, not a transparent passthrough).
	roots := x509.NewCertPool()
	roots.AddCert(p.attacker.ca.GetRootCA())
	tc := tls.Client(c, &tls.Config{ServerName: "localhost", RootCAs: roots, NextProtos: []string{"http/1.1"}})
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client TLS handshake against MITM cert: %v", err)
	}
	// The client's decrypted request must reach the attacker pipeline intact:
	// its handler echoes method+URL back in X-Proxy-Saw, proving the flow went
	// through the full MITM path (dynamically signed cert for the client, and
	// the attacker server actually serving the connection).
	req, _ := http.NewRequest("GET", "https://localhost:"+portS+"/probe-path", nil)
	req.Header.Set("X-Probe", "1")
	req.Host = "localhost:" + portS
	if err := req.Write(tc); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v (attacker handler echo expected)", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("X-Proxy-Saw") != "GET https://localhost:"+portS+"/probe-path" {
		t.Fatalf("attacker pipeline saw %q, want GET https://localhost:%s/probe-path (resp=%q)",
			resp.Header.Get("X-Proxy-Saw"), portS, respBody)
	}
}

// startForwardSocks5 is a minimal SOCKS5 egress: no-auth CONNECT that dials
// whatever the client asks for.
func startForwardSocks5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var hdr [2]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				io.ReadFull(c, make([]byte, int(hdr[1])))
				c.Write([]byte{0x05, 0x00})
				var ch [4]byte
				if _, err := io.ReadFull(c, ch[:]); err != nil {
					return
				}
				var host string
				switch ch[3] {
				case 0x01:
					ip := make([]byte, 4)
					io.ReadFull(c, ip)
					host = net.IP(ip).String()
				case 0x03:
					var l [1]byte
					io.ReadFull(c, l[:])
					d := make([]byte, l[0])
					io.ReadFull(c, d)
					host = string(d)
				default:
					return
				}
				var pb [2]byte
				io.ReadFull(c, pb[:])
				port := int(binary.BigEndian.Uint16(pb[:]))
				dst, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
				if err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				go io.Copy(dst, c)
				io.Copy(c, dst)
				dst.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

// makeSelfSignedCert generates a throwaway self-signed cert for "localhost"
// with the stdlib: the target in the MITM test presents it, so the attacker
// pipeline's own TLS verifies cleanly against the returned pool.
func makeSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ktlv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(ktlv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// startEchoServer echoes everything it receives after an initial banner.
func startEchoServer(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.WriteString(c, banner)
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// recordAddon records the requests/responses that reach the attacker pipeline
// (the same hooks the traffic recorder's sink implements) without short-circuiting
// them, so the upstream response must still make the round trip.
type recordAddon struct {
	BaseAddon
	mu       sync.Mutex
	requests []string
	statuses []int
}

func (a *recordAddon) Requestheaders(f *Flow) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if f.Request != nil && f.Request.URL != nil {
		a.requests = append(a.requests, f.Request.Method+" "+f.Request.URL.String())
	}
}

func (a *recordAddon) Response(f *Flow) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if f.Response != nil {
		a.statuses = append(a.statuses, f.Response.StatusCode)
	}
}

func (a *recordAddon) snapshot() ([]string, []int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.requests...), append([]int(nil), a.statuses...)
}

// TestSocks5PlainHTTPMITM: plaintext HTTP over SOCKS5 must ride the MITM
// pipeline (full request/response recording) instead of the raw relay that only
// reports byte counts — that is the difference between "an internal page was
// fetched" and "127.0.0.1:80 down=35748".
func TestSocks5PlainHTTPMITM(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const body = "socks5-plain-http-body"
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		fmt.Fprint(w, body)
	}))
	_, portS, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := net.LookupPort("tcp", portS)

	// A raw relay here would be the bug: the addon must see the request instead.
	p, addr := newSocksProxy(t, nil, func(m Socks5RawMeta) {
		t.Errorf("plain HTTP went to the raw relay: %s", m)
	})
	rec := &recordAddon{}
	p.AddAddon(rec)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if m := socks5Hello(t, c, 0x00); m != 0 {
		t.Fatalf("method 0x%02x", m)
	}
	if rep := socks5Connect(t, c, "127.0.0.1", port); rep != socks5RepOK {
		t.Fatalf("CONNECT reply 0x%02x", rep)
	}

	// Origin-form, exactly what a client sends after SOCKS5 supplied the target.
	// Two requests prove keep-alive survives the response writer's framing.
	br := bufio.NewReader(c)
	for i := 0; i < 2; i++ {
		if _, err := fmt.Fprintf(c, "GET /probe-path HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nX-Probe: %d\r\n\r\n", portS, i); err != nil {
			t.Fatal(err)
		}
		want := "http://127.0.0.1:" + portS + "/probe-path"
		req, _ := http.NewRequest("GET", want, nil)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("request %d: read response: %v", i, err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(got) != body || resp.Header.Get("X-Upstream") != "yes" {
			t.Fatalf("request %d: upstream response mangled: status=%d body=%q", i, resp.StatusCode, got)
		}
	}

	requests, statuses := rec.snapshot()
	if len(requests) != 2 || len(statuses) != 2 {
		t.Fatalf("pipeline saw %d requests / %d responses, want 2/2 (%v)", len(requests), len(statuses), requests)
	}
	wantAbs := "GET http://127.0.0.1:" + portS + "/probe-path"
	if requests[0] != wantAbs {
		t.Fatalf("pipeline saw %q, want %q (absolute URL proves the proxy-style rewrite)", requests[0], wantAbs)
	}
}
