package proxy

// SOCKS5 ingress sharing the HTTP proxy's listening port (ARTEX).
//
// Protocol detection happens per connection on the first client byte: 0x05 is
// RFC 1928 (no HTTP method starts with that byte) and is served here; anything
// else is handed to the HTTP proxy server as before. CONNECT targets are
// sniffed after the tunnel opens: a TLS ClientHello is MITM'd through the same
// attacker/CA/addon recording pipeline as an HTTP CONNECT; any other protocol
// is relayed as raw TCP with connection metadata reported via
// Options.Socks5RawMeta (byte counts only, never content).
//
// Not supported: BIND, UDP ASSOCIATE (reply 0x07 COMMAND_NOT_SUPPORTED) and
// GSSAPI (never offered).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	log "github.com/sirupsen/logrus"
)

const (
	socks5Version        = 0x05
	socks5MethodNoAuth   = 0x00
	socks5MethodUserPass = 0x02
	socks5MethodUnaccept = 0xff
	socks5CmdConnect     = 0x01
	socks5RepOK          = 0x00
	socks5RepGeneralFail = 0x01
	socks5RepHostUnreach = 0x04
	socks5RepCmdNotSupp  = 0x07
	socks5ATYPIPV4       = 0x01
	socks5ATYPDomain     = 0x03
	socks5ATYPIPV6       = 0x04
	// How long to wait for the client's first byte after CONNECT succeeds. TLS
	// clients send the ClientHello immediately, so well under a second covers
	// them; raw-TCP protocols (MySQL etc.) where the SERVER speaks first pay
	// this as first-byte latency — the cost of deciding MITM vs relay.
	// A transparent client sends its request immediately for HTTP, so this budget is
	// only paid by server-first protocols (MySQL, Redis…). Kept short on purpose.
	transparentSniffTimeout = 250 * time.Millisecond
	socks5SniffTimeout      = 1 * time.Second
	socks5UpstreamTimeout   = 15 * time.Second
	// Bytes peeked to recognise a plaintext HTTP request line (method + target +
	// HTTP/1.x); the sniff deadline still bounds how long that may take.
	socks5SniffProbe = 512
)

// Socks5RawMeta is one report per completed raw-TCP relay (non-TLS traffic the
// MITM layer cannot parse). Metadata only: no content is carried.
type Socks5RawMeta struct {
	Host        string // CONNECT target host (domain as sent, or IP literal)
	Port        int
	BytesUp     int64  // client -> target
	BytesDown   int64  // target -> client
	ViaUpstream bool   // relayed through the configured egress proxy (false = direct dial)
	Egress      string // what it left through, redacted ("" = direct dial)
	Identity    string // who the client authenticated as ("" = anonymous)
	// HeadUp/HeadDown hold the first Socks5CaptureBytes of each direction when
	// capture applied to this connection (nil otherwise). They are raw protocol
	// bytes: the caller decides what they are and whether to keep them.
	HeadUp   []byte
	HeadDown []byte
}

func (m Socks5RawMeta) String() string {
	return fmt.Sprintf("%s:%d up=%d down=%d via_upstream=%v egress=%q identity=%q",
		m.Host, m.Port, m.BytesUp, m.BytesDown, m.ViaUpstream, m.Egress, m.Identity)
}

// serveTransparent handles a connection the kernel redirected to the listener:
// nothing is spoken on the wire, the target and the caller were recovered from
// the socket. Everything past that point is the explicit-CONNECT path, so
// recording depth is identical (MITM for TLS and plaintext HTTP, relay plus
// metadata for anything else). Ownership matches serveSocks5: the MITM pipeline
// takes the conn over, every other path is closed here.
func (proxy *Proxy) serveTransparent(c *wrapClientConn, host string, port int) {

	closeIt := true
	defer func() {
		if closeIt {
			c.Close()
		}
	}()
	proxy.connectTarget(c, host, port, &closeIt, false, transparentSniffTimeout)
}

// transparentIdentity maps the peer's uid to an agent identity. The platform
// installs IdentityFromUID; without it the connection is anonymous.
func (proxy *Proxy) transparentIdentity(conn net.Conn) string {
	if proxy.Opts.IdentityFromUID == nil {
		return ""
	}
	uid := peerUID(conn)
	if uid <= 0 {
		return ""
	}
	return proxy.Opts.IdentityFromUID(uid)
}

// sniffSocks5 peeks the first client byte and reports whether the connection
// speaks SOCKS5. It blocks only the calling goroutine.
func sniffSocks5(c *wrapClientConn) bool {
	b, err := c.Peek(1)
	if err != nil || len(b) == 0 {
		return false
	}
	return b[0] == socks5Version
}

// serveSocks5 handles one connection detected as SOCKS5. The connection never
// reaches the HTTP server; c.connCtx exists already (created at Accept) and is
// reused so addon state stays consistent.
//
// Ownership: on the MITM path the attacker pipeline takes over the conn, so
// this function must NOT close it on return (it does for every other path).
func (proxy *Proxy) serveSocks5(c *wrapClientConn) {
	closeIt := true
	defer func() {
		if closeIt {
			c.Close()
		}
	}()

	br := bufio.NewReader(io.LimitReader(c.r, 4096))
	ver, err := br.ReadByte()
	if err != nil || ver != socks5Version {
		log.Debugf("[socks5] bad version byte 0x%02x", ver)
		return
	}
	nm, err := br.ReadByte()
	if err != nil || nm == 0 {
		return
	}
	methods := make([]byte, nm)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// GSSAPI is never accepted. user/pass is offered when configured; preference
	// order is user/pass (more specific) over no-auth. A client that answers with
	// no-auth is still served — Authenticate decides whether to refuse it, since
	// only the caller knows if credentials are mandatory.
	useAuth := proxy.Opts.Authenticate != nil
	accept := byte(socks5MethodUnaccept)
	for _, m := range methods {
		if m == socks5MethodNoAuth {
			accept = socks5MethodNoAuth
		}
		if m == socks5MethodUserPass && useAuth {
			accept = socks5MethodUserPass
			break
		}
	}
	if _, err := c.Write([]byte{socks5Version, accept}); err != nil {
		return
	}
	if accept == socks5MethodUnaccept {
		return
	}
	if accept == socks5MethodUserPass {
		user, pass, err := socks5UserPass(br)
		if err != nil {
			return
		}
		identity, ok := proxy.Opts.Authenticate(user, pass)
		if !ok {
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		c.connCtx.Identity = identity
		_, _ = c.Write([]byte{0x01, 0x00})
	}

	host, port, rep := socks5ReadConnect(br)
	if rep != socks5RepOK {
		socks5Reply(c, rep)
		return
	}
	proxy.socks5Connect(c, host, port, &closeIt)
}

// socks5UserPass reads the RFC 1929 username/password subnegotiation.
func socks5UserPass(br *bufio.Reader) (user, pass string, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return "", "", err
	}
	if hdr[0] != 0x01 {
		return "", "", fmt.Errorf("socks5 auth version 0x%02x", hdr[0])
	}
	ub := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, ub); err != nil {
		return "", "", err
	}
	var pb [1]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return "", "", err
	}
	pp := make([]byte, pb[0])
	if _, err := io.ReadFull(br, pp); err != nil {
		return "", "", err
	}
	return string(ub), string(pp), nil
}

// socks5ReadConnect parses the CONNECT request. Only command 0x01 is supported.
func socks5ReadConnect(br *bufio.Reader) (host string, port int, rep byte) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return "", 0, socks5RepGeneralFail
	}
	if hdr[1] != socks5CmdConnect {
		return "", 0, socks5RepCmdNotSupp
	}
	switch hdr[3] {
	case socks5ATYPIPV4:
		var ip [4]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", 0, socks5RepGeneralFail
		}
		host = net.IP(ip[:]).String()
	case socks5ATYPDomain:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return "", 0, socks5RepGeneralFail
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(br, d); err != nil {
			return "", 0, socks5RepGeneralFail
		}
		host = string(d)
	case socks5ATYPIPV6:
		var ip [16]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", 0, socks5RepGeneralFail
		}
		host = net.IP(ip[:]).String()
	default:
		return "", 0, socks5RepGeneralFail
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return "", 0, socks5RepGeneralFail
	}
	return host, int(binary.BigEndian.Uint16(pb[:])), socks5RepOK
}

func socks5Reply(c net.Conn, rep byte) {
	_, _ = c.Write([]byte{socks5Version, rep, 0x00, socks5ATYPIPV4, 0, 0, 0, 0, 0, 0})
}

func socks5Fail(c net.Conn, err error) {
	socks5Reply(c, socks5RepHostUnreach)
	log.Debugf("[socks5] connect %v", err)
}

// socks5Connect dials the CONNECT target through the listener's upstream egress
// (the same one HTTP CONNECT uses), then either MITMs TLS or relays raw TCP.
func (proxy *Proxy) socks5Connect(c *wrapClientConn, host string, port int, closeIt *bool) {
	proxy.connectTarget(c, host, port, closeIt, true, socks5SniffTimeout)
}

// connectTarget is the shared body of the explicit and the transparent ingress.
// reply says whether a SOCKS5 success reply must be written: a redirected client
// never sent a handshake, so writing one would inject ten bytes of binary into
// its stream.
func (proxy *Proxy) connectTarget(c *wrapClientConn, host string, port int, closeIt *bool, reply bool, sniffBudget time.Duration) {
	hostport := net.JoinHostPort(host, strconv.Itoa(port))
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Scheme: "https", Host: hostport},
		Host:   hostport,
		Header: http.Header{},
	}
	// Carry the connection context so the egress layer can see who this client was
	// authenticated as (see IdentityFromContext) and route accordingly.
	req = req.WithContext(context.WithValue(context.Background(), connContextKey, c.connCtx))
	dialCtx, cancel := context.WithTimeout(context.Background(), socks5UpstreamTimeout)
	defer cancel()
	dst, viaUpstream, err := proxy.dialUpstream(dialCtx, req, hostport)
	if err != nil {
		socks5Fail(c, err)
		return
	}
	if reply {
		if err := socks5ReplyOK(c); err != nil {
			dst.Close()
			return
		}
	}

	// Sniff the client's first bytes after CONNECT succeeds. A TLS ClientHello
	// and a plaintext HTTP request both go to the MITM pipeline; anything else
	// (or silence until the timeout) is raw TCP the MITM layer cannot parse:
	// relay and report metadata.
	// 只等"首字节"到达，然后用已缓冲的字节分类。**不要** Peek(512)：一个 HTTP 请求
	// 只有几十字节，等不到 512 就会死等满整个嗅探预算 —— 实测这会给每条连接加 1 秒。
	_ = c.SetReadDeadline(time.Now().Add(sniffBudget))
	_, perr := c.r.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	peek, _ := c.r.Peek(c.r.Buffered())
	probe := peek
	if len(probe) > socks5SniffProbe {
		probe = probe[:socks5SniffProbe]
	}
	if perr == nil && len(peek) > 0 && helper.IsTls(peek) {
		log.Debugf("[socks5] %s:%d → MITM", host, port)
		// Always dial-lazy (initHttpsDialFn): the attacker's dialFn opens the
		// plain (possibly proxied) target conn on the first request and the
		// target-side TLS is built from the sniffed ClientHello (SNI/ALPN) —
		// mirroring entry.httpsDialLazyAttack. The previously dialled dst is
		// unused on this path and is closed.
		dst.Close()
		*closeIt = false // the MITM pipeline owns the conn from here
		proxy.socks5MITM(c, req)
		return
	}
	// Plaintext HTTP rides the same attack chain as an HTTP-proxy request (lazy
	// dial through the same egress), so its bodies become recorded exchanges
	// instead of byte counts. Every other protocol keeps the raw relay below.
	if perr == nil && looksLikeHTTP1(probe) {
		log.Debugf("[socks5] %s:%d → MITM (plain HTTP)", host, port)
		dst.Close()      // dial-lazy, exactly like the TLS path
		*closeIt = false // socks5HTTPMITM owns the conn from here
		proxy.socks5HTTPMITM(c, hostport, c.connCtx)
		return
	}
	log.Debugf("[socks5] %s:%d → raw relay (first byte 0x%02x, err=%v)", host, port, firstByte(peek), perr)
	proxy.socks5Relay(c, dst, host, port, viaUpstream, proxy.egressLabel(dialCtx, req), peek)
}

// looksLikeHTTP1 reports whether the bytes seen so far can only be the start of
// a plaintext HTTP/1.x request: a token, a space, then a target and the literal
// "HTTP/1." on the first line. Requiring the version literal keeps binary
// protocols that merely start with a short ASCII token out of the MITM path.
func looksLikeHTTP1(probe []byte) bool {
	if len(probe) < 8 {
		return false
	}
	line := probe
	if i := bytes.Index(line, []byte("\r\n")); i >= 0 {
		line = line[:i]
	} else if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	sp := bytes.IndexByte(line, ' ')
	if sp <= 0 || sp > 8 {
		return false
	}
	for _, b := range line[:sp] {
		if b < 'A' || b > 'Z' {
			return false
		}
	}
	return bytes.Contains(line[sp:], []byte("HTTP/1."))
}

// socks5HTTPMITM serves plaintext HTTP arriving over SOCKS5. Requests are read
// straight off the client conn (origin-form, because SOCKS5 already carried the
// destination), rewritten to the absolute URL the HTTP-proxy path expects, and
// pushed through attacker.initHttpDialFn + attack — the same pipeline HTTP
// CONNECT and the HTTP proxy ingress use, so addons record full exchanges.
func (proxy *Proxy) socks5HTTPMITM(c *wrapClientConn, hostport string, connCtx *ConnContext) {
	ctx := context.WithValue(context.Background(), connContextKey, connCtx)
	for {
		req, err := http.ReadRequest(c.r)
		if err != nil {
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = hostport
		if req.Host == "" {
			req.Host = hostport
		}
		req.RequestURI = ""
		req = req.WithContext(ctx)
		req.RemoteAddr = c.RemoteAddr().String()

		w := newSocks5ResponseWriter(c, req)
		proxy.attacker.initHttpDialFn(req)
		proxy.attacker.attack(w, req)
		if err := w.finish(); err != nil {
			return
		}
		if !w.keepAlive() {
			return
		}
	}
}

// socks5ResponseWriter is the minimal http.ResponseWriter the attack chain needs
// on a connection that has no net/http server behind it: it frames the response
// the way net/http would (chunked when the length is unknown, since the attacker
// hands over an already de-chunked body) and streams it to the client.
type socks5ResponseWriter struct {
	conn    net.Conn
	req     *http.Request
	header  http.Header
	wrote   bool
	chunked bool
	status  int
}

func newSocks5ResponseWriter(conn net.Conn, req *http.Request) *socks5ResponseWriter {
	return &socks5ResponseWriter{conn: conn, req: req, header: make(http.Header)}
}

func (w *socks5ResponseWriter) Header() http.Header { return w.header }

func (w *socks5ResponseWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.status = code
	if w.bodyAllowed() && w.header.Get("Content-Length") == "" {
		// The attacker always supplies a de-chunked body, and ReadResponse drops
		// the upstream's Transfer-Encoding header, so an unknown length must be
		// re-framed here — exactly what net/http's server does for its writer.
		w.chunked = true
		w.header.Set("Transfer-Encoding", "chunked")
	}
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	_ = w.header.Write(w.conn)
	_, _ = io.WriteString(w.conn, "\r\n")
}

func (w *socks5ResponseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.chunked {
		if _, err := fmt.Fprintf(w.conn, "%x\r\n", len(p)); err != nil {
			return 0, err
		}
		if _, err := w.conn.Write(p); err != nil {
			return 0, err
		}
		if _, err := io.WriteString(w.conn, "\r\n"); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return w.conn.Write(p)
}

func (w *socks5ResponseWriter) Flush() {}

// finish terminates the response body (chunked terminator) once the attacker is
// done writing.
func (w *socks5ResponseWriter) finish() error {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.chunked {
		_, err := io.WriteString(w.conn, "0\r\n\r\n")
		return err
	}
	return nil
}

// keepAlive reports whether another request may follow on this connection.
func (w *socks5ResponseWriter) keepAlive() bool {
	if w.header.Get("Connection") == "close" || w.req.Close {
		return false
	}
	return w.req.ProtoAtLeast(1, 1)
}

// bodyAllowed mirrors net/http: HEAD responses and 1xx/204/304 carry no body, so
// they must not be chunk-framed.
func (w *socks5ResponseWriter) bodyAllowed() bool {
	if w.req.Method == http.MethodHead {
		return false
	}
	switch {
	case w.status >= 100 && w.status < 200, w.status == http.StatusNoContent, w.status == http.StatusNotModified:
		return false
	}
	return true
}

func socks5ReplyOK(c net.Conn) error {
	_, err := c.Write([]byte{socks5Version, socks5RepOK, 0x00, socks5ATYPIPV4, 0, 0, 0, 0, 0, 0})
	return err
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// socks5MITM hands the TLS client connection to the attacker pipeline, the same
// lazy path an intercepted HTTP CONNECT takes (httpsDialLazyAttack): the real
// upstream handshake happens against the sniffed SNI after the client's
// ClientHello arrives, and decrypted requests flow through the addons.
func (proxy *Proxy) socks5MITM(c *wrapClientConn, req *http.Request) {
	connCtx := c.connCtx
	connCtx.ClientConn.Tls = true
	connCtx.ClientConn.UpstreamCert = false
	ctx := context.WithValue(context.Background(), connContextKey, connCtx)
	req = req.WithContext(ctx)
	proxy.attacker.initHttpsDialFn(req)
	proxy.attacker.httpsLazyAttack(ctx, c, req)
}

// socks5Relay pipes client<->target and reports byte counts on completion.
// peek holds bytes read from the client during sniffing (nil = none); they are
// replayed to the target before streaming continues. egress names what the relay
// left through ("" = direct dial) and is captured at connect time by the caller.
func (proxy *Proxy) socks5Relay(c *wrapClientConn, dst net.Conn, host string, port int, viaUpstream bool, egress string, peek []byte) {
	defer dst.Close()
	src := &socks5ReplayConn{Conn: c, prefix: peek}
	// Capture the head of each direction only when asked to (and only for the
	// caller's ports): the buffers stay bounded whatever the stream size, and a
	// relay nobody wants recorded costs nothing.
	limit := proxy.Opts.Socks5CaptureBytes
	if limit > 0 && !socks5PortSelected(proxy.Opts.Socks5CapturePorts, port) {
		limit = 0
	}
	var upHead, downHead []byte
	dstW := io.Writer(dst)
	srcW := io.Writer(src)
	if limit > 0 {
		dstW = &socks5HeadWriter{w: dst, buf: &upHead, limit: limit}
		srcW = &socks5HeadWriter{w: src, buf: &downHead, limit: limit}
	}
	var up, down int64
	done := make(chan struct{}, 2)
	go func() {
		up, _ = io.Copy(countingWriter{dstW, &up}, src)
		// One direction finished (usually the client hung up): closing the
		// target unblocks the other copy, mirroring transfer()'s behaviour.
		dst.Close()
		done <- struct{}{}
	}()
	go func() {
		down, _ = io.Copy(countingWriter{srcW, &down}, dst)
		c.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
	if proxy.Opts.Socks5RawMeta != nil {
		identity := ""
		if c.connCtx != nil {
			identity = c.connCtx.Identity
		}
		proxy.Opts.Socks5RawMeta(Socks5RawMeta{
			Host: host, Port: port, BytesUp: up, BytesDown: down,
			ViaUpstream: viaUpstream, Egress: egress, Identity: identity,
			HeadUp: upHead, HeadDown: downHead,
		})
	}
	log.Debugf("[socks5] relay %s closed", net.JoinHostPort(host, strconv.Itoa(port)))
}

// socks5ReplayConn re-emits bytes consumed during protocol sniffing before
// streaming the underlying connection.
type socks5ReplayConn struct {
	net.Conn
	prefix []byte
}

func (c *socks5ReplayConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

type countingWriter struct {
	w io.Writer
	n *int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	*c.n += int64(len(p))
	return c.w.Write(p)
}

// socks5HeadWriter forwards every byte and keeps the first limit of them, so a
// relay can be inspected later without holding the whole stream in memory.
type socks5HeadWriter struct {
	w     io.Writer
	buf   *[]byte
	limit int
}

func (h *socks5HeadWriter) Write(p []byte) (int, error) {
	if room := h.limit - len(*h.buf); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		*h.buf = append(*h.buf, p[:room]...)
	}
	return h.w.Write(p)
}

// socks5PortSelected reports whether port is in the capture list (an empty list
// means every port is selected).
func socks5PortSelected(ports []int, port int) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
