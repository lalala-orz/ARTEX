package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	log "github.com/sirupsen/logrus"
)

// proxyBasicAuth reads the credentials a proxy client supplied in
// Proxy-Authorization. Both values are empty when the header is absent or
// malformed — Options.Authenticate decides whether that is acceptable.
func proxyBasicAuth(req *http.Request) (user, pass string) {
	const prefix = "Basic "
	v := req.Header.Get("Proxy-Authorization")
	if len(v) < len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len(prefix):]))
	if err != nil {
		return "", ""
	}
	user, pass, _ = strings.Cut(string(raw), ":")
	return user, pass
}

// wrap tcpListener for remote client
type wrapListener struct {
	net.Listener
	proxy *Proxy
}

// socks5AcceptedConn marks a connection taken over by the SOCKS5 handler so the
// HTTP server never sees it (its Conn is served to completion independently).
type socks5AcceptedConn struct{ c *wrapClientConn }

func (s *socks5AcceptedConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (s *socks5AcceptedConn) Write(b []byte) (int, error)        { return 0, io.EOF }
func (s *socks5AcceptedConn) Close() error                       { return nil } // serveSocks5 owns the real conn
func (s *socks5AcceptedConn) LocalAddr() net.Addr                { return nil }
func (s *socks5AcceptedConn) RemoteAddr() net.Addr               { return nil }
func (s *socks5AcceptedConn) SetDeadline(t time.Time) error      { return nil }
func (s *socks5AcceptedConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *socks5AcceptedConn) SetWriteDeadline(t time.Time) error { return nil }

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	proxy := l.proxy
	// SOCKS5 shares the port with the HTTP proxy: a first byte of 0x05 is never
	// a valid HTTP method byte, so the sniffing cost is one Peek for non-SOCKS5
	// clients. A SOCKS5 connection is fully served here and never reaches
	// e.server, whose HTTP handler would reject it anyway.
	wc := newWrapClientConn(c, proxy)
	// Transparent mode: the kernel redirected this connection to the listener, so
	// there is no handshake to read. The original destination is the target and the
	// peer's uid says who is asking; recovering both here keeps routing,
	// attribution and recording identical to an explicit CONNECT.
	if host, port, ok := transparentTarget(c); ok {
		log.Debugf("[entry] 透明连接 → %s:%d (peer %s)", host, port, c.RemoteAddr())
		connCtx := newConnContext(wc, proxy)
		// Resolve the peer's uid here, not in the serving goroutine: the lookup reads
		// /proc for a socket that must still exist, and a short-lived connection is
		// already gone by the time the goroutine runs (identity came out empty).
		connCtx.Identity = proxy.transparentIdentity(wc)
		wc.connCtx = connCtx
		go proxy.serveTransparent(wc, host, port)
		return &socks5AcceptedConn{wc}, nil
	}
	if sniffSocks5(wc) {
		connCtx := newConnContext(wc, proxy)
		wc.connCtx = connCtx
		go proxy.serveSocks5(wc)
		return &socks5AcceptedConn{wc}, nil
	}
	// The HTTP proxy ingress is gone. A connection that is neither redirected nor
	// speaking SOCKS5 is not a client this listener serves, so it is dropped here
	// instead of being handled as an HTTP request.
	// 这条日志是排障用的：透明判定失败时，唯一能从外部区分的原因是 conn 的动态类型
	// 拿不到 fd（SO_ORIGINAL_DST 读不了）。带上类型与能力，省一次猜测。
	_, hasSyscallConn := c.(syscall.Conn)
	log.Debugf("[entry] 丢弃 %s：既非透明也非 SOCKS5（conn 类型 %T，syscall.Conn=%v）", c.RemoteAddr(), c, hasSyscallConn)
	_ = c.Close()
	return &socks5AcceptedConn{wc}, nil
}

// wrap tcpConn for remote client
type wrapClientConn struct {
	net.Conn
	r       *bufio.Reader
	proxy   *Proxy
	connCtx *ConnContext

	closeMu   sync.Mutex
	closed    bool
	closeErr  error
	closeChan chan struct{}
}

func newWrapClientConn(c net.Conn, proxy *Proxy) *wrapClientConn {
	return &wrapClientConn{
		Conn:      c,
		r:         bufio.NewReader(c),
		proxy:     proxy,
		closeChan: make(chan struct{}),
	}
}

func (c *wrapClientConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *wrapClientConn) PeekBuffered() ([]byte, error) {
	return c.r.Peek(c.r.Buffered())
}

func (c *wrapClientConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *wrapClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	log.Debugln("in wrapClientConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()
	close(c.closeChan)

	for _, addon := range c.proxy.Addons {
		addon.ClientDisconnected(c.connCtx.ClientConn)
	}

	if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
		c.connCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

// wrap tcpConn for remote server
type wrapServerConn struct {
	net.Conn
	proxy   *Proxy
	connCtx *ConnContext

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

func (c *wrapServerConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	log.Debugln("in wrapServerConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()

	for _, addon := range c.proxy.Addons {
		addon.ServerDisconnected(c.connCtx)
	}

	if !c.connCtx.ClientConn.Tls {
		c.connCtx.ClientConn.Conn.(*wrapClientConn).Conn.(*net.TCPConn).CloseRead()
	} else {
		// if keep-alive connection close
		if !c.connCtx.closeAfterResponse {
			c.connCtx.ClientConn.Conn.Close()
		}
	}

	return c.closeErr
}

type entry struct {
	proxy  *Proxy
	server *http.Server
}

func newEntry(proxy *Proxy) *entry {
	e := &entry{proxy: proxy}
	e.server = &http.Server{
		Addr:    proxy.Opts.Addr,
		Handler: e,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if sc, ok := c.(*socks5AcceptedConn); ok {
				// A SOCKS5 connection hijacked at Accept: it is never served by
				// this server (its handler goroutine owns the real conn), so
				// the marker must not be unwrapped here.
				return context.WithValue(ctx, connContextKey, sc.c.connCtx)
			}
			return context.WithValue(ctx, connContextKey, c.(*wrapClientConn).connCtx)
		},
	}
	return e
}

func (e *entry) start() error {
	addr := e.server.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Infof("Proxy start listen at %v\n", e.server.Addr)
	pln := &wrapListener{
		Listener: ln,
		proxy:    e.proxy,
	}
	return e.server.Serve(pln)
}

func (e *entry) close() error {
	return e.server.Close()
}

func (e *entry) shutdown(ctx context.Context) error {
	return e.server.Shutdown(ctx)
}

func (e *entry) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.ServeHTTP",
		"host": req.Host,
	})
	// Add entry proxy authentication
	if e.proxy.authProxy != nil {
		b, err := e.proxy.authProxy(res, req)
		if !b {
			log.Errorf("Proxy authentication failed: %s", err.Error())
			httpError(res, "", http.StatusProxyAuthRequired)
			return
		}
	}
	// Identify the client once per connection. The credential arrives on the first
	// request (a CONNECT for HTTPS, or the request itself for plain HTTP) and is
	// remembered, because later requests on the same connection carry no
	// credentials of their own.
	if e.proxy.Opts.Authenticate != nil {
		user, pass := proxyBasicAuth(req)
		// The credential belongs to this proxy, never to the origin: drop it before
		// anything forwards the headers on.
		req.Header.Del("Proxy-Authorization")
		identity, ok := e.proxy.Opts.Authenticate(user, pass)
		if !ok {
			log.Errorf("Proxy authentication failed for user %q", user)
			httpError(res, "", http.StatusProxyAuthRequired)
			return
		}
		if cc, ok := req.Context().Value(connContextKey).(*ConnContext); ok && cc != nil {
			cc.Identity = identity
		}
	}
	// proxy via connect tunnel
	if req.Method == "CONNECT" {
		e.handleConnect(res, req)
		return
	}

	if !req.URL.IsAbs() || req.URL.Host == "" {
		res = helper.NewResponseCheck(res)
		for _, addon := range proxy.Addons {
			addon.AccessProxyServer(req, res)
		}
		if res, ok := res.(*helper.ResponseCheck); ok {
			if !res.Wrote {
				res.WriteHeader(400)
				io.WriteString(res, "此为代理服务器，不能直接发起请求")
			}
		}
		return
	}

	// http proxy
	proxy.attacker.initHttpDialFn(req)
	proxy.attacker.attack(res, req)
}

func (e *entry) handleConnect(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.handleConnect",
		"host": req.Host,
	})

	shouldIntercept := proxy.shouldIntercept == nil || proxy.shouldIntercept(req)
	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	f.ConnContext.Intercept = shouldIntercept
	defer f.finish()

	// trigger addon event Requestheaders
	for _, addon := range proxy.Addons {
		addon.Requestheaders(f)
	}

	if !shouldIntercept {
		log.Debugf("begin transpond %v", req.Host)
		e.directTransfer(res, req, f)
		return
	}

	if f.ConnContext.ClientConn.UpstreamCert {
		e.httpsDialFirstAttack(res, req, f)
		return
	}

	log.Debugf("begin intercept %v", req.Host)
	e.httpsDialLazyAttack(res, req, f)
}

func (e *entry) establishConnection(res http.ResponseWriter, f *Flow) (net.Conn, error) {
	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		for _, addon := range e.proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		res.WriteHeader(502)
		return nil, err
	}
	_, err = io.WriteString(cconn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		cconn.Close()
		for _, addon := range e.proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		return nil, err
	}

	f.Response = &Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	// trigger addon event Responseheaders
	for _, addon := range e.proxy.Addons {
		addon.Responseheaders(f)
	}

	return cconn, nil
}

func (e *entry) directTransfer(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.directTransfer",
		"host": req.Host,
	})

	conn, err := proxy.getUpstreamConn(req.Context(), req)
	if err != nil {
		for _, addon := range proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		res.WriteHeader(502)
		return
	}
	defer conn.Close()

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		return
	}
	defer cconn.Close()

	transfer(log, conn, cconn)
}

func (e *entry) httpsDialFirstAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.httpsDialFirstAttack",
		"host": req.Host,
	})

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		for _, addon := range proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		res.WriteHeader(502)
		return
	}

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		conn.Close()
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		conn.Close()
		log.Error(err)
		return
	}

	if helper.IsTls(peek) {
		f.ConnContext.ClientConn.Tls = true
		proxy.attacker.httpsTlsDial(req.Context(), cconn, conn)
		return
	}

	wsPeek, err := cconn.(*wrapClientConn).PeekBuffered()
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		cconn.Close()
		conn.Close()
		log.Error(err)
		return
	}

	if helper.IsWebSocket(wsPeek) {
		err = proxy.webSocketHandler.handle(conn, cconn, f)
		if err != nil {
			log.Errorf("WebSocket handle error: %v", err)
			cconn.Close()
			conn.Close()
		}
		return
	}

	transfer(log, conn, cconn)
	cconn.Close()
	conn.Close()
}

func (e *entry) httpsDialLazyAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.httpsDialLazyAttack",
		"host": req.Host,
	})

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		log.Error(err)
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}

	if helper.IsTls(peek) {
		f.ConnContext.ClientConn.Tls = true
		proxy.attacker.httpsLazyAttack(req.Context(), cconn, req)
		return
	}

	wsPeek, err := cconn.(*wrapClientConn).PeekBuffered()
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}

	if helper.IsWebSocket(wsPeek) {
		conn, err := proxy.attacker.httpsDial(req.Context(), req)
		if err != nil {
			cconn.Close()
			log.Error(err)
			return
		}
		err = proxy.webSocketHandler.handle(conn, cconn, f)
		if err != nil {
			log.Errorf("WebSocket handle error: %v", err)
			cconn.Close()
			conn.Close()
		}
		return
	}

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}
	transfer(log, conn, cconn)
	conn.Close()
	cconn.Close()
}
