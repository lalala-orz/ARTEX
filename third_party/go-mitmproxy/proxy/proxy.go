package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"

	"github.com/lqqyt2423/go-mitmproxy/cert"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	log "github.com/sirupsen/logrus"
)

type Options struct {
	Debug             int
	Addr              string
	StreamLargeBodies int64 // 当请求或响应体大于此字节时，转为 stream 模式
	SslInsecure       bool
	CaRootPath        string
	NewCaFunc         func() (cert.CA, error) //创建 Ca 的函数
	Upstream          string
	LogFilePath       string // Path to write logs to file

	// Authenticate identifies the client using the listener, shared by both
	// ingresses: user/pass come from SOCKS5 RFC 1929, or from the HTTP
	// Proxy-Authorization header — both empty when the client sent no credentials.
	// ok=false rejects the client. identity is remembered for the connection and
	// handed to every egress dialer (see IdentityFromContext), which is what lets
	// one listener route different clients to different egresses. nil accepts
	// anyone, with an empty identity.
	//
	// Not to be confused with authProxy: that upstream hook answers "may this HTTP
	// request proceed" and can write its own response. Authenticate answers "who is
	// this", for both ingresses.
	Authenticate func(user, pass string) (identity string, ok bool)
	// EgressLabel, when set, names the egress for one connection (redacted),
	// overriding the label derived from the dialer or the upstream URL. A dialer
	// that routes per client only knows the real egress after looking the
	// connection up, and the ledger must not name the router instead. Returning ""
	// falls back to the derived label.
	EgressLabel func(ctx context.Context, req *http.Request) string
	// Socks5RawMeta, when set, receives one metadata report per completed
	// non-TLS relay (see Socks5RawMeta). Content is never reported.
	Socks5RawMeta func(Socks5RawMeta)
	// IdentityFromUID names the agent behind a connection the kernel redirected to
	// the listener (transparent mode). Such a connection carries no credentials, so
	// the uid of the peer is the only identity available; returning "" makes it
	// anonymous.
	IdentityFromUID func(uid int) string
	// Socks5CaptureBytes keeps that many bytes per direction from a raw relay and
	// reports them through Socks5RawMeta.HeadUp/HeadDown. 0 disables capture.
	Socks5CaptureBytes int
	// Socks5CapturePorts restricts capture to these destination ports; empty
	// captures every port (subject to Socks5CaptureBytes). Byte counting and
	// ledger metadata are unaffected either way.
	Socks5CapturePorts []int
	// DisableUpstreamKeepAlive stops the MITM's transports from pooling upstream
	// connections. An egress with very few slots (a tunnel) loses one to every
	// connection left idle in the pool, and it is only reclaimed when the peer
	// times it out — so such an egress must not keep them.
	DisableUpstreamKeepAlive atomic.Bool
}

// UpstreamDialFunc opens one connection through an egress the caller owns, such as
// an in-process tunnel. It takes precedence over every URL-based upstream, because
// the two answer different questions: a proxy URL says how to reach the internet,
// while an injected dialer says how to reach this connection's target. req is the
// request that triggered the connection and may be nil where the context does not
// carry it.
//
// A dialer that only serves some connections returns ErrEgressNotHandled for the
// rest, which hands them back to the upstream proxy URL. Returning any other error
// refuses the connection.
type UpstreamDialFunc func(ctx context.Context, req *http.Request, network, address string) (net.Conn, error)

// ErrEgressNotHandled tells dialUpstream that the installed dialer does not serve
// this connection, so the upstream proxy URL (or a direct dial) must be used
// instead. It is how an egress chosen per client — a task's own tunnel — coexists
// with a listener-wide upstream.
var ErrEgressNotHandled = errors.New("egress dialer did not handle this connection")

type Proxy struct {
	Opts    *Options
	Version string
	Addons  []Addon

	entry               *entry
	attacker            *attacker
	webSocketHandler    *webSocketHandler
	shouldIntercept     func(req *http.Request) bool              // req is received by proxy.server
	upstreamProxy       func(req *http.Request) (*url.URL, error) // req is received by proxy.server, not client request
	upstreamDialer      UpstreamDialFunc
	upstreamDialerLabel string
	authProxy           func(res http.ResponseWriter, req *http.Request) (bool, error)
}

// proxy.server req context key
var proxyReqCtxKey = new(struct{})

func NewProxy(opts *Options) (*Proxy, error) {
	if opts.StreamLargeBodies <= 0 {
		opts.StreamLargeBodies = 1024 * 1024 * 5 // default: 5mb
	}

	proxy := &Proxy{
		Opts:    opts,
		Version: "1.9.2",
		Addons:  make([]Addon, 0),
	}

	proxy.entry = newEntry(proxy)

	attacker, err := newAttacker(proxy)
	if err != nil {
		return nil, err
	}
	proxy.attacker = attacker

	proxy.webSocketHandler = newWebSocketHandler(proxy)

	return proxy, nil
}

func (proxy *Proxy) AddAddon(addon Addon) {
	proxy.Addons = append(proxy.Addons, addon)
}

func (proxy *Proxy) Start() error {
	go func() {
		if err := proxy.attacker.start(); err != nil {
			log.Error(err)
		}
	}()
	return proxy.entry.start()
}

func (proxy *Proxy) Close() error {
	return proxy.entry.close()
}

func (proxy *Proxy) Shutdown(ctx context.Context) error {
	return proxy.entry.shutdown(ctx)
}

func (proxy *Proxy) GetCertificate() x509.Certificate {
	return *proxy.attacker.ca.GetRootCA()
}

func (proxy *Proxy) GetCertificateByCN(commonName string) (*tls.Certificate, error) {
	return proxy.attacker.ca.GetCert(commonName)
}

func (proxy *Proxy) SetShouldInterceptRule(rule func(req *http.Request) bool) {
	proxy.shouldIntercept = rule
}

func (proxy *Proxy) SetUpstreamProxy(fn func(req *http.Request) (*url.URL, error)) {
	proxy.upstreamProxy = fn
}

// SetUpstreamDialer installs an egress dialer, which then wins over the upstream
// proxy URL for every captured connection. label names the egress for the ledger
// and logs and must not carry credentials. Set it before the proxy starts serving;
// like upstreamProxy it is read per request and is not synchronised.
func (proxy *Proxy) SetUpstreamDialer(fn UpstreamDialFunc, label string) {
	proxy.upstreamDialer, proxy.upstreamDialerLabel = fn, label
}

// egressLabel names what a connection is about to leave through: Options.EgressLabel
// when it answers — a dialer that routes per client knows the real egress only
// after looking the connection up — otherwise the dialer's label, the upstream
// proxy URL without credentials, or "" for a direct dial. Resolved once per
// connection, so a later swap cannot rewrite what already happened.
func (proxy *Proxy) egressLabel(ctx context.Context, req *http.Request) string {
	if proxy.Opts.EgressLabel != nil {
		l := proxy.Opts.EgressLabel(context.WithValue(ctx, identityKey, identityOf(ctx, req)), req)
		if l != "" {
			return l
		}
	}
	if proxy.upstreamDialer != nil {
		return proxy.upstreamDialerLabel
	}
	proxyUrl, err := proxy.getUpstreamProxyUrl(req)
	if err != nil || proxyUrl == nil {
		return ""
	}
	return redactedURL(proxyUrl)
}

// identityKey carries the authenticated identity into an egress dialer.
var identityKey = new(struct{})

// IdentityFromContext reports who the listener authenticated for the connection
// being dialed, as seen from inside an egress dialer. Empty when the client sent no
// credentials and Options.Authenticate accepted it anonymously.
func IdentityFromContext(ctx context.Context) string {
	s, _ := ctx.Value(identityKey).(string)
	return s
}

// identityOf reads the identity the ingress recorded for this connection. The
// request is preferred because not every path threads the connection context
// through the dial context as well.
func identityOf(ctx context.Context, req *http.Request) string {
	if req != nil {
		if cc, ok := req.Context().Value(connContextKey).(*ConnContext); ok && cc != nil {
			return cc.Identity
		}
	}
	if cc, ok := ctx.Value(connContextKey).(*ConnContext); ok && cc != nil {
		return cc.Identity
	}
	return ""
}

// redactedURL renders a proxy URL without its userinfo: egress labels reach the
// ledger and the logs, where credentials must never appear.
func redactedURL(u *url.URL) string {
	c := *u
	c.User = nil
	return c.String()
}

func (proxy *Proxy) realUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		// An injected dialer owns the egress. Answering nil keeps net/http from
		// doing its own CONNECT to this URL on top of the dialer, which would
		// tunnel the tunnel; upstreamDialContext then opens the connection.
		if proxy.upstreamDialer != nil {
			return nil, nil
		}
		req := cReq.Context().Value(proxyReqCtxKey).(*http.Request)
		return proxy.getUpstreamProxyUrl(req)
	}
}

// upstreamDialContext is the transport-level counterpart of getUpstreamConn, for
// callers whose egress is expressed as Transport.Proxy instead of a dial function.
//
// Without an injected dialer it is a plain dial, which is both net/http's own
// default and the hop used to reach an upstream proxy host. With one installed,
// Transport.Proxy answers nil and net/http reaches this function to open the target
// connection, so the dialer takes over.
func (proxy *Proxy) upstreamDialContext() func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if proxy.upstreamDialer == nil {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		req, _ := ctx.Value(proxyReqCtxKey).(*http.Request)
		conn, _, err := proxy.dialUpstream(ctx, req, address)
		return conn, err
	}
}

func (proxy *Proxy) getUpstreamProxyUrl(req *http.Request) (*url.URL, error) {
	if proxy.upstreamProxy != nil {
		return proxy.upstreamProxy(req)
	}
	if len(proxy.Opts.Upstream) > 0 {
		return url.Parse(proxy.Opts.Upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

// dialUpstream resolves the egress for one connection: an injected dialer first,
// then the upstream proxy URL, then a direct dial. viaUpstream reports whether the
// connection left through something other than a direct dial, which callers record
// as evidence that the traffic was not sent from this host's own address.
func (proxy *Proxy) dialUpstream(ctx context.Context, req *http.Request, address string) (conn net.Conn, viaUpstream bool, err error) {
	if proxy.upstreamDialer != nil {
		dialCtx := context.WithValue(ctx, identityKey, identityOf(ctx, req))
		conn, err = proxy.upstreamDialer(dialCtx, req, "tcp", address)
		switch {
		case err == nil:
			return conn, true, nil
		case errors.Is(err, ErrEgressNotHandled):
			// This connection is not the dialer's to serve: fall through to the
			// upstream proxy URL, or to a direct dial.
		default:
			// Any other error is a refusal and must surface: silently dialing
			// directly here would send the traffic from this host's own address.
			return nil, true, err
		}
	}
	var proxyUrl *url.URL
	if proxyUrl, err = proxy.getUpstreamProxyUrl(req); err != nil {
		return nil, false, err
	}
	if proxyUrl != nil {
		conn, err = helper.GetProxyConn(ctx, proxyUrl, address, proxy.Opts.SslInsecure)
		return conn, true, err
	}
	conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	return conn, false, err
}

func (proxy *Proxy) getUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	conn, _, err := proxy.dialUpstream(ctx, req, helper.CanonicalAddr(req.URL))
	return conn, err
}

func (proxy *Proxy) SetAuthProxy(fn func(res http.ResponseWriter, req *http.Request) (bool, error)) {
	proxy.authProxy = fn
}
