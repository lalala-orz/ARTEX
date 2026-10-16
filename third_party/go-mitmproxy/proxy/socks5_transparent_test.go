package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
)

// 透明入口：客户端什么都不说（没有握手），目标与身份都从 socket 恢复；记录深度应与
// 显式 CONNECT 一致 —— 这里断言 MITM 真的看到了请求、且响应原样回到客户端。
func TestServeTransparentPlainHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "transparent-body")
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	rec := &recordAddon{}
	p, err := NewProxy(&Options{
		Addr:        "127.0.0.1:0",
		SslInsecure: true,
		NewCaFunc:   func() (cert.CA, error) { return cert.NewSelfSignCAMemory() },
	})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAddon(rec)
	// 直连上游：测试进程里可能带着 HTTP_PROXY，会让这次拨号走外部代理。
	p.SetUpstreamProxy(func(*http.Request) (*url.URL, error) { return nil, nil })

	// 真实 TCP 连接（不是 net.Pipe）：透明路径要的是正常的 deadline/地址语义。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		wc := newWrapClientConn(c, p)
		wc.connCtx = newConnContext(wc, p)
		p.serveTransparent(wc, host, port)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(client, "GET /x HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(client)

	rec.mu.Lock()
	reqs := append([]string(nil), rec.requests...)
	rec.mu.Unlock()
	if len(reqs) != 1 || !strings.Contains(reqs[0], "http://"+host) {
		t.Fatalf("addon 看到的请求 = %v，想要 1 条 http://%s/...", reqs, host)
	}
	if !strings.Contains(string(body), "transparent-body") {
		head := body
		if len(head) > 160 {
			head = head[:160]
		}
		t.Fatalf("上游响应没透传回客户端: %q", string(head))
	}
}
