package server

import "testing"

// socks5/socks5h 地址要能被自动识别成"已有代理"这一路 —— 否则 agent 直接丢一个 socks5
// 地址过来会被载荷校验拒掉。http/https 保持载荷语义（也可能是 CONNECT 型代理，由 backend 指定）。
func TestIsProxyBackendAutoDetectsSocks5(t *testing.T) {
	cases := []struct {
		name string
		req  TunnelRequest
		want bool
	}{
		{"显式 proxy", TunnelRequest{Backend: "proxy", ServerURL: "socks5://127.0.0.1:1080"}, true},
		{"socks5 自动识别", TunnelRequest{ServerURL: "socks5://user:pass@10.0.0.1:1080"}, true},
		{"socks5h 自动识别", TunnelRequest{ServerURL: "socks5h://10.0.0.1:1080"}, true},
		{"载荷 URL 仍是载荷", TunnelRequest{ServerURL: "http://target/tunnel.php"}, false},
		{"显式 regeorg", TunnelRequest{Backend: "regeorg", ServerURL: "http://target/tunnel.php"}, false},
		{"http 代理需显式声明", TunnelRequest{Backend: "http", ServerURL: "http://10.0.0.1:3128"}, true},
	}
	for _, c := range cases {
		if got := isProxyBackend(c.req); got != c.want {
			t.Fatalf("%s: isProxyBackend=%v，想要 %v", c.name, got, c.want)
		}
	}
}

// 代理型出口的地址校验要给出清楚错误：不支持的协议、坏地址都不能拖到运行期才炸。
func TestOpenTunnelRejectsBadProxyAddress(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	if _, err := m.OpenTunnel(t.Context(), TunnelRequest{TaskID: 987654, Backend: "proxy", ServerURL: "ftp://1.2.3.4:21"}); err == nil {
		t.Fatal("不支持的协议应当被拒绝")
	}
	if _, err := m.OpenTunnel(t.Context(), TunnelRequest{TaskID: 987654, Backend: "proxy", ServerURL: "socks5://"}); err == nil {
		t.Fatal("缺 host 的地址应当被拒绝")
	}
}
