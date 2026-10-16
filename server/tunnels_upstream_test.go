package server

import "testing"

// 控制通道的出口解析：""=跟随 global_proxy、"direct"/none/off=直连、其它=原样当代理地址。
//
// "direct" 不是便利选项而是必需品：载荷部署在私有网段时，对外的代理通常拒绝转发私有目标
// （实测 ProxyCat 拒绝 192.168/10/172.16），此时探活会直接失败在代理那一跳。
func TestResolveUpstream(t *testing.T) {
	const gp = "socks5://user:pass@172.17.0.1:1080"
	cases := []struct{ in, want string }{
		{"", gp},
		{"   ", gp},
		{"direct", ""},
		{"DIRECT", ""},
		{" direct ", ""},
		{"none", ""},
		{"off", ""},
		{"socks5://127.0.0.1:1081", "socks5://127.0.0.1:1081"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
	}
	for _, c := range cases {
		if got := resolveUpstream(c.in, gp); got != c.want {
			t.Errorf("resolveUpstream(%q) = %q，想要 %q", c.in, got, c.want)
		}
	}
}
