package agent

import (
	"strings"
	"testing"
)

// 出网不再靠环境变量：agent 的每条 TCP 都被内核 REDIRECT 进监听器（透明兜底），
// 所以这里**只**注入 CA 信任，绝不注入代理变量 —— 工具不需要知道代理存在，也就
// 不存在"忘了配代理"这条绕过路径。下面三个测试把这条不变量钉住。

func TestProxyEnvNoCAIsNil(t *testing.T) {
	// 没有 CA（捕获关闭）时什么都不注入，连代理地址也一样。
	for _, tc := range []struct{ proxy, socks string }{
		{"", ""},
		{"http://127.0.0.1:8788", "socks5h://127.0.0.1:8788"},
	} {
		if env := proxyEnv(tc.proxy, "", tc.socks); env != nil {
			t.Fatalf("proxyEnv(%q, \"\", %q) = %v, want nil", tc.proxy, tc.socks, env)
		}
	}
}

// 关键不变量：无论传进来什么代理地址，都不能出现任何代理变量。旧实现往 BashEnv 里
// 塞 HTTP_PROXY/ALL_PROXY，那是"靠自觉"的一层；透明拦截落地后它是多余的，而且留着
// 会让工具以为自己需要选代理。
func TestProxyEnvNeverAdvertisesProxy(t *testing.T) {
	forbidden := []string{
		"HTTP_PROXY=", "HTTPS_PROXY=", "http_proxy=", "https_proxy=",
		"ALL_PROXY=", "all_proxy=", "NO_PROXY=", "no_proxy=", "NODE_USE_ENV_PROXY=",
	}
	env := proxyEnv("http://127.0.0.1:8788", "/data/_ca/mitmproxy-ca-cert.pem", "socks5h://task9:tok@127.0.0.1:8788")
	for _, bad := range forbidden {
		for _, e := range env {
			if strings.HasPrefix(e, bad) {
				t.Errorf("proxyEnv 仍然注入了代理变量 %q（透明拦截下不该有）: %v", e, env)
			}
		}
	}
	if len(env) == 0 {
		t.Fatalf("有 CA 时应当注入 CA 信任变量，得到空")
	}
}

func TestProxyEnvInjectsCAWhenRecording(t *testing.T) {
	// 透明模式下 HTTPS 仍要 MITM，客户端必须信任平台 CA；且 python/node 读各自的
	// 证书库而不是系统 store，所以这几个变量一个都不能少。
	env := proxyEnv("http://127.0.0.1:8788", "/data/ca.pem", "")
	has := func(prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"SSL_CERT_FILE=", "CURL_CA_BUNDLE=", "REQUESTS_CA_BUNDLE=", "GIT_SSL_CAINFO=", "NODE_EXTRA_CA_CERTS="} {
		if !has(want) {
			t.Errorf("proxyEnv with CA missing %s: %v", want, env)
		}
	}
	// CA 变量必须指向传入的路径，否则信任的是别的东西。
	for _, e := range env {
		if strings.HasPrefix(e, "REQUESTS_CA_BUNDLE=") && !strings.HasSuffix(e, "/data/ca.pem") {
			t.Errorf("REQUESTS_CA_BUNDLE = %q, want /data/ca.pem", e)
		}
	}
}

// 开关 OFF 时必须把代理变量加回来：那时候没有内核兜底，不加就是"静默直连、零记录"，
// 正是这个开关不能造成的回归。地址用监听器的 SOCKS5 端点（HTTP 入口已删），
// socks5h 让 curl/wget/requests+PySocks 也能用。
func TestEgressEnvFallbackAdvertisesSocks(t *testing.T) {
	socks := "socks5h://task9:tok@127.0.0.1:8788"
	env := egressEnv("http://127.0.0.1:8788", "/data/ca.pem", socks)
	get := func(prefix string) string {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return strings.TrimPrefix(e, prefix)
			}
		}
		return ""
	}
	for _, k := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "http_proxy=", "https_proxy=", "ALL_PROXY=", "all_proxy="} {
		if got := get(k); got != socks {
			t.Errorf("%s = %q, 想要 SOCKS5 端点 %q", k, got, socks)
		}
	}
	if get("NO_PROXY=") != "127.0.0.1,localhost" {
		t.Errorf("NO_PROXY = %q, 想要 127.0.0.1,localhost", get("NO_PROXY="))
	}
	// CA 信任在同一份 env 里，别因为回落就丢了。
	for _, k := range []string{"SSL_CERT_FILE=", "CURL_CA_BUNDLE=", "REQUESTS_CA_BUNDLE=", "NODE_EXTRA_CA_CERTS="} {
		if get(k) == "" {
			t.Errorf("回落 env 丢了 CA 变量 %s: %v", k, env)
		}
	}
}

// 没有可用代理地址时回落 env 只留 CA（不编造一个连不上的代理）。
func TestEgressEnvWithoutTargetIsCAOnly(t *testing.T) {
	env := egressEnv("", "/data/ca.pem", "")
	for _, e := range env {
		if strings.Contains(e, "PROXY=") || strings.Contains(e, "proxy=") {
			t.Fatalf("没有代理地址时不该出现代理变量: %v", env)
		}
	}
	if len(env) == 0 {
		t.Fatal("有 CA 时应至少注入 CA 变量")
	}
}

// 核心不变量：同一组地址，开关 ON 不出现代理变量、OFF 必须出现。
func TestBashEnvSwitchesOnLockdown(t *testing.T) {
	addr, ca, socks := "http://127.0.0.1:8788", "/data/ca.pem", "socks5h://task9:tok@127.0.0.1:8788"
	on := bashEnv(addr, ca, socks, true)
	off := bashEnv(addr, ca, socks, false)
	for _, e := range on {
		if strings.Contains(e, "PROXY=") || strings.Contains(e, "proxy=") {
			t.Errorf("开关 ON 时不该有代理变量: %q", e)
		}
	}
	found := false
	for _, e := range off {
		if strings.HasPrefix(e, "ALL_PROXY=") {
			found = true
		}
	}
	if !found {
		t.Fatalf("开关 OFF 时必须注入代理变量（否则静默直连无记录）: %v", off)
	}
	// 两种模式都必须带 CA。
	if len(on) == 0 || len(off) == 0 {
		t.Fatalf("两种模式都应有 CA 信任变量: on=%v off=%v", on, off)
	}
}
