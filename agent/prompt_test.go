package agent

import (
	"strings"
	"testing"
)

// TestSocksHostPortParsing pins the snippet's address parsing: a value it cannot
// split must report ok=false so the prompt omits the snippet rather than printing
// a broken one the agent would then copy into a script.
func TestSocksHostPortParsing(t *testing.T) {
	for _, tc := range []struct {
		in         string
		host, port string
		ok         bool
	}{
		{"socks5h://127.0.0.1:8788", "127.0.0.1", "8788", true},
		{"socks5://0.0.0.0:8788", "0.0.0.0", "8788", true},
		{"socks5h://[::1]:8788", "::1", "8788", true},
		{"127.0.0.1:8788", "127.0.0.1", "8788", true},
		{"", "", "", false},
		{"socks5h://127.0.0.1", "", "", false},
		{"socks5h://:8788", "", "", false},
		{"socks5h://127.0.0.1:", "", "", false},
	} {
		host, port, ok := socksHostPort(tc.in)
		if ok != tc.ok || host != tc.host || port != tc.port {
			t.Errorf("socksHostPort(%q) = (%q,%q,%v), want (%q,%q,%v)", tc.in, host, port, ok, tc.host, tc.port, tc.ok)
		}
	}
}

func TestRenderSystemOverrideAndFallback(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })

	// no override → built-in default
	PromptOverride = nil
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "g"}); got != "DEFAULT" {
		t.Fatalf("no override should give default, got %q", got)
	}

	// override → rendered with vars
	PromptOverride = func(k string) (string, bool) {
		if k == "planner" {
			return "目标:{{.Goal}} 范围:{{.Scope}}", true
		}
		return "", false
	}
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "拿下X", Scope: "*.x.com"}); got != "目标:拿下X 范围:*.x.com" {
		t.Fatalf("override render: %q", got)
	}

	// override referencing a non-catalog var → execution error → fallback to default
	PromptOverride = func(k string) (string, bool) { return "{{.NotInCatalog}}", true }
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "x"}); got != "DEFAULT" {
		t.Fatalf("bad var should fall back to default, got %q", got)
	}

	// full plannerSystem path: DB body [A] is honored, then the code-owned tail
	// [C] (中间产物输出规约) is ALWAYS appended — editing the body can't drop it.
	PromptOverride = func(k string) (string, bool) { return "PLANNER {{.Goal}}", true }
	got := plannerSystem("拿下X", "/data", "/data")
	if !strings.HasPrefix(got, "PLANNER 拿下X") {
		t.Fatalf("plannerSystem body not honored: %q", got)
	}
	if !strings.Contains(got, "中间产物输出规约") || !strings.Contains(got, "/data") {
		t.Fatalf("plannerSystem missing code-owned artifact tail: %q", got)
	}

	// worker dual-text via {{if .ProxyAddr}} in a user template, plus the code tail:
	// [B] trafficTool present only when RECORDING (caCert set — the MITM is on, so
	// the traffic_* tools exist), [C] artifact spec always present. The trafficTool
	// block is gated on the CA (arg 2), NOT on ProxyAddr — a global egress proxy
	// with capture off routes traffic but records nothing.
	PromptOverride = func(k string) (string, bool) {
		return "{{if .ProxyAddr}}走代理 {{.ProxyAddr}}{{else}}手动{{end}}", true
	}
	recording := workerSystem("127.0.0.1:8080", "/ca.pem", "socks5h://127.0.0.1:8080", "/data", "/data")
	if !strings.HasPrefix(recording, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker proxy branch body: %q", recording)
	}
	if !strings.Contains(recording, "traffic_search") {
		t.Fatalf("worker while recording should inject trafficTool: %q", recording)
	}
	if strings.Contains(recording, "traffic_refs") {
		t.Fatalf("worker bypassed shared optional evidence policy: %q", recording)
	}
	if !strings.Contains(recording, "中间产物输出规约") {
		t.Fatalf("worker missing artifact tail: %q", recording)
	}
	// 出网透明化之后，提示词要讲的不是"该用哪种客户端"（已经没有代理变量可配，内核
	// 会把 agent 的每条 TCP 送进监听器），而是**记录到什么程度** —— 以为数据库正文被
	// 完整保存的 agent，事后会引用并不存在的证据。
	for _, want := range []string{"出网是透明的", "不需要设置任何代理变量", "前 8KB", "由平台决定"} {
		if !strings.Contains(recording, want) {
			t.Fatalf("worker with a SOCKS5 endpoint should explain recording depth (missing %q): %q", want, recording)
		}
	}
	if !strings.Contains(recording, `socks.SOCKS5, "127.0.0.1", 8080`) {
		t.Fatalf("worker should get a runnable PySocks snippet for tunnel-only internal names: %q", recording)
	}
	// 旧架构的"客户端白名单"必须彻底消失：它把 http.client/裸 socket 说成会带着真实
	// 出口 IP 直连目标，而透明拦截下它们同样被记录 —— 留着只会让 agent 白花步数。
	for _, stale := range []string{"NODE_USE_ENV_PROXY", "真实出口 IP", "set_default_proxy", "正文不落库"} {
		if strings.Contains(recording, stale) {
			t.Fatalf("worker prompt still carries pre-transparent guidance %q: %q", stale, recording)
		}
	}
	// Egress proxy set but capture OFF (no CA): the ProxyAddr template branch still
	// renders, but the trafficTool block must NOT — those tools are not registered.
	egressOnly := workerSystem("127.0.0.1:8080", "", "", "/data", "/data")
	if !strings.HasPrefix(egressOnly, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker egress-only branch body: %q", egressOnly)
	}
	if strings.Contains(egressOnly, "traffic_search") {
		t.Fatalf("worker without recording must NOT inject trafficTool: %q", egressOnly)
	}
	// 记录开着但监听器没有 SOCKS5 入口 → 那句"只有经隧道才解析得了的内网域名"的提示省略。
	noSocks := workerSystem("127.0.0.1:8080", "/ca.pem", "", "/data", "/data")
	if !strings.Contains(noSocks, "traffic_search") {
		t.Fatalf("worker while recording should inject trafficTool: %q", noSocks)
	}
	if strings.Contains(noSocks, "socks.SOCKS5") {
		t.Fatalf("worker without a SOCKS5 endpoint must not ship a SOCKS5 snippet: %q", noSocks)
	}
	noProxy := workerSystem("", "", "", "/data", "/data")
	if !strings.HasPrefix(noProxy, "手动") {
		t.Fatalf("worker no-proxy branch body: %q", noProxy)
	}
	if strings.Contains(noProxy, "traffic_search") {
		t.Fatalf("worker without proxy must NOT inject trafficTool: %q", noProxy)
	}
}
