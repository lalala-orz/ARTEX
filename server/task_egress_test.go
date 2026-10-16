package server

import (
	"strings"
	"testing"
)

// 建任务时填的出口：地址不合法要立刻说清楚并记在待生效表里（任务照建）；
// 代理连不上时也要留下原因而不是静默失败 —— 否则界面上"填了像没填"。
func TestTaskEgressPendingLifecycle(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	clearPendingTaskEgress(778899)

	// 只接受 socks5/socks5h/http/https 这几种代理协议；别的协议立刻说清楚。
	// 注意：http://host:port 本身就是合法的 HTTP 代理，无法与"载荷 URL"按协议区分，
	// 所以它不会被拒绝，而是走探活 —— 探活不过就留原因（这正是设计）。
	err := registerTaskEgress(m, 778899, "ftp://1.2.3.4:21", "")
	if err == nil || !strings.Contains(err.Error(), "只支持 socks5") {
		t.Fatalf("不支持的协议应当被拒绝并说明原因，得到 err=%v", err)
	}
	views := pendingEgressViews()
	hit := false
	for _, v := range views {
		if v.TaskID == 778899 {
			hit = true
			if v.Reason == "" {
				t.Fatal("被拒绝的出口也要留下原因")
			}
			if !strings.Contains(v.Reason, "只支持 socks5") {
				t.Fatalf("原因不对：%q", v.Reason)
			}
		}
	}
	if !hit {
		t.Fatal("被拒绝的出口应当留在待生效表里（任务照建 + 界面能看到）")
	}

	// 代理连不上：任务照建，但待生效，且原因可读。
	dead := registerTaskEgress(m, 778899, "socks5://127.0.0.1:1", "127.0.0.1:1")
	if dead == nil {
		t.Fatal("连不上的代理不该算成功")
	}
	reason := ""
	for _, v := range pendingEgressViews() {
		if v.TaskID == 778899 {
			reason = v.Reason
		}
	}
	if reason == "" {
		t.Fatal("连不上的代理也要留下原因")
	}

	// 清掉（等价于手动绑定成功后走的那一步）。
	clearPendingTaskEgress(778899)
	for _, v := range pendingEgressViews() {
		if v.TaskID == 778899 {
			t.Fatal("清理之后不该还在待生效表里")
		}
	}
}
