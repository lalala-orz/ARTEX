package server

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/payloads"
	"github.com/Autumn-27/artex/tunnel"
)

// 工具层闭环：清单可发现 → tunnel_up 建隧道并绑定 → tunnel_list 看得到 → tunnel_down
// 释放；探活不过时同样拒绝绑定。用的是 policy 层的真实代码路径，只有隧道本身是假的。
func TestTunnelToolsLifecycle(t *testing.T) {
	m, tr, _ := newTunnelTestManager(t)
	s := &Server{m: m}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7})

	// 1) 发现：清单必须带投放方式/目标/绝对路径，且文件真的在位。
	out := workflowCall(t, ctx, s.toolTunnelPayloads(), map[string]any{}, false)
	var listed struct {
		Dir   string           `json:"dir"`
		Usage string           `json:"usage"`
		Files []payloads.Entry `json:"files"`
	}
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("清单不是合法 JSON: %v (%s)", err, out)
	}
	if listed.Dir == "" || listed.Usage == "" || len(listed.Files) == 0 {
		t.Fatalf("清单内容不完整: %s", out)
	}
	for _, e := range listed.Files {
		if e.Deploy == "" || e.Target == "" || e.TunnelURL == "" || e.SHA256 == "" {
			t.Errorf("条目描述不完整: %+v", e)
		}
		if _, err := os.Stat(e.Path); err != nil {
			t.Errorf("清单里的文件不在位: %v", err)
		}
	}

	// 2) 没有任务上下文时必须拒绝：隧道必须归属某个任务。
	if r := workflowCall(t, context.Background(), s.toolTunnelUp(),
		map[string]any{"url": "http://10.1.1.5/x.php"}, true); !strings.Contains(r, "任务") {
		t.Fatalf("无任务上下文的报错不对: %s", r)
	}

	// 3) 建隧道：探活通过 → 绑定到本任务。
	fake := &fakeTunnel{desc: "suo5:http://10.1.1.5:8080/x.php"}
	var gotReq TunnelRequest
	m.tunnelOpener = func(_ context.Context, req TunnelRequest) (tunnel.Dialer, error) {
		gotReq = req
		return fake, nil
	}
	up := workflowCall(t, ctx, s.toolTunnelUp(),
		map[string]any{"url": "http://10.1.1.5:8080/x.php", "backend": "regeorg", "upstream": "direct"}, false)
	// upstream=direct 解析后是 ""：这条隧道的控制通道直连。
	if gotReq.Backend != "regeorg" || gotReq.Upstream != "" {
		t.Fatalf("工具没有把 backend 传下去: %+v", gotReq)
	}
	if got := tr.IdentityEgressLabel("task7"); got != fake.desc {
		t.Fatalf("工具建隧道后 task7 的出口 = %q，想要 %q", got, fake.desc)
	}
	if !strings.Contains(up, fake.desc) {
		t.Fatalf("tunnel_up 的结果里没有出口描述: %s", up)
	}

	// 4) 列表看得到，并且报告健康。
	list := workflowCall(t, ctx, s.toolTunnelList(), map[string]any{}, false)
	if !strings.Contains(list, `"healthy":true`) || !strings.Contains(list, fake.desc) {
		t.Fatalf("tunnel_list 未显示健康隧道: %s", list)
	}

	// 5) 关闭 → 回到默认出口，隧道真的被关。
	workflowCall(t, ctx, s.toolTunnelDown(), map[string]any{}, false)
	if got := tr.IdentityEgressLabel("task7"); got != "" {
		t.Fatalf("tunnel_down 后仍绑着出口 %q", got)
	}
	if !fake.isClosed() {
		t.Fatal("tunnel_down 后隧道没有真的关闭")
	}

	// 6) 探活不过 → 工具层同样拒绝绑定，任务继续走原出口。
	bad := &fakeTunnel{desc: "suo5:http://10.1.1.6/x.php", fail: true}
	m.tunnelOpener = func(context.Context, TunnelRequest) (tunnel.Dialer, error) { return bad, nil }
	if r := workflowCall(t, ctx, s.toolTunnelUp(),
		map[string]any{"url": "http://10.1.1.6/x.php"}, true); !strings.Contains(r, "探活失败") {
		t.Fatalf("探活失败的报错不对: %s", r)
	}
	if got := tr.IdentityEgressLabel("task7"); got != "" {
		t.Fatalf("探活失败却绑定了出口 %q", got)
	}
	if !bad.isClosed() {
		t.Fatal("探活失败后隧道没有关闭（连接泄漏）")
	}
}

// 一个任务只有一条出口，所以第二条隧道要被拒——工具层要如实把这句话说出来。
func TestTunnelUpRefusesSecondTunnel(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	s := &Server{m: m}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7})
	m.tunnelOpener = func(context.Context, TunnelRequest) (tunnel.Dialer, error) {
		return &fakeTunnel{desc: "suo5:http://10.1.1.5:8080/x.php"}, nil
	}
	workflowCall(t, ctx, s.toolTunnelUp(), map[string]any{"url": "http://10.1.1.5:8080/x.php"}, false)
	if r := workflowCall(t, ctx, s.toolTunnelUp(),
		map[string]any{"url": "http://10.1.1.6/x.php"}, true); !strings.Contains(r, "已有") {
		t.Fatalf("第二条隧道的报错不对: %s", r)
	}
}
