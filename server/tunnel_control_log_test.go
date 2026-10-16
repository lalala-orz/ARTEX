package server

import (
	"testing"

	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/artex/tunnel"
)

// 控制通道的记录策略：
//   - 每条隧道**第一次成功**留一条（这是"控制通道真到得了载荷"的证据）；
//   - 之后的成功**不记**（regeorg 是长轮询，一条活跃隧道每秒几十个请求，全记会灌满索引）；
//   - **传输层失败**记一条，并在窗口内按同类失败去重（这是"隧道为什么不通"的答案）。
func TestTunnelControlLogPolicy(t *testing.T) {
	m, tr, _ := newTunnelTestManager(t)
	log := m.tunnelControlLog(42, "socks5://p:1080")
	if log == nil {
		t.Fatal("应当拿到控制通道回调")
	}
	yes := tunnel.ControlEvent{At: 100, Method: "POST", Host: "payload.example", Path: "/tunnel.php", Status: 200, ReqLen: 10, RespLen: 20}
	log(yes)
	log(yes) // 第二次成功：不记
	fail := tunnel.ControlEvent{At: 101, Method: "POST", Host: "payload.example", Path: "/tunnel.php",
		Err: "dial tcp 10.0.0.9:80: connect: connection refused"}
	log(fail)
	log(fail) // 窗口内同类失败：不记
	tr.FlushRecords()

	rows, total, err := tr.Page(traffic.PageQuery{TaskID: 42}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("应当只有 2 条（1 次首次成功 + 1 次失败），得到 total=%d len=%d", total, len(rows))
	}
	for _, r := range rows {
		if r.Egress != "tunnel-control:socks5://p:1080" {
			t.Fatalf("出口标签应写明控制通道走了哪：%+v", r)
		}
	}
	// 另一个任务（或另一条隧道）的第一次成功要单独记，不该被上面那条"首次"吞掉。
	other := m.tunnelControlLog(43, "")
	other(tunnel.ControlEvent{At: 200, Method: "POST", Host: "payload2.example", Path: "/t.php", Status: 200})
	tr.FlushRecords()
	if _, total, err := tr.Page(traffic.PageQuery{TaskID: 43}, 0, 10); err != nil || total != 1 {
		t.Fatalf("另一条隧道的首次成功应记 1 条，得到 %d (err=%v)", total, err)
	}
	if _, total, err := tr.Page(traffic.PageQuery{Egress: "tunnel-control:direct"}, 0, 10); err != nil || total != 1 {
		t.Fatalf("直连控制通道应有 1 条，得到 %d (err=%v)", total, err)
	}
}
