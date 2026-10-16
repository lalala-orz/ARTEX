package traffic

import "testing"

// 流量页现在是"一份列表看全部"：HTTP/HTTPS 交换与裸 TCP 转发（SOCKS5/透明转发的
// 非 HTTP 流量）合在一起按时间排序，用同一套任务/出口/主机筛选。之前裸 TCP 藏在
// 单独的"账本"侧栏里，要看一个任务到底产生了哪些流量得两头翻。
func TestPageUnifiedMergesHTTPAndRaw(t *testing.T) {
	tr, _ := openTraffic(t)
	// 一条 HTTP 交换（task 7，经代理）
	tr.record(pendingExchange{
		id: "u1", ts: 100, host: "web.example", method: "GET", url: "http://web.example/",
		status: 200, taskID: 7, identity: "task7", egress: "socks5://10.0.0.1:1080",
		respBody: []byte("hello"),
	})
	// 一条裸 TCP 转发（task 7，直连）与一条裸 TCP（task 9）
	tr.recordSocks5Conn(Socks5Conn{TS: 90, ListenerID: "global", TaskID: 7, Identity: "task7",
		DstHost: "10.0.0.5", DstPort: 3306, BytesUp: 12, BytesDown: 340, Egress: ""})
	tr.recordSocks5Conn(Socks5Conn{TS: 110, ListenerID: "global", TaskID: 9, Identity: "task9",
		DstHost: "10.0.0.6", DstPort: 6379, BytesUp: 5, BytesDown: 7, ViaUpstream: true, Egress: "socks5://10.0.0.1:1080"})

	rows, total, err := tr.PageUnified(PageQuery{}, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(rows) != 3 {
		t.Fatalf("合并后应有 3 条（1 HTTP + 2 raw），实际 total=%d len=%d", total, len(rows))
	}
	// 时间倒序：raw(110) → raw(90) → http(100)？不对：110 > 100 > 90 ⇒ 顺序应是 raw,http,raw
	if rows[0].Kind != "raw" || rows[0].TaskID != 9 {
		t.Fatalf("第一行应是 task9 的 raw: %+v", rows[0])
	}
	if rows[1].Kind != "http" || rows[1].Status != 200 {
		t.Fatalf("第二行应是 http 交换: %+v", rows[1])
	}
	raw := rows[0]
	if raw.Method != "TCP" || raw.URL != "tcp://10.0.0.6:6379" || raw.BytesUp != 5 || raw.BytesDown != 7 || !raw.ViaUpstream {
		t.Fatalf("raw 行映射不对: %+v", raw)
	}
	// 按任务筛：task7 = 1 HTTP + 1 raw
	if _, total, _ := tr.PageUnified(PageQuery{TaskID: 7}, 0, 50); total != 2 {
		t.Fatalf("task7 应有 2 条，实际 %d", total)
	}
	// 出口精确：socks5 那条 raw + http 那条 = 2
	if _, total, _ := tr.PageUnified(PageQuery{Egress: "socks5://10.0.0.1:1080"}, 0, 50); total != 2 {
		t.Fatalf("经代理的应有 2 条，实际 %d", total)
	}
	// 直连：那条 3306 裸 TCP
	rows, total, err = tr.PageUnified(PageQuery{Egress: "direct"}, 0, 50)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].Kind != "raw" || rows[0].URL != "tcp://10.0.0.5:3306" {
		t.Fatalf("直连应只剩 10.0.0.5 的 raw，实际 total=%d rows=%+v err=%v", total, rows, err)
	}
	// 主机筛选对两张表都生效
	if _, total, _ := tr.PageUnified(PageQuery{Host: "web.example"}, 0, 50); total != 1 {
		t.Fatalf("host 筛选 = %d，想要 1", total)
	}
	// 出口下拉的数据源
	vals, err := tr.EgressValues()
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 1 || vals[0] != "socks5://10.0.0.1:1080" {
		t.Fatalf("出口汇总 = %v，想要只有一个代理值", vals)
	}
}
