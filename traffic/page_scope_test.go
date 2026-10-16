package traffic

import "testing"

// 「未归属」（task 0）必须能单独筛出来：它是平台自身/没有任务上下文的流量，光传
// task_id=0 不行——那在后端等于"没填筛选"。HTTP 表与合并视图都要认这个筛选。
func TestUnattributedFilterMatchesTaskZeroRows(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(pendingExchange{id: "u0", ts: 1, host: "platform.example", method: "GET", url: "http://platform.example/", status: 200})
	tr.record(pendingExchange{id: "u1", ts: 2, host: "task42.example", method: "GET", url: "http://task42.example/", status: 200, taskID: 42})

	if _, total, err := tr.Page(PageQuery{}, 0, 10); err != nil || total != 2 {
		t.Fatalf("不带筛选应看到 2 条，得到 %d (err=%v)", total, err)
	}
	rows, total, err := tr.Page(PageQuery{Unattributed: true}, 0, 10)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].ID != "u0" {
		t.Fatalf("「未归属」应只匹配 task_id=0 的行：total=%d rows=%v err=%v", total, rows, err)
	}
	if _, total, err := tr.PageUnified(PageQuery{Unattributed: true}, 0, 10); err != nil || total != 1 {
		t.Fatalf("合并视图的「未归属」筛选 = %d (err=%v)，想要 1", total, err)
	}
}

// 主机列表（流量页的选择器）必须包含"只有裸 TCP"的目标：以前它只读 exchanges，
// 于是这些目标在界面上根本列不出来，也就没法按主机删。
func TestHostsIncludesRawTCPOnlyTargets(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(pendingExchange{id: "h1", ts: 10, host: "web.example", method: "GET", url: "http://web.example/", status: 200})
	tr.recordSocks5Conn(Socks5Conn{TS: 20, ListenerID: "global", DstHost: "db.internal", DstPort: 3306})

	hosts, err := tr.Hosts()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, h := range hosts {
		seen[h.Host] = h.Count
	}
	if seen["web.example"] != 1 {
		t.Fatalf("HTTP 主机计数 = %d，想要 1", seen["web.example"])
	}
	if seen["db.internal"] != 1 {
		t.Fatalf("只有裸 TCP 的目标没进主机列表：%v", seen)
	}
}

// 删任务按 task_id 删（主机清单兜底）：只按主机清单会漏掉"本任务但目标不在清单里"的行
// —— 裸 TCP 的目标最容易这样漏，因为主机清单历来来自 HTTP 侧。
func TestStageDeleteForTaskCoversRawOnlyTargets(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(pendingExchange{id: "a1", ts: 1, host: "shared.example", method: "GET", url: "http://shared.example/", status: 200, taskID: 42})
	tr.record(pendingExchange{id: "a2", ts: 2, host: "only42.example", method: "GET", url: "http://only42.example/", status: 200, taskID: 42})
	tr.record(pendingExchange{id: "b1", ts: 3, host: "other99.example", method: "GET", url: "http://other99.example/", status: 200, taskID: 99})
	tr.recordSocks5Conn(Socks5Conn{TS: 4, ListenerID: "global", TaskID: 42, DstHost: "raw-only.example",
		DstPort: 3306, Service: "mysql", HeadUp: []byte("x"), HeadDown: []byte("y")})

	stage, err := tr.StageDeleteForTask(42, []string{"shared.example"})
	if err != nil {
		t.Fatal(err)
	}
	if stage.Deleted() == 0 {
		t.Fatal("应当删到行")
	}
	if err := stage.Commit(); err != nil {
		t.Fatal(err)
	}
	count := func(q string) int {
		var n int
		if err := tr.DB().QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM exchanges WHERE task_id=42`); n != 0 {
		t.Fatalf("本任务的交换行没删净：剩 %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM socks5_connections WHERE task_id=42`); n != 0 {
		t.Fatalf("本任务的裸 TCP 行没删净（主机不在清单里就漏）：剩 %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM socks5_bodies`); n != 0 {
		t.Fatalf("裸 TCP 正文没删净：剩 %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM exchanges WHERE task_id=99`); n != 1 {
		t.Fatalf("别的任务、主机不在清单里的行被误删：剩下 %d，想要 1", n)
	}
}
