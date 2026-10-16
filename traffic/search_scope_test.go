package traffic

import "testing"

// B3 的契约：不给 host、只给正文关键词时，检索应当【默认限定调用者所属任务】。
// 这是"按证据内容反查承载它的交换"能走通的关键，也是多任务同靶场时不串味的保证。
func TestQueryScopedWithoutHostStaysInTask(t *testing.T) {
	tr, _ := openTraffic(t)
	const needle = "vbid9vyu04zpjux8xkk"
	tr.record(pendingExchange{
		id: "s1", ts: 1, host: "run.example", method: "POST", url: "http://run.example/rce.php",
		status: 200, taskID: 7, identity: "task7",
		reqBody:  []byte("ipaddress=; for f in instance-id; do curl -s http://100.100.100.200; done"),
		respBody: []byte("instance-id " + needle + " zhangjiakou"),
	})
	tr.record(pendingExchange{
		id: "s2", ts: 2, host: "other.example", method: "GET", url: "http://other.example/x",
		status: 200, taskID: 9, identity: "task9",
		respBody: []byte("无关内容 " + needle),
	})

	scoped := func(taskID int64) int {
		t.Helper()
		rows, err := tr.queryScoped("", "", needle, taskID, 0, 5)
		if err != nil {
			t.Fatalf("queryScoped: %v", err)
		}
		return len(rows)
	}
	if got := scoped(7); got != 1 {
		t.Fatalf("task 7 内检索 = %d，想要 1（无 host 也要能命中）", got)
	}
	if got := scoped(9); got != 1 {
		t.Fatalf("task 9 内检索 = %d，想要 1", got)
	}
	if got := scoped(11); got != 0 {
		t.Fatalf("无关任务检索 = %d，想要 0（必须限定在本任务）", got)
	}
	if got := scoped(0); got != 2 {
		t.Fatalf("不限定任务 = %d，想要 2", got)
	}
	// 太短的词无法进入 trigram 索引：这里直接报错拒绝（而不是静默退化成全库扫描）。
	if _, err := tr.queryScoped("", "", "vb", 0, 0, 5); err == nil {
		t.Fatal("两个字符的关键词应当被拒绝（trigram 门槛 ≥3）")
	}
	// 给了 host 时仍然只按该 host 精确匹配。
	if rows, err := tr.queryScoped("run.example", "", needle, 0, 0, 5); err != nil || len(rows) != 1 {
		t.Fatalf("带 host 的检索 = %d err=%v，想要 1", len(rows), err)
	}
}
