package traffic

import (
	"testing"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// The traffic page has to answer "this task's traffic" and "what actually left
// through a proxy or a tunnel", so Page grew identity/egress/task filters.
func TestPageFiltersByTaskIdentityEgress(t *testing.T) {
	tr, _ := openTraffic(t)
	rows := []pendingExchange{
		{id: "1", ts: 1, host: "a.example", method: "GET", url: "http://a.example/1",
			status: 200, taskID: 7, identity: "task7", egress: "socks5://10.0.0.1:1080"},
		{id: "2", ts: 2, host: "b.example", method: "GET", url: "http://b.example/2",
			status: 200, taskID: 7, identity: "task7"},
		{id: "3", ts: 3, host: "c.example", method: "GET", url: "http://c.example/3",
			status: 200, taskID: 9, identity: "task9", egress: "regeorg:http://tunnel/x.php"},
	}
	for _, pe := range rows {
		tr.record(pe)
	}
	total := func(f PageQuery) int {
		t.Helper()
		_, n, err := tr.Page(f, 0, 50)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := total(PageQuery{}); got != 3 {
		t.Fatalf("无过滤 = %d，想要 3", got)
	}
	if got := total(PageQuery{TaskID: 7}); got != 2 {
		t.Fatalf("task 7 = %d，想要 2", got)
	}
	if got := total(PageQuery{Identity: "task9"}); got != 1 {
		t.Fatalf("identity task9 = %d，想要 1", got)
	}
	if got := total(PageQuery{Egress: "socks5://10.0.0.1:1080"}); got != 1 {
		t.Fatalf("egress 含 socks5 = %d，想要 1", got)
	}
	if got := total(PageQuery{Egress: "regeorg:http://tunnel/x.php"}); got != 1 {
		t.Fatalf("egress 精确匹配 = %d，想要 1", got)
	}
	// direct 是关键字：只看出口为空（直连）的行。
	if got := total(PageQuery{Egress: "direct"}); got != 1 {
		t.Fatalf("egress=direct（直连）= %d，想要 1", got)
	}
	if got := total(PageQuery{TaskID: 7, Egress: "socks5://10.0.0.1:1080"}); got != 1 {
		t.Fatalf("task7+经代理 = %d，想要 1", got)
	}
	if got := total(PageQuery{TaskID: 9, Egress: "socks5"}); got != 0 {
		t.Fatalf("task9+经代理 = %d，想要 0", got)
	}
}

// An exchange that left through the listener upstream must say so, the way the
// raw-TCP ledger already does — otherwise a proxied row is indistinguishable from
// a direct one in the traffic view.
func TestExchangeEgressFallsBackToListenerUpstream(t *testing.T) {
	tr, _ := openTraffic(t)
	if err := tr.SetUpstreamProxy("socks5://user:pass@10.1.2.3:1080"); err != nil {
		t.Fatal(err)
	}
	tr.enqueue(newFlow("proxied.example", "GET", "/x", nil, []byte("ok")))
	rs, total, err := tr.Page(PageQuery{Host: "proxied.example"}, 0, 10)
	if err != nil || total != 1 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	if rs[0].Egress != "socks5://10.1.2.3:1080" {
		t.Fatalf("egress = %q，想要脱敏后的代理 URL", rs[0].Egress)
	}
	if rs[0].Egress == "socks5://user:pass@10.1.2.3:1080" {
		t.Fatal("egress 里不能出现凭据")
	}
}

// The identity binding wins over the listener upstream: a task with a tunnel must
// keep reporting its tunnel even while a global proxy is configured.
func TestIdentityEgressWinsOverListenerUpstream(t *testing.T) {
	tr, _ := openTraffic(t)
	if err := tr.SetUpstreamProxy("socks5://10.1.2.3:1080"); err != nil {
		t.Fatal(err)
	}
	tr.SetIdentityEgress("taskA", "tokA", 42, labelDialer{label: "regeorg:tunnel"})
	tr.enqueue(newFlow("tunnelled.example", "GET", "/y", nil, []byte("ok"),
		func(f *mproxy.Flow) { f.ConnContext = &mproxy.ConnContext{Identity: "taskA"} }))
	rs, total, err := tr.Page(PageQuery{Host: "tunnelled.example"}, 0, 10)
	if err != nil || total != 1 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	if rs[0].Egress != "regeorg:tunnel" {
		t.Fatalf("egress = %q，想要该身份的隧道标签", rs[0].Egress)
	}
	if rs[0].TaskID != 42 || rs[0].Identity != "taskA" {
		t.Fatalf("归属丢失: task_id=%d identity=%q", rs[0].TaskID, rs[0].Identity)
	}
}
