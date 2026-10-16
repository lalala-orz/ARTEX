package traffic

import "testing"

// 「只看有正文的 TCP」：识别出数据库协议、真保存了上下行字节的连接才该留下。
// 没有这个筛选，想找"哪个连接能点开看包"只能一页页翻。
func TestTCPWithBodyFilter(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.recordSocks5Conn(Socks5Conn{TS: 10, ListenerID: "global", DstHost: "db.example", DstPort: 3306,
		Service: "mysql", HeadUp: []byte("select 1"), HeadDown: []byte("greeting")})
	tr.recordSocks5Conn(Socks5Conn{TS: 11, ListenerID: "global", DstHost: "plain.example", DstPort: 8080})
	tr.record(pendingExchange{id: "h1", ts: 12, host: "web.example", method: "GET", url: "http://web.example/", status: 200})

	if _, total, err := tr.PageUnified(PageQuery{}, 0, 10); err != nil || total != 3 {
		t.Fatalf("不带筛选应有 3 条，得到 %d (err=%v)", total, err)
	}
	rows, total, err := tr.PageUnified(PageQuery{TCPWithBody: true}, 0, 10)
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("「有正文的 TCP」应只剩 1 条，得到 total=%d len=%d err=%v", total, len(rows), err)
	}
	if rows[0].Kind != "raw" || rows[0].Service != "mysql" {
		t.Fatalf("筛出来的应当是那条 mysql 裸 TCP：%+v", rows[0])
	}
}
