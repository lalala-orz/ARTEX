package traffic

import "testing"

// 删流量必须连裸 TCP 账本一起删。
//
// 之前 deleteWhere 只清 exchanges 一系（exchanges/exchange_bodies/blob_refs/ex_fts），
// socks5_connections 和 socks5_bodies 从来没被删过：按主机删、批量删、甚至"清空全部"
// 之后，裸 TCP 行和被识别的数据库上下行头部都还在。合并成一张流量表后这个漏洞直接可见
// （删完还在列表里）。
func TestDeleteHostAlsoRemovesRawTCPLedger(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(pendingExchange{id: "d1", ts: 10, host: "gone.example", method: "GET",
		url: "http://gone.example/", status: 200, respBody: []byte("x")})
	tr.recordSocks5Conn(Socks5Conn{TS: 11, ListenerID: "global", DstHost: "gone.example", DstPort: 3306,
		BytesUp: 5, BytesDown: 50, Service: "mysql", HeadUp: []byte("select 1"), HeadDown: []byte("greeting")})
	// 与它无关的一条：不该被顺手删掉
	tr.recordSocks5Conn(Socks5Conn{TS: 12, ListenerID: "global", DstHost: "keep.example", DstPort: 6379,
		BytesUp: 1, BytesDown: 2})

	// 删除条数现在是"交换 + 裸 TCP"的合计：这条主机 1 条交换 + 1 条裸 TCP = 2。
	// 以前只报交换数，清空两百多条裸 TCP 却报 0，看着像没删。
	if n, err := tr.DeleteHost("gone.example"); err != nil || n != 2 {
		t.Fatalf("DeleteHost = %d, err=%v（想要 1 交换 + 1 裸 TCP = 2）", n, err)
	}
	var conns, bodies int
	if err := tr.DB().QueryRow(`SELECT COUNT(*) FROM socks5_connections WHERE dst_host='gone.example'`).Scan(&conns); err != nil {
		t.Fatal(err)
	}
	if err := tr.DB().QueryRow(`SELECT COUNT(*) FROM socks5_bodies`).Scan(&bodies); err != nil {
		t.Fatal(err)
	}
	if conns != 0 {
		t.Fatalf("按主机删后仍留下 %d 条裸 TCP 账本行（正文 %d 行）", conns, bodies)
	}
	if bodies != 0 {
		t.Fatalf("按主机删后仍留下 %d 行裸 TCP 正文", bodies)
	}
	var keep int
	if err := tr.DB().QueryRow(`SELECT COUNT(*) FROM socks5_connections WHERE dst_host='keep.example'`).Scan(&keep); err != nil {
		t.Fatal(err)
	}
	if keep != 1 {
		t.Fatalf("无关主机的账本行被误删：keep=%d", keep)
	}

	// 清空全部也要连账本一起清
	if _, _, err := tr.DeleteAll(); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`SELECT COUNT(*) FROM socks5_connections`, `SELECT COUNT(*) FROM socks5_bodies`, `SELECT COUNT(*) FROM exchanges`} {
		var left int
		if err := tr.DB().QueryRow(q).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Fatalf("清空全部后 %s 仍剩 %d 行", q, left)
		}
	}
}
