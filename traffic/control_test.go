package traffic

import "testing"

// 控制通道记录要真的落到同一张流量表里（任务归属 + 出口标签 + 失败原因），
// 这样隧道健康/失败才和别的流量一样可筛可查。
func TestRecordControlExchangeWritesRow(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.RecordControlExchange(ControlExchange{
		At: 1700, TaskID: 42, Egress: "tunnel-control:direct",
		Method: "POST", Host: "payload.example", Path: "/tunnel.php",
		URL: "http://payload.example/tunnel.php", Status: 200, ReqLen: 12, RespLen: 34,
	})
	tr.RecordControlExchange(ControlExchange{
		At: 1701, TaskID: 42, Egress: "tunnel-control:socks5://p:1080",
		Method: "POST", Host: "payload.example", Path: "/tunnel.php",
		Status: 0, ErrText: "dial tcp 10.0.0.9:80: connect: connection refused",
	})
	tr.FlushRecords()

	rows, total, err := tr.Page(PageQuery{TaskID: 42}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("应当有 2 条控制通道记录，得到 total=%d len=%d", total, len(rows))
	}
	byEgress := map[string]int{}
	for _, r := range rows {
		byEgress[r.Egress]++
		if r.TaskID != 42 {
			t.Fatalf("任务归属丢了：%+v", r)
		}
	}
	if byEgress["tunnel-control:direct"] != 1 || byEgress["tunnel-control:socks5://p:1080"] != 1 {
		t.Fatalf("出口标签不对：%v", byEgress)
	}

	// 失败原因存在"响应正文"里：流量页点开就能看到为什么不通。
	var failBody string
	if err := tr.DB().QueryRow(`SELECT b.resp_body FROM exchange_bodies b JOIN exchanges e ON e.id=b.id
		WHERE e.egress=?`, "tunnel-control:socks5://p:1080").Scan(&failBody); err != nil {
		t.Fatalf("失败记录里应当能读到原因：%v", err)
	}
	if failBody == "" {
		t.Fatal("失败原因为空")
	}
}
