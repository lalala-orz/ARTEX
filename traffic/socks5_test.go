package traffic

import "testing"

// TestSocks5ConnsLedger pins the raw-TCP ledger contract: rows land with their
// task attribution, byte counts and egress flag, paging works, and the filter
// matches the traffic page's nil/0/pointer semantics.
func TestSocks5ConnsLedger(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	rows := []Socks5Conn{
		{TS: 100, ListenerID: GlobalListenerID, TaskID: 7, DstHost: "10.0.0.5", DstPort: 3306, BytesUp: 12, BytesDown: 340, ViaUpstream: true},
		{TS: 101, ListenerID: GlobalListenerID, TaskID: 7, DstHost: "10.0.0.6", DstPort: 22, BytesUp: 5, BytesDown: 0},
		{TS: 102, ListenerID: GlobalListenerID, TaskID: 0, DstHost: "10.0.0.7", DstPort: 6379},
	}
	for _, c := range rows {
		tr.recordSocks5Conn(c)
	}

	// Everything, newest first.
	got, total, err := tr.Socks5Conns("", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(got) != 3 {
		t.Fatalf("total=%d len=%d, want 3/3", total, len(got))
	}
	if got[0].DstPort != 6379 || got[2].DstPort != 3306 {
		t.Fatalf("order wrong: %+v", got)
	}
	if !got[2].ViaUpstream || got[2].BytesUp != 12 || got[2].BytesDown != 340 {
		t.Fatalf("byte counts / egress flag lost: %+v", got[2])
	}
	if got[2].TaskID != 7 || got[2].ListenerID != GlobalListenerID {
		t.Fatalf("attribution lost: %+v", got[2])
	}

	// Host filter: only rows for that destination.
	got, total, err = tr.Socks5Conns("10.0.0.5", 0, 100)
	if err != nil || total != 1 || len(got) != 1 || got[0].DstPort != 3306 {
		t.Fatalf("host filter: total=%d len=%d got=%+v err=%v", total, len(got), got, err)
	}
	// A different destination is not returned by the first filter.
	got, total, err = tr.Socks5Conns("10.0.0.7", 0, 100)
	if err != nil || total != 1 || got[0].DstPort != 6379 {
		t.Fatalf("second host filter: total=%d got=%+v err=%v", total, got, err)
	}

	// Paging.
	got, total, err = tr.Socks5Conns("", 1, 2)
	if err != nil || total != 3 || len(got) != 1 || got[0].DstPort != 3306 {
		t.Fatalf("page 1: total=%d got=%+v err=%v", total, got, err)
	}
}
