package traffic

import (
	"fmt"
	"os"
	"testing"
)

// Recording runs on the response path, so it must be asynchronous: a synchronous
// write serialised concurrent responses behind one lock. This locks in both halves
// of the contract — FlushRecords makes an enqueued exchange observable, and closing
// drains the queue instead of dropping what was already accepted.
func TestRecordingIsAsyncAndDrainsOnClose(t *testing.T) {
	dir, err := os.MkdirTemp("", "artex-async-rec-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	tr, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		if err := tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n); err != nil {
			t.Fatalf("计数: %v", err)
		}
		return n
	}
	base := count()
	for i := 0; i < 25; i++ {
		tr.enqueue(newFlow("async.example.com", "GET", fmt.Sprintf("/i/%d", i), nil, []byte("x")))
	}
	tr.FlushRecords()
	if got := count() - base; got != 25 {
		t.Fatalf("FlushRecords 后应新增 25 条，实际 %d", got)
	}
	// Accepted but not flushed: stopRecords (via Close) must still persist it.
	tr.enqueue(newFlow("async.example.com", "GET", "/last", nil, []byte("y")))
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := reopened.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
	if n-base != 26 {
		t.Fatalf("Close 应排空队列（新增 26），磁盘上读到 %d", n-base)
	}
}
