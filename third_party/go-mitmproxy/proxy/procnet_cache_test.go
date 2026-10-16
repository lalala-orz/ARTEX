package proxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The transparent ingress looks a peer's uid up once per accepted connection, so the
// lookup must not re-scan /proc/net/tcp* every time — that scan serialised concurrent
// accepts (100 parallel connections, p50 ~1s). It must also never answer from a stale
// snapshot for an address the snapshot does not contain.
func TestUIDForLocalAddrSnapshotCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	a := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	b := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40001}

	write := func(uidA int, uidB int) {
		body := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
		body += fmt.Sprintf("   0: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %d 0 0\n", procHexAddr(a), uidA)
		if uidB > 0 {
			body += fmt.Sprintf("   1: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %d 0 0\n", procHexAddr(b), uidB)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	expire := func() {
		v, ok := uidTables.Load(path)
		if !ok {
			t.Fatal("快照未建立")
		}
		c := v.(*uidTable)
		c.mu.Lock()
		c.readAt = time.Now().Add(-time.Second)
		c.mu.Unlock()
	}

	write(20000, 0)
	if uid, ok := uidForLocalAddr(path, a); !ok || uid != 20000 {
		t.Fatalf("首次查找 = (%d,%v)，想要 (20000,true)", uid, ok)
	}
	// Fresh snapshot that already contains the address: served from memory, so a
	// change on disk is not observed yet.
	write(20001, 0)
	if uid, ok := uidForLocalAddr(path, a); !ok || uid != 20000 {
		t.Fatalf("快照期内应复用，得到 (%d,%v)", uid, ok)
	}
	// Expired: re-read.
	expire()
	if uid, ok := uidForLocalAddr(path, a); !ok || uid != 20001 {
		t.Fatalf("过期后应重读，得到 (%d,%v)", uid, ok)
	}
	// An address the snapshot does not contain must never be answered from cache:
	// a socket that appears later always gets a fresh read.
	write(20001, 30000)
	if uid, ok := uidForLocalAddr(path, b); !ok || uid != 30000 {
		t.Fatalf("快照里没有的新地址必须重读，得到 (%d,%v)", uid, ok)
	}
	if uid, ok := uidForLocalAddr(path, a); !ok || uid != 20001 {
		t.Fatalf("重读后 a 应为 20001，得到 (%d,%v)", uid, ok)
	}
}
