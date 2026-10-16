package proxy

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// /proc/net/tcp 的地址是小端十六进制、端口在后；匹配靠这个格式，写错就永远认不出人。
func TestProcHexAddr(t *testing.T) {
	cases := []struct {
		ip   string
		port int
		want string
	}{
		{"127.0.0.1", 8788, "0100007F:2254"},
		{"172.20.0.3", 3306, "030014AC:0CEA"},
		{"0.0.0.0", 0, "00000000:0000"},
	}
	for _, c := range cases {
		if got := procHexAddr(&net.TCPAddr{IP: net.ParseIP(c.ip), Port: c.port}); got != c.want {
			t.Errorf("procHexAddr(%s:%d) = %q, 想要 %q", c.ip, c.port, got, c.want)
		}
	}
	if procHexAddr(nil) != "" {
		t.Error("nil 地址应返回空串")
	}
}

// 客户端 socket 的 local 地址唯一决定它的 uid —— 这是 SO_PEERCRED 在 TCP 上失效后的退路。
func TestUIDForLocalAddr(t *testing.T) {
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2254 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0          0 12345 1 0000000000000000 100 0 0 10 0
   1: 030014AC:0CEA 0100007F:2254 01 00000000:00000000 00:00000000 00000000  20000      0 12346 1 0000000000000000 100 0 0 10 0
`
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	if err := os.WriteFile(path, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	uid, ok := uidForLocalAddr(path, &net.TCPAddr{IP: net.ParseIP("172.20.0.3"), Port: 3306})
	if !ok || uid != 20000 {
		t.Fatalf("uidForLocalAddr = (%d, %v), 想要 (20000, true)", uid, ok)
	}
	if _, ok := uidForLocalAddr(path, &net.TCPAddr{IP: net.ParseIP("10.9.9.9"), Port: 1}); ok {
		t.Fatal("不存在的地址不该匹配到任何 uid")
	}
	if _, ok := uidForLocalAddr(filepath.Join(dir, "nope"), &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}); ok {
		t.Fatal("读不到表时应返回 false")
	}
}
