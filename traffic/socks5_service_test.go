package traffic

import (
	"bytes"
	"path/filepath"
	"testing"
)

// 服务识别：端口优先，非默认端口靠指纹；认不出就存元数据、不存正文。
func TestClassifySocks5Service(t *testing.T) {
	cases := []struct {
		name string
		port int
		up   []byte
		down []byte
		want string
	}{
		{"mysql 默认端口", 3306, nil, []byte{0x0a, '5', '.', '6', '.', '9'}, "mysql"},
		{"postgres 默认端口", 5432, nil, nil, "postgres"},
		{"mssql 默认端口", 1433, nil, nil, "mssql"},
		{"mongodb 默认端口", 27017, nil, nil, "mongodb"},
		{"redis 默认端口", 6379, nil, nil, "redis"},
		{"memcached 默认端口", 11211, nil, nil, "memcached"},
		{"mysql 指纹（服务端先说的版本串）", 13306, nil, []byte{0x0a, '8', '.', '0', '.', '3', '0', 0x00}, "mysql"},
		{"postgres 指纹（StartupMessage 196608）", 15432, []byte{0, 0, 0, 8, 0, 3, 0, 0}, nil, "postgres"},
		{"redis 指纹（RESP 数组）", 16379, []byte("*2\r\n$4\r\nAUTH\r\n"), nil, "redis"},
		{"memcached 指纹（文本 get）", 21211, []byte("get foo\r\n"), nil, "memcached"},
		{"mssql 指纹（TDS pre-login 0x04）", 11433, nil, []byte{0x04, 0x00, 0x00, 0x2b}, "mssql"},
		{"mongodb 指纹（opcode 2013）", 37017, append(make([]byte, 12), 0xdd, 0x07, 0, 0), nil, "mongodb"},
		{"ssh 不该被认成数据库", 2222, []byte("SSH-2.0-OpenSSH_8.9\r\n"), []byte("SSH-2.0-x\r\n"), ""},
		{"未知端口且无指纹", 9999, []byte("PING\r\n"), []byte("+PONG\r\n"), ""},
	}
	for _, c := range cases {
		if got := classifySocks5Service(c.port, c.up, c.down); got != c.want {
			t.Errorf("%s: classify(%d) = %q，想要 %q", c.name, c.port, got, c.want)
		}
	}
}

// 只有识别出的数据库服务才落正文；未识别的一律只留元数据。
func TestRecordSocks5BodyOnlyForKnownService(t *testing.T) {
	dir := t.TempDir()
	tr, err := Open(filepath.Join(dir, "traffic"), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	up := []byte("select user,password from mysql.user")
	down := []byte{0x0a, '5', '.', '6', '.', '9'}

	tr.recordSocks5Conn(Socks5Conn{TS: 1, ListenerID: GlobalListenerID, DstHost: "127.0.0.1", DstPort: 3306,
		BytesUp: int64(len(up)), BytesDown: int64(len(down)), Service: "mysql", HeadUp: up, HeadDown: down})
	tr.recordSocks5Conn(Socks5Conn{TS: 2, ListenerID: GlobalListenerID, DstHost: "127.0.0.1", DstPort: 9999,
		BytesUp: 3, BytesDown: 3, Service: "", HeadUp: []byte("abc"), HeadDown: []byte("def")})

	rows, total, err := tr.Socks5Conns("", 0, 10)
	if err != nil || total != 2 {
		t.Fatalf("账本行数 = %d (err=%v)，想要 2", total, err)
	}
	var mysqlID int64
	for _, r := range rows {
		if r.DstPort == 3306 {
			mysqlID = r.ID
			if r.Service != "mysql" {
				t.Fatalf("service = %q，想要 mysql", r.Service)
			}
		} else if r.Service != "" {
			t.Fatalf("未识别服务却记了 service=%q", r.Service)
		}
	}
	if mysqlID == 0 {
		t.Fatal("没找到 MySQL 那条")
	}
	svc, gotUp, gotDown, ok, err := tr.Socks5Body(mysqlID)
	if err != nil || !ok {
		t.Fatalf("读正文失败 ok=%v err=%v", ok, err)
	}
	if svc != "mysql" || !bytes.Equal(gotUp, up) || !bytes.Equal(gotDown, down) {
		t.Fatalf("正文对不上: service=%q up=%q down=%q", svc, gotUp, gotDown)
	}
	for _, r := range rows {
		if r.DstPort == 9999 {
			if _, _, _, ok, _ := tr.Socks5Body(r.ID); ok {
				t.Fatal("未识别的连接竟然存了正文")
			}
		}
	}
}
