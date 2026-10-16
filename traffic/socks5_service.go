package traffic

import (
	"bytes"
	"encoding/binary"
	"log"
)

// Raw-TCP capture for the common database services.
//
// The SOCKS5 ingress relays anything the MITM layer cannot parse without looking
// inside, so those connections have only byte counts in the ledger. For database
// traffic that is not enough evidence: the handshake and the first statements are
// plaintext, and they are exactly what proves which account connected and what it
// asked for. The listener therefore keeps a bounded head of each direction
// (Options.Socks5CaptureBytes) for the ports below, and this file decides what
// those bytes are and stores them.
//
// Scope is deliberately narrow: only recognised database services get their heads
// persisted. Everything else stays metadata-only.

// socks5CapturePorts lists the destination ports whose heads are worth keeping —
// the default ports of the database services this recorder recognises.
var socks5CapturePorts = []int{
	3306,  // MySQL / MariaDB
	5432,  // PostgreSQL
	1433,  // Microsoft SQL Server (TDS)
	27017, // MongoDB
	6379,  // Redis
	11211, // Memcached
	1521,  // Oracle TNS
	9042,  // Cassandra CQL
	9000,  // ClickHouse native
}

// socks5CaptureHeadBytes bounds how much of each direction is kept per connection:
// 8 KiB carries a full database handshake plus the first statements and result rows,
// and stays small enough to keep inline in SQLite.
const socks5CaptureHeadBytes = 8192

// Socks5CapturePorts returns the ports the listener should capture heads for.
func Socks5CapturePorts() []int { return append([]int(nil), socks5CapturePorts...) }

const socks5BodiesSchema = `
CREATE TABLE IF NOT EXISTS socks5_bodies (
  conn_id   INTEGER PRIMARY KEY,
  service   TEXT NOT NULL DEFAULT '',
  up_head   BLOB,
  down_head BLOB
);
`

// classifySocks5Service names the database protocol behind a relayed connection,
// preferring the port and falling back to a fingerprint of the captured head so a
// service on a non-default port is still recognised. Unknown stays "" and is not
// stored.
func classifySocks5Service(port int, up, down []byte) string {
	switch port {
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	case 1433:
		return "mssql"
	case 27017:
		return "mongodb"
	case 6379:
		return "redis"
	case 11211:
		return "memcached"
	case 1521:
		return "oracle"
	case 9042:
		return "cassandra"
	case 9000:
		return "clickhouse"
	}
	// Non-default port: only a protocol fingerprint decides.
	head := down
	if len(head) > 64 {
		head = head[:64]
	}
	if len(head) > 0 && head[0] == 0x0a && bytes.ContainsRune(head, '.') {
		return "mysql" // server-first greeting: version string
	}
	if len(up) >= 8 && binary.BigEndian.Uint32(up[4:8]) == 196608 {
		return "postgres" // StartupMessage: protocol 3.0
	}
	if len(up) > 0 {
		if up[0] == '*' || up[0] == '$' || up[0] == ':' {
			return "redis" // RESP
		}
		if up[0] == 0x80 {
			return "memcached" // binary protocol magic
		}
		for _, cmd := range [][]byte{[]byte("get "), []byte("set "), []byte("stats")} {
			if bytes.HasPrefix(up, cmd) {
				return "memcached"
			}
		}
	}
	if len(down) > 0 && down[0] == 0x04 {
		return "mssql" // TDS pre-login response
	}
	if len(up) >= 16 {
		switch binary.LittleEndian.Uint32(up[12:16]) {
		case 1, 2004, 2010, 2012, 2013:
			return "mongodb"
		}
	}
	return ""
}

// recordSocks5Body stores the captured heads of one connection. Only recognised
// services are stored, which is also what keeps unrelated plaintext off disk.
func (t *Traffic) recordSocks5Body(connID int64, service string, up, down []byte) {
	if connID <= 0 || service == "" {
		return
	}
	if _, err := t.db.Exec(`INSERT OR REPLACE INTO socks5_bodies(conn_id,service,up_head,down_head)
VALUES(?,?,?,?)`, connID, service, up, down); err != nil {
		log.Printf("[traffic] socks5 正文头部写入失败（conn %d, %s）: %v", connID, service, err)
	}
}

// Socks5Body returns the captured heads of one connection, or ok=false when
// nothing was stored for it.
func (t *Traffic) Socks5Body(connID int64) (service string, up, down []byte, ok bool, err error) {
	row := t.db.QueryRow(`SELECT service,up_head,down_head FROM socks5_bodies WHERE conn_id=?`, connID)
	if err = row.Scan(&service, &up, &down); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return "", nil, nil, false, nil
		}
		return "", nil, nil, false, err
	}
	return service, up, down, true, nil
}
