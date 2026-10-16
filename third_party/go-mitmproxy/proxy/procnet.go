package proxy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Reading a socket's owning uid out of /proc/net/tcp{,6} is plain text work, so it
// lives here untagged and is unit-tested on every platform. The Linux-only file
// next to this one supplies the address that gets looked up.

// uidForLocalAddr returns the uid owning the socket bound to addr, by looking it up
// in one /proc/net/tcp* table.
//
// The table is parsed into a snapshot instead of scanned per call: that scan costs
// milliseconds when the system holds many sockets, and the transparent ingress looks
// one up per accepted connection — enough to serialise concurrent accepts (measured:
// 100 parallel connections, p50 ~1s against 3.8ms direct).
//
// A snapshot is reused only while it is fresh AND already contains the address, so a
// socket that appears after the snapshot always triggers a fresh read. Reusing an
// entry cannot mis-attribute a different socket either: the key is the local
// address, and Linux keeps a closed 4-tuple in TIME_WAIT for far longer than the
// window below, so the same address cannot come back within it.
func uidForLocalAddr(path string, addr *net.TCPAddr) (int, bool) {
	if addr == nil {
		return 0, false
	}
	want := procHexAddr(addr)
	if want == "" {
		return 0, false
	}
	v, _ := uidTables.LoadOrStore(path, &uidTable{})
	c := v.(*uidTable)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rows != nil && time.Since(c.readAt) < uidSnapshotTTL {
		if uid, ok := c.rows[want]; ok {
			return uid, true
		}
	}
	rows, err := readUIDTable(path)
	if err != nil {
		return 0, false
	}
	c.rows, c.readAt = rows, time.Now()
	uid, ok := rows[want]
	return uid, ok
}

// uidSnapshotTTL is how long a parsed table may be reused. Short on purpose: it only
// has to cover a burst of connections accepted together.
const uidSnapshotTTL = 50 * time.Millisecond

// uidTable is one parsed table plus when it was read.
type uidTable struct {
	mu     sync.Mutex
	rows   map[string]int
	readAt time.Time
}

// uidTables maps a /proc path to its snapshot.
var uidTables sync.Map

// readUIDTable parses local_address -> uid out of one table. IPv6 addresses are
// normalised the same way procHexAddr renders them, so lookups are case-insensitive
// on the address column.
func readUIDTable(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows := make(map[string]int, 256)
	sc := bufio.NewScanner(f)
	sc.Scan() // header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// sl local_address rem_address st tx:rx tr:when retrnsmt uid ...
		if len(fields) < 8 {
			continue
		}
		uid, err := strconv.Atoi(fields[7])
		if err != nil {
			continue
		}
		rows[strings.ToUpper(fields[1])] = uid
	}
	return rows, sc.Err()
}

// procHexAddr renders an address the way /proc/net/tcp{,6} does: IPv4 as
// little-endian hex, IPv6 as four little-endian 32-bit words, then the port.
func procHexAddr(a *net.TCPAddr) string {
	if a == nil {
		return ""
	}
	if ip := a.IP.To4(); ip != nil {
		return fmt.Sprintf("%02X%02X%02X%02X:%04X", ip[3], ip[2], ip[1], ip[0], a.Port)
	}
	ip := a.IP.To16()
	if ip == nil {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < 16; i += 4 {
		fmt.Fprintf(&sb, "%02X%02X%02X%02X", ip[i+3], ip[i+2], ip[i+1], ip[i])
	}
	fmt.Fprintf(&sb, ":%04X", a.Port)
	return sb.String()
}
