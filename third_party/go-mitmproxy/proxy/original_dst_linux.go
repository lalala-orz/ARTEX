//go:build linux

package proxy

import (
	"net"
	"syscall"
	"unsafe"
)

// soOriginalDst is the getsockopt name netfilter uses to report the address a
// connection was redirected from; the syscall package does not export it.
const soOriginalDst = 80

// getsockopt wraps the raw syscall so both helpers below can share it.
func getsockopt(fd, level, opt uintptr, val unsafe.Pointer, len *uint32) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, level, opt,
		uintptr(val), uintptr(unsafe.Pointer(len)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// transparentTarget reports the address a redirected connection was aimed at.
// ok is false when the kernel holds no NAT mapping for it (the client dialled the
// listener directly) or when the mapping points at the listener itself, which is
// what a direct connection looks like from here.
func transparentTarget(conn net.Conn) (host string, port int, ok bool) {
	tcp, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return "", 0, false
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return "", 0, false
	}
	var (
		sa   syscall.RawSockaddrInet4
		alen = uint32(unsafe.Sizeof(sa))
		serr error
	)
	if cerr := raw.Control(func(fd uintptr) {
		serr = getsockopt(fd, syscall.SOL_IP, soOriginalDst, unsafe.Pointer(&sa), &alen)
	}); cerr != nil || serr != nil {
		return "", 0, false
	}
	if sa.Family != syscall.AF_INET {
		return "", 0, false
	}
	host = net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]).String()
	port = int(uint16(sa.Port)>>8 | uint16(sa.Port)<<8)
	// A direct connection reports the listener's own address, so nothing was
	// redirected: treat it as a normal client.
	if la, isTCPAddr := conn.LocalAddr().(*net.TCPAddr); isTCPAddr && la.Port == port && la.IP.String() == host {
		return "", 0, false
	}
	return host, port, true
}

// peerUID returns the uid that opened the other end of this connection, which is
// how a redirected connection is attributed to the task that started it.
//
// SO_PEERCRED looks like the obvious source, but on Linux it only carries
// credentials for AF_UNIX sockets: over TCP it reports uid -1 (measured on the
// deployment target). The kernel does record the owner of every TCP socket, so the
// client's socket is found in /proc/net/tcp{,6} and its uid column read back.
//
// The client is matched by its *local* address: its socket still names the pre-NAT
// destination, so only that address is unique to it.
func peerUID(conn net.Conn) int {
	peer, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if uid, found := uidForLocalAddr(table, peer); found {
			return uid
		}
	}
	return 0
}
