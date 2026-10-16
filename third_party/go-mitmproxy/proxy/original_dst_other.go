//go:build !linux

package proxy

import "net"

// transparentTarget and peerUID are Linux-only (netfilter SO_ORIGINAL_DST and
// SO_PEERCRED). Elsewhere transparent interception is unavailable, so the
// listener only serves explicit clients.
func transparentTarget(net.Conn) (string, int, bool) { return "", 0, false }

func peerUID(net.Conn) int { return 0 }
