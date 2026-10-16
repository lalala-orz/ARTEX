#!/bin/sh
# Transparent egress interception for the agent's uid (ARTEX).
#
# The agent's commands cannot reach a target directly: every TCP connection they
# open is redirected into the listener, which recovers the original destination
# with SO_ORIGINAL_DST and treats it exactly like an explicit CONNECT. The client
# needs no proxy configuration at all, and there is nothing to forget.
#
# Scope: the rules match locally generated traffic by socket owner, so the
# platform (root) is never touched — that is what keeps the listener's own
# upstream, the tunnel's control channel and the LLM calls working, with no
# exception list. Loopback stays open (the platform API and the listener itself
# live there); DNS needs no rule because only TCP is redirected here.
#
# Usage: egress-lockdown.sh apply|remove|status
set -e

# Agent uids: a range (per-task uids) and a single fallback (task-less agents).
RANGE="${ARTEX_AGENT_UID_RANGE:-20000-29999}"
SINGLE="${ARTEX_AGENT_UID:-1001}"
LISTENER_PORT="${ARTEX_LISTENER_PORT:-8788}"
CHAIN="ARTEX_EGRESS"

owner_match() {
	# Emits the two -m owner arguments for one uid or uid range.
	echo "-m owner --uid-owner $1"
}

apply() {
	iptables -t nat -N "$CHAIN" 2>/dev/null || true
	iptables -t nat -F "$CHAIN"
	# The listener itself must never be redirected (self-loop), then true loopback
	# is left alone: the platform API and the listener live there.
	#
	# The exemption is 127.0.0.0/8 rather than `-o lo`: Linux routes packets to any
	# local address through lo, so matching the interface would also exempt the
	# container's own non-loopback IP — a hole an agent could reach services
	# through. Matching the address keeps only real loopback out.
	iptables -t nat -A "$CHAIN" -p tcp --dport "$LISTENER_PORT" -j RETURN
	iptables -t nat -A "$CHAIN" -d 127.0.0.0/8 -j RETURN
	# Everything else the agent opens goes to the listener.
	iptables -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$LISTENER_PORT"
	for u in "$RANGE" "$SINGLE"; do
		iptables -t nat -C OUTPUT $(owner_match "$u") -j "$CHAIN" 2>/dev/null ||
			iptables -t nat -I OUTPUT 1 $(owner_match "$u") -j "$CHAIN"
	done
	echo "applied: uid $RANGE (and $SINGLE) TCP -> 127.0.0.1:$LISTENER_PORT; loopback and DNS untouched"
}

remove() {
	for u in "$RANGE" "$SINGLE"; do
		while iptables -t nat -C OUTPUT $(owner_match "$u") -j "$CHAIN" 2>/dev/null; do
			iptables -t nat -D OUTPUT $(owner_match "$u") -j "$CHAIN"
		done
	done
	iptables -t nat -F "$CHAIN" 2>/dev/null || true
	iptables -t nat -X "$CHAIN" 2>/dev/null || true
	echo "removed"
}

status() {
	echo "--- nat $CHAIN ---"
	iptables -t nat -S "$CHAIN" 2>/dev/null || { echo "not applied"; return 0; }
	echo "--- nat OUTPUT (agent hooks) ---"
	iptables -t nat -S OUTPUT | grep -- "--uid-owner" || echo "(no agent hooks)"
}

case "${1:-status}" in
apply) apply ;;
remove) remove ;;
status) status ;;
*)
	echo "usage: $0 apply|remove|status" >&2
	exit 2
	;;
esac