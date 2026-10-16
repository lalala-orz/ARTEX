package traffic

import (
	"context"
	"errors"
	"net"
	"testing"
)

type fakeEgressDialer struct{ tunnel bool }

func (f *fakeEgressDialer) Describe() string { return "fake:egress" }
func (f *fakeEgressDialer) Dial(context.Context, string) (net.Conn, error) {
	return nil, errors.New("fake")
}
func (f *fakeEgressDialer) TunnelEgress() bool { return f.tunnel }

// 槽位受限的出口（隧道）绝不能被上游连接池占着：空闲连接会一直握着隧道的并发名额，
// 直到对端超时，表现就是"发几次之后隧道再也连不上"。
func TestHasTunnelEgress(t *testing.T) {
	tun := &fakeEgressDialer{tunnel: true}
	plain := &fakeEgressDialer{}

	tr := &Traffic{}
	if tr.hasTunnelEgress() {
		t.Fatal("没有任何出口时不应判定为隧道")
	}
	tr.applyEgress(&egress{dialer: plain, label: plain.Describe()})
	if tr.hasTunnelEgress() {
		t.Fatal("普通出口不应判定为隧道")
	}
	tr.applyEgress(&egress{dialer: tun, label: tun.Describe()})
	if !tr.hasTunnelEgress() {
		t.Fatal("隧道出口必须被识别（否则连接池会吃掉并发名额）")
	}
	// 默认出口是普通出口、但某个身份绑了隧道时，也必须判定为隧道。
	tr.applyEgress(&egress{dialer: plain, label: plain.Describe()})
	tr.identities.Store("task1", &identityEgress{token: "t", taskID: 1, egress: &egress{dialer: tun, label: tun.Describe()}})
	if !tr.hasTunnelEgress() {
		t.Fatal("身份级隧道出口也必须被识别")
	}
	// proxy 为 nil 时不能 panic（构造期的调用路径）。
	tr.syncUpstreamKeepAlive()
}
