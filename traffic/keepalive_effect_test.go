package traffic

import "testing"

// A1 的修复只有在"标志真的落到监听器的 transport 选项上"时才算数：槽位受限的出口
// 一旦还有上游连接池，空闲连接就会一直占着隧道名额，直到对端超时 —— 表现就是
// "发几次之后隧道再也连不上"。这里直接断言那个 atomic 开关，而不只是判定的布尔值。
func TestSyncUpstreamKeepAliveFollowsTunnelEgress(t *testing.T) {
	tr, _ := openTraffic(t)
	if tr.proxy == nil || tr.proxy.Opts == nil {
		t.Fatal("测试前提：Open 应当建好 proxy 与 Opts")
	}
	opt := &tr.proxy.Opts.DisableUpstreamKeepAlive
	if opt.Load() {
		t.Fatal("默认（无隧道）不应关闭上游复用")
	}
	tun := &fakeEgressDialer{tunnel: true}
	plain := &fakeEgressDialer{}

	tr.applyEgress(&egress{dialer: tun, label: tun.Describe()})
	if !opt.Load() {
		t.Fatal("默认出口是隧道 ⇒ 必须关闭上游复用（否则空闲连接占死名额）")
	}
	tr.applyEgress(&egress{dialer: plain, label: plain.Describe()})
	if opt.Load() {
		t.Fatal("换回普通出口 ⇒ 应当恢复连接复用")
	}
	// 任务隧道走的正是身份这条路：必须同样生效。
	tr.SetIdentityEgress("taskZ", "tokZ", 7, tun)
	if !opt.Load() {
		t.Fatal("身份级隧道也必须关闭上游复用")
	}
	tr.SetIdentityEgress("taskZ", "tokZ", 7, nil)
	if opt.Load() {
		t.Fatal("身份解除绑定后应当恢复复用")
	}
	// 没有任何出口时也不该 panic（构造期路径）。
	tr.applyEgress(nil)
	if opt.Load() {
		t.Fatal("清空出口后应当恢复复用")
	}
}
