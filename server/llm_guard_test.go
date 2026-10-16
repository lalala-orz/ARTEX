package server

import "testing"

// "别打 LLM 网关"这条保护必须比到端口：本次实盘就遇到同一台机器 39.98.119.49:80 是网关、
// :18080 是待测靶场；只比 host 会把靶场一起挡掉（连 scope 都建不出来，任务等于空跑）。
func TestIsLLMGatewayTarget(t *testing.T) {
	const gwHost = "39.98.119.49"
	const gwPort = 80
	cases := []struct {
		host string
		port int
		want bool
	}{
		{gwHost, 80, true},     // 网关本身：挡
		{gwHost, 18080, false}, // 同主机其它端口（靶场）：放行
		{gwHost, 443, false},
		{"example.com", 80, false},
		{"", 80, false},
	}
	for _, c := range cases {
		if got := isLLMGatewayTarget(gwHost, gwPort, c.host, c.port); got != c.want {
			t.Errorf("isLLMGatewayTarget(%s:%d) = %v，想要 %v", c.host, c.port, got, c.want)
		}
	}
	// 没配置网关（或解析不出来）时不该误挡任何东西。
	if isLLMGatewayTarget("", 0, gwHost, 80) {
		t.Error("未配置网关时不应拦截")
	}
	if isLLMGatewayTarget(gwHost, 0, gwHost, 80) {
		t.Error("端口未知时不应拦截")
	}
	// 大小写不敏感
	if !isLLMGatewayTarget("Example.COM", 80, "example.com", 80) {
		t.Error("host 比较应当大小写不敏感")
	}
}
