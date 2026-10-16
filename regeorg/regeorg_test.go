package regeorg

import (
	"bytes"
	"strings"
	"testing"
)

// TunnelChars 必须是标准字母表的**真置换**：少一个字符，载荷的 strtr 就会把某些字节
// 原样透传，编码出来的请求体谁也解不开。
func TestTunnelCharsIsPermutation(t *testing.T) {
	if len(TunnelChars) != len(Base64Chars) {
		t.Fatalf("TunnelChars 长度 = %d，想要 %d", len(TunnelChars), len(Base64Chars))
	}
	seen := map[rune]int{}
	for _, c := range TunnelChars {
		seen[c]++
	}
	for _, c := range Base64Chars {
		if seen[c] != 1 {
			t.Errorf("字符 %q 在 TunnelChars 里出现 %d 次，想要 1 次", c, seen[c])
		}
		delete(seen, c)
	}
	for c, n := range seen {
		t.Errorf("TunnelChars 多出字符 %q（%d 次）", c, n)
	}
}

// BLV 编解码必须互补，包括空值与跨过长度偏移的大值。
func TestBLVRoundTrip(t *testing.T) {
	for i, in := range []map[byte][]byte{
		{FieldCmd: []byte(CmdRead), FieldMark: []byte("abc")},
		{FieldData: []byte{}, FieldCmd: []byte(CmdForward)},
		{FieldData: bytes.Repeat([]byte("x"), 70000)}, // 大值：长度字段不能截断
	} {
		raw := blvEncode(in)
		out, err := blvDecode(raw)
		if err != nil {
			t.Fatalf("case %d 解码失败: %v", i, err)
		}
		for k, v := range in {
			if !bytes.Equal(out[k], v) {
				t.Fatalf("case %d 字段 %d 不一致: %d 字节 vs %d 字节", i, k, len(out[k]), len(v))
			}
		}
	}
}

// 请求体的编码/解码必须互补：客户端编的，服务端能解；服务端编的（含垃圾字段），客户端能解。
func TestBodyRoundTrip(t *testing.T) {
	in := map[byte][]byte{
		FieldCmd:  []byte(CmdConnect),
		FieldMark: []byte("NeoMark/123"),
		FieldIP:   []byte("10.1.1.5"),
		FieldPort: []byte("3306"),
	}
	out, err := DecodeBody(EncodeBody(in))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range in {
		if !bytes.Equal(out[k], v) {
			t.Errorf("字段 %d 不一致: %q vs %q", k, out[k], v)
		}
	}
}

// 载荷的应答可能带换行、'=' 可能被去掉、前面可能有空白——解码器必须像 PHP/Python 那样宽容。
//
// 注意这里**不**模拟"伪装页面"：我们的生成参数不启用伪装（USE_REQUEST_TEMPLATE=0，载荷
// 直接吐变形 base64），而一旦启用伪装，HTML 片段里的字符本身就在 base64 字母表内，光靠
// 过滤是救不回来的——上游是用 --cut-left/--cut-right/--extract 精确裁剪。真要用伪装，
// 客户端得把那套裁剪也实现，不能只靠这里。
func TestDecodeBodyIsLenient(t *testing.T) {
	body := EncodeBody(map[byte][]byte{FieldStatus: []byte(StatusOK), FieldData: []byte("hello")})
	messy := "\r\n  " + strings.TrimRight(body, "=") + "  \n"
	out, err := DecodeBody(messy)
	if err != nil {
		t.Fatalf("宽容解码失败: %v", err)
	}
	if string(out[FieldStatus]) != StatusOK || string(out[FieldData]) != "hello" {
		t.Fatalf("解码结果不对: %q / %q", out[FieldStatus], out[FieldData])
	}
	if _, err := DecodeBody("   \n"); err == nil {
		t.Fatal("空内容应当报错")
	}
}

// 生成器必须把参数都替换掉：留下任何占位符，投放出去的载荷就是坏的。
func TestGenerateSubstitutesEveryParameter(t *testing.T) {
	for _, kind := range Kinds() {
		src, p, err := Generate(kind)
		if err != nil {
			t.Fatalf("%s 生成失败: %v", kind, err)
		}
		if p.Name == "" || p.Deploy == "" || len(src) == 0 {
			t.Errorf("%s 的载荷信息不完整: %+v", kind, p)
		}
		text := string(src)
		for _, leftover := range []string{
			"BASE64 CHARSLIST", "BLV_L_OFFSET", "HTTPCODE", "READBUF", "MAXREADSIZE",
			"USE_REQUEST_TEMPLATE", "START_INDEX", "END_INDEX",
			"NeoGeorg says, 'All seems fine'",
		} {
			if strings.Contains(text, leftover) {
				t.Errorf("%s 里还留着未替换的占位符 %q", kind, leftover)
			}
		}
		// 除 java（参数由加载方传入）之外，都必须带上我们的字母表与探活串。
		if kind != "java" {
			if !strings.Contains(text, TunnelChars) {
				t.Errorf("%s 没有替换进 TunnelChars", kind)
			}
			if !strings.Contains(text, Hello) {
				t.Errorf("%s 没有替换进 Hello", kind)
			}
		}
	}
}

// HelloBytes 必须解得出**非空**内容：一旦为空，客户端那侧 bytes.Contains(body, nil) 恒为真，
// "载荷应答对不对"的探活就永远通过——这是个会静默废掉校验的坑，必须钉住。
func TestHelloBytesIsNotEmpty(t *testing.T) {
	if got := HelloBytes(); len(got) == 0 {
		t.Fatal("HelloBytes 为空：探活校验会形同虚设")
	}
}

// java 模板是内存马类：en/de/HTTPCODE 由**加载方传参**（args[2..4]），不是能直接投放的文件。
// 这条测试把该事实钉住，免得以后有人以为生成出来的 .java 可以直接用。
func TestJavaTemplateTakesParamsAtLoadTime(t *testing.T) {
	src, p, err := Generate("java")
	if err != nil {
		t.Fatal(err)
	}
	if p.Deploy != "compile-inject" {
		t.Errorf("java 的投放方式 = %q，想要 compile-inject", p.Deploy)
	}
	text := string(src)
	if strings.Contains(text, TunnelChars) {
		t.Error("java 模板不该包含字母表字面量")
	}
	if !strings.Contains(text, "args[2]") || !strings.Contains(text, "args[3]") {
		t.Error("java 模板应当从 args 里取 en/de")
	}
}

// 前缀噪声不能把解码打死。PHP 5.6 默认会先吐一段 Deprecated 的 HTML 警告（实测就是这样把
// 应答顶成"字段 62 长度 9 亿"的），它的字母和 "/" 都在 base64 字母表里，过滤不掉，只能靠
// "逐字节偏移重试 + 必须带 STATUS" 找回真实帧。
func TestDecodeBodySkipsPrefixNoise(t *testing.T) {
	want := map[byte][]byte{
		FieldStatus: []byte(StatusOK),
		FieldData:   []byte("hello world"),
	}
	encoded := EncodeBody(want)

	noise := "<br />\n<b>Deprecated</b>:  Automatically populating $HTTP_RAW_POST_DATA is " +
		"deprecated and will be removed in a future version of PHP\n<br />\n"

	got, err := DecodeBody(noise + encoded)
	if err != nil {
		t.Fatalf("带前缀噪声时解码失败: %v", err)
	}
	if string(got[FieldStatus]) != StatusOK || string(got[FieldData]) != "hello world" {
		t.Fatalf("解出来的字段不对: %q / %q", got[FieldStatus], got[FieldData])
	}

	// 无噪声时行为必须完全不变。
	plain, err := DecodeBody(encoded)
	if err != nil {
		t.Fatalf("无噪声时解码失败: %v", err)
	}
	if string(plain[FieldStatus]) != StatusOK || string(plain[FieldData]) != "hello world" {
		t.Fatalf("无噪声时字段不对: %q / %q", plain[FieldStatus], plain[FieldData])
	}
}
