package main

import (
	"net/http"
	"testing"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":           "1.2.3.4",
		"  1.2.3.4:8080 ":   "1.2.3.4",
		"::ffff:8.8.8.8":    "8.8.8.8",
		"[2001:db8::1]:443": "2001:db8::1",
		"2001:db8::1":       "2001:db8::1",
		`"10.0.0.1"`:        "10.0.0.1",
		"not-an-ip":         "",
		"":                  "",
	}
	for in, want := range cases {
		if got := normalizeIP(in); got != want {
			t.Errorf("normalizeIP(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsPrivateOrLocalIP(t *testing.T) {
	priv := []string{"127.0.0.1", "::1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "172.31.255.1", "100.64.1.2", "169.254.1.1"}
	pub := []string{"8.8.8.8", "114.114.114.114", "1.1.1.1", "172.217.160.1", "36.112.0.1"}
	for _, ip := range priv {
		if !isPrivateOrLocalIP(ip) {
			t.Errorf("%s should be private/local", ip)
		}
	}
	for _, ip := range pub {
		if isPrivateOrLocalIP(ip) {
			t.Errorf("%s should be public", ip)
		}
	}
}

func TestGetClientIPPrefersPublic(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "36.112.8.1, 127.0.0.1")
	r.Header.Set("X-Real-IP", "10.0.0.2")
	if got := getClientIP(r); got != "36.112.8.1" {
		t.Fatalf("got %q want public client IP", got)
	}
}

func TestJoinAndUnknown(t *testing.T) {
	if got := joinLocationParts("中国", "江苏", "南京"); got != "中国 江苏 南京" {
		t.Fatalf("join=%q", got)
	}
	if got := joinLocationParts("中国", "中国", "未知"); got != "中国" {
		t.Fatalf("dedup=%q", got)
	}
	if !isUnknownLocation("未知地区") || !isUnknownLocation("") || isUnknownLocation("江苏省 南京市") {
		t.Fatal("isUnknownLocation mismatch")
	}
	if got := stripISP("江苏省南京市 电信"); got != "江苏省南京市" {
		t.Fatalf("stripISP=%q", got)
	}
}

func TestDecodeGBKJSON(t *testing.T) {
	gb, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(`{"pro":"江苏省","city":"南京市"}`))
	if err != nil {
		t.Fatal(err)
	}
	got := decodeIPAPIBody(gb, "text/html;charset=GBK")
	if string(got) != `{"pro":"江苏省","city":"南京市"}` {
		t.Fatalf("decoded=%q", got)
	}
}

func TestRefineAndScore(t *testing.T) {
	if got := refineLocation("中国 江苏 南京"); got != "江苏省 南京市" {
		t.Fatalf("spaced=%q", got)
	}
	if got := refineLocation("中国广东省深圳市 电信"); got != "广东省 深圳市" {
		t.Fatalf("compact=%q", got)
	}
	if got := refineLocation("中国"); got != "中国" {
		t.Fatalf("country=%q", got)
	}
	if locationScore("中国") != 1 || locationScore("江苏省 南京市") < 4 {
		t.Fatal("score mismatch")
	}
	if !needsBetterLocation("中国") || needsBetterLocation("江苏省 南京市") {
		t.Fatal("needsBetterLocation mismatch")
	}
}

func TestLiveLookupSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skip live lookup")
	}
	loc := resolveIPLocation("114.114.114.114")
	t.Log("114.114.114.114 =>", loc)
	if isUnknownLocation(loc) {
		t.Fatal("expected a real location from at least one provider")
	}
	if locationScore(loc) < 3 {
		t.Fatalf("expected province/city, got %q", loc)
	}
	loc2 := resolveIPLocation("8.8.8.8")
	t.Log("8.8.8.8 =>", loc2)
	if isUnknownLocation(loc2) {
		t.Fatal("8.8.8.8 should resolve")
	}
}

func TestDisplayLocation(t *testing.T) {
	if got := displayLocation("江苏省 南京市", ""); got != "江苏省 南京市" {
		t.Fatalf("keep stored: %q", got)
	}
	if got := displayLocation("", ""); got != "未知地区" {
		t.Fatalf("empty: %q", got)
	}
	storeIPLocCache("8.8.8.8", "美国 弗吉尼亚", 24*time.Hour)
	if got := displayLocation("未知地区", "8.8.8.8"); got != "美国 弗吉尼亚" {
		t.Fatalf("cache peek: %q", got)
	}
}
