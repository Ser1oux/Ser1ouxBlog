package main

import (
	"strings"
	"testing"
)

func TestApplySiteBootstrapReplacesDefaults(t *testing.T) {
	raw := []byte(`<!DOCTYPE html><html><head>
<title>Ser1oux-Blog - 极简博客</title>
</head><body>
<span id="siteName">Ser1oux-Blog</span>
<div class="profile-nickname" id="profileNickname">博主昵称</div>
<div class="notice-content" id="noticeContent">欢迎来到我的博客！</div>
<img class="bg-image" id="bgImage" src="/BG/BG.jpg" alt="背景">
</body></html>`)

	out := string(applySiteBootstrapWith(raw, siteBootstrap{
		SiteName:         "ser1oux-blog",
		Nickname:         "Ser1oux",
		Notice:           "今天天气不错",
		CustomBackground: "/uploads/mybg.jpg",
	}))

	if strings.Contains(out, "Ser1oux-Blog") {
		t.Fatal("default Ser1oux-Blog still present:\n", out)
	}
	if !strings.Contains(out, "<title>ser1oux-blog</title>") {
		t.Fatal("title not replaced:", out)
	}
	if !strings.Contains(out, `<span id="siteName">ser1oux-blog</span>`) {
		t.Fatal("nav name not replaced")
	}
	if !strings.Contains(out, "Ser1oux") {
		t.Fatal("nickname not injected")
	}
	if !strings.Contains(out, "今天天气不错") {
		t.Fatal("notice not injected")
	}
	if !strings.Contains(out, `src="/uploads/mybg.jpg"`) {
		t.Fatal("background not injected:", out)
	}
	if !strings.Contains(out, `window.__SITE_BOOTSTRAP__`) {
		t.Fatal("bootstrap script missing")
	}
	if !strings.Contains(out, `"siteName":"ser1oux-blog"`) {
		t.Fatal("bootstrap json missing siteName")
	}
}

func TestApplySiteBootstrapEscapesHTML(t *testing.T) {
	raw := []byte(`<html><head><title>Ser1oux-Blog - 极简博客</title></head><body><span id="siteName">Ser1oux-Blog</span></body></html>`)
	out := string(applySiteBootstrapWith(raw, siteBootstrap{SiteName: `<script>x</script>`}))
	if !strings.Contains(out, `<span id="siteName">&lt;script&gt;x&lt;/script&gt;</span>`) {
		t.Fatal("site name not escaped in html:", out)
	}
}
