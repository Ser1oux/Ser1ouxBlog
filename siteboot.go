package main

import (
	"bytes"
	"encoding/json"
	"html"
	"log"
	"mime"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
)

type siteBootstrap struct {
	SiteName         string `json:"siteName"`
	Nickname         string `json:"nickname,omitempty"`
	Bio              string `json:"bio,omitempty"`
	Avatar           string `json:"avatar,omitempty"`
	CustomBackground string `json:"customBackground,omitempty"`
	Notice           string `json:"notice,omitempty"`
}

var (
	bgSrcByID = regexp.MustCompile(`(<img\b[^>]*\bid="bgImage"[^>]*\bsrc=")(/BG/BG\.jpg)(")`)
	bgIDBySrc = regexp.MustCompile(`(<img\b[^>]*\bsrc=")(/BG/BG\.jpg)("[^>]*\bid="bgImage")`)
)

func loadSiteBootstrap() siteBootstrap {
	boot := siteBootstrap{SiteName: "博客"}
	meta, err := loadMetadata()
	if err != nil || meta == nil {
		return boot
	}
	if name := strings.TrimSpace(meta.SiteName); name != "" {
		boot.SiteName = name
	}
	boot.Nickname = strings.TrimSpace(meta.Nickname)
	boot.Bio = strings.TrimSpace(meta.Bio)
	boot.Avatar = strings.TrimSpace(meta.Avatar)
	boot.CustomBackground = strings.TrimSpace(meta.CustomBackground)
	boot.Notice = strings.TrimSpace(meta.Notice)
	return boot
}

func applySiteBootstrap(raw []byte) []byte {
	boot := loadSiteBootstrap()
	return applySiteBootstrapWith(raw, boot)
}

func applySiteBootstrapWith(raw []byte, boot siteBootstrap) []byte {
	name := strings.TrimSpace(boot.SiteName)
	if name == "" {
		name = "博客"
	}
	esc := html.EscapeString(name)

	repls := [][2]string{
		{"<title>Ser1oux-Blog - 极简博客</title>", "<title>" + esc + "</title>"},
		{"<title>文章归档 - Ser1oux-Blog</title>", "<title>文章归档 - " + esc + "</title>"},
		{"<title>关于 - Ser1oux-Blog</title>", "<title>关于 - " + esc + "</title>"},
		{"<title>留言板 - Ser1oux-Blog</title>", "<title>留言板 - " + esc + "</title>"},
		{"<title>登录 - Ser1oux-Blog</title>", "<title>登录 - " + esc + "</title>"},
		{"<title>找回密码 - Ser1oux-Blog</title>", "<title>找回密码 - " + esc + "</title>"},
		{"<title>个人中心 - Ser1oux-Blog</title>", "<title>个人中心 - " + esc + "</title>"},
		{`<title id="pageTitle">文章详情 - Ser1oux-Blog</title>`, `<title id="pageTitle">文章详情 - ` + esc + `</title>`},
		{"<title>文章管理 - Ser1oux-Blog</title>", "<title>文章管理 - " + esc + "</title>"},
		{"<title>附件管理 - Ser1oux-Blog</title>", "<title>附件管理 - " + esc + "</title>"},
		{"<title>设置 - Ser1oux-Blog</title>", "<title>设置 - " + esc + "</title>"},
		{"<title>管理后台 - Ser1oux-Blog</title>", "<title>管理后台 - " + esc + "</title>"},
		{`<span id="siteName">Ser1oux-Blog</span>`, `<span id="siteName">` + esc + `</span>`},
		{`<span id="siteName">Ser1oux-Blog 管理</span>`, `<span id="siteName">` + esc + `</span>`},
	}
	out := raw
	for _, pair := range repls {
		out = bytes.ReplaceAll(out, []byte(pair[0]), []byte(pair[1]))
	}
	// 规则是按字面量匹配的：模板一改就可能静默失效。这里显式检查占位符，
	// 让品牌名替换失败能在日志里被发现，而不是悄悄保持默认值。
	if bytes.Contains(out, []byte(`<span id="siteName">Ser1oux-Blog`)) {
		log.Printf("[template] siteName 占位符未被替换，siteboot 规则与模板可能已失配")
	}

	if nick := strings.TrimSpace(boot.Nickname); nick != "" {
		out = bytes.ReplaceAll(out,
			[]byte(`id="profileNickname">博主昵称</div>`),
			[]byte(`id="profileNickname">`+html.EscapeString(nick)+`</div>`),
		)
	}
	if notice := strings.TrimSpace(boot.Notice); notice != "" {
		out = bytes.ReplaceAll(out,
			[]byte(`id="noticeContent">欢迎来到我的博客！</div>`),
			[]byte(`id="noticeContent">`+html.EscapeString(notice)+`</div>`),
		)
	}

	if bg := strings.TrimSpace(boot.CustomBackground); bg != "" {
		escBG := html.EscapeString(bg)
		out = bgSrcByID.ReplaceAll(out, []byte(`${1}`+escBG+`${3}`))
		out = bgIDBySrc.ReplaceAll(out, []byte(`${1}`+escBG+`${3}`))
	}

	payload, err := json.Marshal(boot)
	if err != nil {
		return out
	}
	inject := []byte("\n<script>window.__SITE_BOOTSTRAP__=" + string(payload) +
		`;window.siteDisplayName=function(s){s=s||{};var b=window.__SITE_BOOTSTRAP__||{};return (s.siteName||b.siteName||"博客");};</script>` + "\n")
	out = bytes.Replace(out, []byte("</head>"), append(inject, []byte("</head>")...), 1)
	out = bytes.Replace(out, []byte("</body>"), append([]byte(notifyWidgetHTML), []byte("</body>")...), 1)
	return out
}

func writeHTMLPage(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Write(applySiteBootstrap(raw))
}

func serveEmbedded(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFiles.ReadFile(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(strings.ToLower(path), ".html") {
		writeHTMLPage(w, data)
		return
	}
	// 不用 ServeContent：它会按原始长度写 Content-Length，
	// 而外层 gzip 中间件会改变响应长度。直接 Write 交给 net/http 分块发送。
	if ct := mime.TypeByExtension(filepath.Ext(path)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
}
