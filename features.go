package main

// 站点功能扩展：站内搜索 / RSS / 按日访客统计 / 自定义 slug 工具。
// 全部服务于公开前台，注意不要泄露敏感字段。

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// -------------------------- 站内搜索 --------------------------

type searchResult struct {
	Post
	Snippet string `json:"snippet,omitempty"`
}

// searchPosts GET /api/search?q=关键字
// 标题/分类/标签/摘要/正文全文匹配（大小写不敏感），返回按日期倒序的命中列表。
func searchPosts(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	results := []searchResult{}
	if q != "" {
		if metadata, err := loadMetadata(); err == nil {
			ql := strings.ToLower(q)
			posts := append([]Post{}, metadata.Posts...)
			sort.Slice(posts, func(i, j int) bool { return posts[i].Date.After(posts[j].Date) })
			for i := range posts {
				p := posts[i]
				content := ""
				if data, err := os.ReadFile(filepath.Join(postsDir, p.ID+".md")); err == nil {
					content = string(data)
				}
				matched := strings.Contains(strings.ToLower(p.Title), ql) ||
					strings.Contains(strings.ToLower(p.Category), ql) ||
					strings.Contains(strings.ToLower(p.Excerpt), ql) ||
					strings.Contains(strings.ToLower(content), ql)
				if !matched {
					for _, t := range p.Tags {
						if strings.Contains(strings.ToLower(t), ql) {
							matched = true
							break
						}
					}
				}
				if !matched {
					continue
				}
				results = append(results, searchResult{Post: p, Snippet: searchSnippet(content, q)})
				if len(results) >= 50 {
					break
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":   q,
		"total":   len(results),
		"results": results,
	})
}

// searchSnippet 从正文中截取命中位置附近的片段
// 修复（v2 审查 P0-2）：旧实现用「原文」的命中下标去切「压平空白后」的字符串，
// 命中位置靠后时 start > len(clean) 导致切片越界 panic（接口 502）。
// 现统一在压平后的字符串上定位与截取，并对边界做双重保护。
func searchSnippet(content, q string) string {
	clean := strings.Join(strings.Fields(content), " ") // 压平换行
	lower := strings.ToLower(clean)
	idx := strings.Index(lower, strings.ToLower(q))
	if idx < 0 {
		r := []rune(clean)
		if len(r) > 80 {
			return string(r[:80]) + "…"
		}
		return clean
	}
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + len(q) + 40
	if end > len(clean) {
		end = len(clean)
	}
	if start > end { // 防御：ToLower 改变字节长度等极端情形
		start = end
	}
	snippet := clean[start:end]
	if start > 0 {
		snippet = "…" + snippet
	}
	if end < len(clean) {
		snippet += "…"
	}
	return snippet
}

// -------------------------- 自动生成封面 --------------------------

// 封面渐变配色（seed 哈希挑选，同一文章颜色稳定）
var coverPalettes = [][2]string{
	{"#667eea", "#764ba2"}, {"#f093fb", "#f5576c"}, {"#4facfe", "#00f2fe"},
	{"#43e97b", "#38f9d7"}, {"#fa709a", "#fee140"}, {"#30cfd0", "#330867"},
	{"#ff9a9e", "#a18cd1"}, {"#0f2027", "#2c5364"}, {"#ee9ca7", "#ffdde1"},
	{"#2b5876", "#4e4376"},
}

// serveDefaultCover GET /api/default-cover?seed=xxx&title=yyy
// 文章未配封面时按标题生成一张渐变字卡，免去每次发文找图。
func serveDefaultCover(w http.ResponseWriter, r *http.Request) {
	title := strings.TrimSpace(r.URL.Query().Get("title"))
	seed := strings.TrimSpace(r.URL.Query().Get("seed"))
	if seed == "" {
		seed = title
	}
	if seed == "" {
		seed = "blog"
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	pair := coverPalettes[h.Sum32()%uint32(len(coverPalettes))]

	// 取标题前两个字符作为封面字（无标题则用 seed）
	runes := []rune(title)
	if len(runes) == 0 {
		runes = []rune(seed)
	}
	if len(runes) > 2 {
		runes = runes[:2]
	}
	var letter strings.Builder
	_ = xml.EscapeText(&letter, []byte(string(runes)))

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="800" height="450" viewBox="0 0 800 450">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="%s"/>
      <stop offset="1" stop-color="%s"/>
    </linearGradient>
  </defs>
  <rect width="800" height="450" fill="url(#g)"/>
  <circle cx="120" cy="380" r="180" fill="rgba(255,255,255,0.07)"/>
  <circle cx="700" cy="80" r="140" fill="rgba(255,255,255,0.09)"/>
  <circle cx="640" cy="400" r="90" fill="rgba(0,0,0,0.06)"/>
  <text x="400" y="258" dy="0.35em" text-anchor="middle" fill="rgba(255,255,255,0.94)" font-family="system-ui,-apple-system,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif" font-size="150" font-weight="700">%s</text>
</svg>`, pair[0], pair[1], letter.String())

	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=604800")
	w.Write([]byte(svg))
}

// -------------------------- RSS 订阅 --------------------------

// serveRSS GET /rss.xml —— RSS 2.0，最近 20 篇
func serveRSS(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	base := externalBaseURL(r)
	siteName := metadata.SiteName
	if siteName == "" {
		siteName = "博客"
	}
	description := metadata.Bio
	if description == "" {
		description = siteName
	}

	posts := append([]Post{}, metadata.Posts...)
	sort.Slice(posts, func(i, j int) bool { return posts[i].Date.After(posts[j].Date) })
	if len(posts) > 20 {
		posts = posts[:20]
	}

	esc := xml.EscapeText
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rss version=\"2.0\">\n<channel>\n")
	fmt.Fprintf(&b, "<title>")
	esc(&b, []byte(siteName))
	b.WriteString("</title>\n<link>")
	esc(&b, []byte(base))
	b.WriteString("</link>\n<description>")
	esc(&b, []byte(description))
	b.WriteString("</description>\n<lastBuildDate>")
	b.WriteString(time.Now().Format(time.RFC1123Z))
	b.WriteString("</lastBuildDate>\n")

	for _, p := range posts {
		link := fmt.Sprintf("%s/post/%s", base, url.PathEscape(p.Slug))
		b.WriteString("<item>\n<title>")
		esc(&b, []byte(p.Title))
		b.WriteString("</title>\n<link>")
		esc(&b, []byte(link))
		b.WriteString("</link>\n<guid>")
		esc(&b, []byte(link))
		b.WriteString("</guid>\n<pubDate>")
		b.WriteString(p.Date.Format(time.RFC1123Z))
		b.WriteString("</pubDate>\n<description>")
		esc(&b, []byte(p.Excerpt))
		b.WriteString("</description>\n</item>\n")
	}
	b.WriteString("</channel>\n</rss>")

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	w.Write([]byte(b.String()))
}

// -------------------------- 按日访客统计 --------------------------

var (
	statsFile = filepath.Join(dataDir, "stats.json")
	statsMu   sync.Mutex
)

type visitorStatsStore struct {
	Days map[string]int `json:"days"`
}

func loadStatsUnlocked() (*visitorStatsStore, error) {
	store := &visitorStatsStore{Days: map[string]int{}}
	data, err := os.ReadFile(statsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, store); err != nil {
		// 统计文件损坏不致命，重置即可
		return &visitorStatsStore{Days: map[string]int{}}, nil
	}
	if store.Days == nil {
		store.Days = map[string]int{}
	}
	return store, nil
}

// bumpDailyVisitor 记录一次访问到当天（保留最近 60 天，超出自动清理）
func bumpDailyVisitor() {
	statsMu.Lock()
	defer statsMu.Unlock()
	store, err := loadStatsUnlocked()
	if err != nil {
		return
	}
	today := time.Now().Format("2006-01-02")
	store.Days[today]++
	cutoff := time.Now().AddDate(0, 0, -60).Format("2006-01-02")
	for d := range store.Days {
		if d < cutoff {
			delete(store.Days, d)
		}
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return
	}
	_ = writeFileAtomic(statsFile, data, 0644)
}

// getVisitorStats GET /api/visitor-stats —— 最近 30 天访问量（公开）
func getVisitorStats(w http.ResponseWriter, r *http.Request) {
	statsMu.Lock()
	store, err := loadStatsUnlocked()
	statsMu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type dayCount struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	list := []dayCount{}
	for i := 29; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		list = append(list, dayCount{Date: d, Count: store.Days[d]})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"days":  list,
		"total": metadataVisitorTotal(),
	})
}

func metadataVisitorTotal() int {
	if metadata, err := loadMetadata(); err == nil {
		return metadata.VisitorCount
	}
	return 0
}

// -------------------------- 自定义 slug --------------------------

// normalizeCustomSlug 校验自定义英文 slug：仅小写字母/数字/连字符，长度 1-80
func normalizeCustomSlug(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
		if !ok {
			continue
		}
		if r == '-' {
			if lastDash {
				continue
			}
			lastDash = true
		} else {
			lastDash = false
		}
		b.WriteRune(r)
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "", fmt.Errorf("自定义链接不能为空")
	}
	if utf8.RuneCountInString(out) > 80 {
		return "", fmt.Errorf("自定义链接过长（最多80字符）")
	}
	return out, nil
}

// uniquePostSlug 保证 slug 不与其他文章冲突，冲突时追加 -2/-3…
func uniquePostSlug(metadata *Metadata, base, exceptID string) string {
	slug := base
	for n := 2; ; n++ {
		conflict := false
		for i := range metadata.Posts {
			if metadata.Posts[i].ID != exceptID && metadata.Posts[i].Slug == slug {
				conflict = true
				break
			}
		}
		if !conflict {
			return slug
		}
		slug = fmt.Sprintf("%s-%d", base, n)
	}
}

// resolvePostSlug 生成文章 slug：自定义优先，未提供则按标题生成
func resolvePostSlug(metadata *Metadata, custom, title, exceptID string) (string, error) {
	base := ""
	if strings.TrimSpace(custom) != "" {
		s, err := normalizeCustomSlug(custom)
		if err != nil {
			return "", err
		}
		base = s
	}
	if base == "" {
		base = slugify(title)
		if base == "" {
			base = "post"
		}
	}
	return uniquePostSlug(metadata, base, exceptID), nil
}
