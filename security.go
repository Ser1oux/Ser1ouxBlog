package main

import (
	"compress/gzip"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// writeJSON 统一 JSON 响应：固定 Content-Type 与状态码。
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// 密码策略
// ---------------------------------------------------------------------------

// minPasswordLen 所有设置/修改密码的入口统一使用该下限。
const minPasswordLen = 8

var errPasswordTooShort = fmt.Errorf("密码至少 %d 位", minPasswordLen)

// validateNewPassword 校验新密码强度。仅在服务端生效，前端 minlength 只作提示。
func validateNewPassword(pw string) error {
	n := len([]rune(pw))
	if n < minPasswordLen {
		return errPasswordTooShort
	}
	if n > 200 {
		return errors.New("密码过长")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 首次初始化口令
// ---------------------------------------------------------------------------

var (
	setupTokenMu sync.RWMutex
	setupToken   string
	// setupMu 串行化初始化请求，防止并发 /api/setup 各自创建一个管理员。
	setupMu sync.Mutex
)

// regenerateSetupToken 生成并记录一个新的初始化口令。
// 重置站点会把 SetupCompleted 置回 false，此时必须重新发放口令，
// 否则站点会卡在“需要初始化但没有有效口令”的状态。
func regenerateSetupToken() string {
	buf := make([]byte, 24)
	if _, err := cryptorand.Read(buf); err != nil {
		log.Fatal("生成初始化口令失败: ", err)
	}
	token := hex.EncodeToString(buf)
	setupTokenMu.Lock()
	setupToken = token
	setupTokenMu.Unlock()
	log.Printf("站点尚未初始化，一次性初始化口令: %s", token)
	return token
}

// initSetupToken 在站点尚未初始化时生成一次性口令，只输出到服务端日志。
// 没有该口令，任何人先扫到端口也无法通过 /api/setup 抢注管理员。
func initSetupToken() {
	m, err := loadMetadata()
	if err == nil && m.SetupCompleted {
		return
	}
	token := regenerateSetupToken()
	fmt.Printf("\n🔐 站点尚未初始化。请访问 /setup 并填入一次性口令: %s\n\n", token)
}

// validSetupToken 常量时间比较，避免口令被逐字节试探。
func validSetupToken(got string) bool {
	setupTokenMu.RLock()
	want := setupToken
	setupTokenMu.RUnlock()
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(strings.TrimSpace(got))) == 1
}

// ---------------------------------------------------------------------------
// 部署配置：反向代理信任与站点根地址
// ---------------------------------------------------------------------------

// trustProxy 默认关闭。只有显式设置 TRUST_PROXY=1 时才采信 X-Forwarded-*，
// 否则限流键与审计日志一律使用 TCP 连接的真实来源。
var trustProxy = func() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("TRUST_PROXY")))
	return v == "1" || v == "true" || v == "yes"
}()

// siteBaseURL 用于生成邮件里的绝对链接，优先级高于请求头。
var siteBaseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("SITE_URL")), "/")

// baseURLFor 返回站点根地址：优先 SITE_URL，其次可信代理传来的转发头，最后用 Host。
func baseURLFor(r *http.Request) string {
	if siteBaseURL != "" {
		return siteBaseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if trustProxy {
		if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto == "https" || proto == "http" {
			scheme = proto
		}
		if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" {
			host = fwd
		}
	}
	return scheme + "://" + sanitizeHostHeader(host)
}

// sanitizeHostHeader 去掉空白与控制字符，防止把 CRLF 拼进邮件正文。
func sanitizeHostHeader(host string) string {
	host = strings.TrimSpace(host)
	var b strings.Builder
	for _, r := range host {
		if r < 0x20 || r == 0x7f || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isSafePublicURL 只允许 http/https 绝对地址。
// 用于社交链接等会直接被写入 href 的字段，拦掉 javascript:/data: 协议。
func isSafePublicURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// ---------------------------------------------------------------------------
// 用户对外视图
// ---------------------------------------------------------------------------

// publicUser 是所有接口返回用户的唯一形状：不含 passwordHash 等凭据字段。
type publicUser struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email,omitempty"`
	Nickname  string    `json:"nickname,omitempty"`
	Avatar    string    `json:"avatar,omitempty"`
	IsAdmin   bool      `json:"isAdmin"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"createdAt"`
}

func toPublicUser(u *User) publicUser {
	if u == nil {
		return publicUser{}
	}
	return publicUser{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		Nickname:  u.Nickname,
		Avatar:    resolveUserAvatar(u),
		IsAdmin:   u.IsAdmin,
		Verified:  u.Verified,
		CreatedAt: u.CreatedAt,
	}
}

// ---------------------------------------------------------------------------
// 会话版本：改密 / 改角色 / 删号后可让旧 cookie 立即失效
// ---------------------------------------------------------------------------

func bumpSessionVersion(m *Metadata, userID string) {
	if u := findUserByID(m, userID); u != nil {
		u.SessionVersion++
	}
}

// syncAdminCredential 让管理员账号在两个存储里保持一致。
// 历史数据存在 admin 与 users 两份密码：登录走 Admin.PasswordHash，
// 改密只写 Users。这里在改密时同步两侧，避免旧密码继续可登录。
func syncAdminCredential(m *Metadata, u *User) {
	if m.Admin == nil || u == nil {
		return
	}
	if m.Admin.Username == "" || m.Admin.Username == u.Username {
		m.Admin.Username = u.Username
		m.Admin.PasswordHash = u.PasswordHash
	}
}

// ---------------------------------------------------------------------------
// 时序均衡：用户不存在时也做一次 bcrypt 比较
// ---------------------------------------------------------------------------

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

func dummyPasswordCompare(pw string) {
	dummyHashOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("ser1oux-blog-dummy-password"), bcrypt.DefaultCost)
	})
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
}

// ---------------------------------------------------------------------------
// 邮件发送并发上限与超时
// ---------------------------------------------------------------------------

const (
	smtpDialTimeout = 10 * time.Second
	smtpIOTimeout   = 60 * time.Second
)

// emailSemaphore 限制后台邮件 goroutine 数量，避免公开接口把发信队列堆爆。
var emailSemaphore = make(chan struct{}, 8)

// sendEmailAsync 在受限的 goroutine 中发信；队列已满时丢弃并记录，
// 而不是无限派生 goroutine。
func sendEmailAsync(fn func()) {
	select {
	case emailSemaphore <- struct{}{}:
		go func() {
			defer func() { <-emailSemaphore }()
			fn()
		}()
	default:
		log.Printf("[mail] 后台邮件队列已满，丢弃本次通知")
	}
}

// ---------------------------------------------------------------------------
// 审计日志
// ---------------------------------------------------------------------------

func auditLog(action string, r *http.Request, detail string) {
	ip := "-"
	user := "-"
	if r != nil {
		ip = getClientIP(r)
		session, _ := store.Get(r, "session")
		if v, ok := session.Values["username"].(string); ok && v != "" {
			user = v
		} else if v, ok := session.Values["userID"].(string); ok && v != "" {
			user = v
		}
	}
	log.Printf("[audit] action=%s ip=%s user=%s detail=%s", action, ip, user, sanitizeDisplayText(detail))
}

// ---------------------------------------------------------------------------
// metadata 内存缓存：避免每个请求都重新读盘 + JSON 解析
// ---------------------------------------------------------------------------

var (
	metaCacheMu sync.RWMutex
	metaCache   *Metadata
)

// cloneMetadata 深拷贝，保证缓存快照不会被 handler 就地修改。
func cloneMetadata(m *Metadata) *Metadata {
	if m == nil {
		return nil
	}
	c := *m
	c.Posts = append([]Post(nil), m.Posts...)
	for i := range c.Posts {
		c.Posts[i].Tags = append([]string(nil), m.Posts[i].Tags...)
	}
	c.Users = append([]User(nil), m.Users...)
	c.SocialLinks = append([]SocialLink(nil), m.SocialLinks...)
	c.Categories = append([]string(nil), m.Categories...)
	c.Tags = append([]string(nil), m.Tags...)
	if m.Admin != nil {
		a := *m.Admin
		c.Admin = &a
	}
	if m.SMTP != nil {
		s := *m.SMTP
		c.SMTP = &s
	}
	if m.VerificationCodes != nil {
		codes := make(map[string]VerificationCode, len(m.VerificationCodes))
		for k, v := range m.VerificationCodes {
			codes[k] = v
		}
		c.VerificationCodes = codes
	}
	return &c
}

func cachedMetadataCopy() *Metadata {
	metaCacheMu.RLock()
	defer metaCacheMu.RUnlock()
	return cloneMetadata(metaCache)
}

func setMetadataCache(m *Metadata) {
	metaCacheMu.Lock()
	metaCache = cloneMetadata(m)
	metaCacheMu.Unlock()
}

// invalidateMetadataCache 在导入备份等外部改动 data/ 后强制重新读盘。
func invalidateMetadataCache() {
	metaCacheMu.Lock()
	metaCache = nil
	metaCacheMu.Unlock()
}

// ---------------------------------------------------------------------------
// 文章正文缓存：详情页与搜索不再每个请求都读盘
// ---------------------------------------------------------------------------

var (
	postContentMu sync.RWMutex
	postContent   = map[string]string{}
)

func invalidatePostContent(id string) {
	postContentMu.Lock()
	delete(postContent, id)
	postContentMu.Unlock()
}

// invalidateAllPostContent 在导入备份后清空全部正文缓存。
func invalidateAllPostContent() {
	postContentMu.Lock()
	postContent = map[string]string{}
	postContentMu.Unlock()
}

func readPostContent(id string) (string, error) {
	postContentMu.RLock()
	if v, ok := postContent[id]; ok {
		postContentMu.RUnlock()
		return v, nil
	}
	postContentMu.RUnlock()

	data, err := os.ReadFile(filepath.Join(postsDir, id+".md"))
	if err != nil {
		return "", err
	}
	postContentMu.Lock()
	postContent[id] = string(data)
	postContentMu.Unlock()
	return string(data), nil
}

// paginateParams 解析 limit/offset：默认 500 条，硬上限 1000，
// 避免列表接口一次把所有评论/留言读进内存并编码给客户端。
func paginateParams(r *http.Request) (int, int) {
	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	return limit, offset
}

// ---------------------------------------------------------------------------
// 上传配额与旧文件回收
// ---------------------------------------------------------------------------

// maxUploadsDirBytes 上传目录容量上限（2GB）。写满后所有 JSON 写入都会失败，
// 因此到达水位后直接拒绝新的上传，而不是等到磁盘耗尽。
const maxUploadsDirBytes int64 = 2 << 30

func uploadsDirBytes() int64 {
	entries, err := os.ReadDir(uploadsDir)
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil && !info.IsDir() {
			total += info.Size()
		}
	}
	return total
}

// removeUploadByURL 删除 /uploads/ 下的旧文件（换头像、换背景时调用）。
func removeUploadByURL(rawURL string) {
	if !strings.HasPrefix(rawURL, "/uploads/") {
		return
	}
	name := filepath.Base(rawURL)
	if name == "." || name == ".." || name == "" {
		return
	}
	if err := os.Remove(filepath.Join(uploadsDir, name)); err != nil && !os.IsNotExist(err) {
		log.Printf("清理旧上传文件失败 %s: %v", name, err)
	}
}

// writeUploadAtomic 把上传流写入临时文件后原子改名，避免中断留下半截文件。
func writeUploadAtomic(name string, src io.Reader, maxBytes int64) error {
	tmp, err := os.CreateTemp(uploadsDir, ".upload-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if _, err := io.Copy(tmp, io.LimitReader(src, maxBytes+1)); err != nil {
		return err
	}
	if info, err := tmp.Stat(); err != nil || info.Size() > maxBytes {
		return errors.New("文件超过大小上限")
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(uploadsDir, name))
}

// ---------------------------------------------------------------------------
// 上传文件直出：图片内联，其余一律以附件下载
// ---------------------------------------------------------------------------

var inlineImageExts = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true,
}

// serveUploads 替代 http.FileServer：禁止目录列表，非图片强制下载，
// 避免上传的 .md/.txt 被浏览器按内容嗅探成 text/html 执行。
func serveUploads(w http.ResponseWriter, r *http.Request) {
	cleanPath := pathClean(r.URL.Path)
	if strings.HasSuffix(cleanPath, "/") {
		http.NotFound(w, r)
		return
	}
	name := filepath.Base(cleanPath)
	if name == "." || name == ".." || name == "" {
		http.NotFound(w, r)
		return
	}
	// 只接受 /uploads/<文件名> 这一层；/uploads/a/b 不能映射成 uploads/b。
	if strings.TrimPrefix(cleanPath, "/uploads/") != name {
		http.NotFound(w, r)
		return
	}
	target := filepath.Join(uploadsDir, name)
	root, err := filepath.Abs(uploadsDir)
	if err != nil {
		http500(w, err)
		return
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		http500(w, err)
		return
	}
	if abs != filepath.Join(root, name) {
		http.Error(w, "invalid path", http.StatusForbidden)
		return
	}
	if st, err := os.Stat(abs); err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	ext := strings.ToLower(filepath.Ext(name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !inlineImageExts[ext] {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+url.PathEscape(name)+"\"")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeFile(w, r, abs)
}

// pathClean 只做 URL 路径清理，不触碰文件系统。
func pathClean(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

// ---------------------------------------------------------------------------
// 通用中间件
// ---------------------------------------------------------------------------

// recoverMiddleware 兜住 handler 里的 panic，避免单个请求打挂整个进程。
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[panic] %s %s: %v", r.Method, r.URL.Path, rec)
				http.Error(w, "服务器内部错误", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// requestLogMiddleware 为每个请求生成 ID 并记录一行访问日志。
func requestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/uploads/") || strings.HasPrefix(r.URL.Path, "/BG/") || strings.HasPrefix(r.URL.Path, "/public/") {
			next.ServeHTTP(w, r)
			return
		}
		buf := make([]byte, 8)
		if _, err := cryptorand.Read(buf); err != nil {
			copy(buf, []byte("00000000"))
		}
		reqID := hex.EncodeToString(buf)
		w.Header().Set("X-Request-Id", reqID)
		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		log.Printf("[http] %s %s %d %s id=%s ip=%s", r.Method, sanitizeDisplayText(r.URL.Path), rec.status, time.Since(start).Round(time.Millisecond), reqID, getClientIP(r))
	})
}

type gzipResponseWriter struct {
	http.ResponseWriter
	zw *gzip.Writer
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	return g.zw.Write(b)
}

// compressiblePath 已压缩或二进制资源不参与 gzip，避免白费 CPU。
// /api/export-data 用 ServeFile 直接发 tar.gz，不能再套一层 gzip（会破坏 Content-Length）。
func compressiblePath(p string) bool {
	if strings.HasPrefix(p, "/uploads/") || strings.HasPrefix(p, "/BG/") || strings.HasPrefix(p, "/favicon") || strings.HasPrefix(p, "/api/export-data") {
		return false
	}
	switch strings.ToLower(filepath.Ext(p)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".zip", ".gz", ".mp3", ".mp4", ".webm", ".svg":
		return false
	}
	return true
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") || r.Header.Get("Range") != "" || !compressiblePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Del("Content-Length")
		zw := gzip.NewWriter(w)
		defer zw.Close()
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, zw: zw}, r)
	})
}
