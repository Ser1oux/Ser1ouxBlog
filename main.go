package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

//go:embed public/*.html admin/*.html public/vendor/*
var staticFiles embed.FS

var (
	store        *sessions.CookieStore
	dataDir      = "data"
	postsDir     = filepath.Join(dataDir, "posts")
	uploadsDir   = filepath.Join(dataDir, "uploads")
	metadataFile = filepath.Join(dataDir, "metadata.json")
	commentsFile = filepath.Join(dataDir, "comments.json")
	messagesFile = filepath.Join(dataDir, "messages.json")
)

// initSessionStore 初始化会话存储。
// 密钥优先取环境变量 SESSION_SECRET；未配置时随机生成（重启后所有登录态失效）。
// 绝不能使用写死在公开仓库里的密钥，否则任何人都能伪造管理员会话。
func initSessionStore() {
	secret := strings.TrimSpace(os.Getenv("SESSION_SECRET"))
	if secret == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			log.Fatal("生成会话密钥失败: ", err)
		}
		secret = hex.EncodeToString(buf)
		fmt.Println("⚠️  未配置 SESSION_SECRET，已生成随机会话密钥（重启后所有登录会话失效）")
	}
	store = sessions.NewCookieStore([]byte(secret))

	// Cookie 安全属性：HttpOnly 防 JS 读取，SameSite=Lax 缓解 CSRF，Secure 仅经 HTTPS 传输。
	// 本地 HTTP 调试可设置环境变量 COOKIE_SECURE=false。
	secure := !strings.EqualFold(strings.TrimSpace(os.Getenv("COOKIE_SECURE")), "false")
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   30 * 24 * 3600,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// writeFileAtomic 先写临时文件再原子替换，避免进程崩溃后留下半截 JSON。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// errSkipSave 回填任务无变更时跳过落盘。
var errSkipSave = errors.New("无需保存")

// sanitizeHeader 过滤邮件头中的换行，防止 CRLF 头注入。
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", "")
}

// sanitizeDisplayText 去掉展示文本中的控制字符。
func sanitizeDisplayText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isValidAvatarURL 头像仅允许站内相对路径（/uploads/、/BG/、/api/default-avatar），
// 并拒绝引号等字符，防止前端属性上下文注入与外链钓鱼。
func isValidAvatarURL(s string) bool {
	if s == "" || len(s) > 300 {
		return false
	}
	if strings.ContainsAny(s, "\"'`<> \t\r\n\\") {
		return false
	}
	if strings.HasPrefix(s, "/uploads/") || strings.HasPrefix(s, "/BG/") {
		return !strings.Contains(s, "..")
	}
	return strings.HasPrefix(s, "/api/default-avatar")
}

// slidingWindowLimiter 进程内滑动窗口限流器。
type slidingWindowLimiter struct {
	mu      sync.Mutex
	entries map[string][]time.Time
}

var apiRateLimiter = &slidingWindowLimiter{entries: make(map[string][]time.Time)}

// maxLimiterEntries 限制限流表规模。达到上限时先清理过期键，
// 仍然超限则拒绝新键（fail closed），避免内存被伪造键无限撑大。
const maxLimiterEntries = 10000

func (l *slidingWindowLimiter) allow(key string, max int, window time.Duration) bool {
	if len(key) > 256 {
		key = key[:256]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	if len(l.entries) >= maxLimiterEntries {
		if _, exists := l.entries[key]; !exists {
			for k, v := range l.entries {
				if len(v) == 0 || now.Sub(v[len(v)-1]) >= window {
					delete(l.entries, k)
				}
			}
			if len(l.entries) >= maxLimiterEntries {
				return false
			}
		}
	}

	list := l.entries[key]
	kept := make([]time.Time, 0, len(list)+1)
	for _, t := range list {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= max {
		l.entries[key] = kept
		return false
	}
	l.entries[key] = append(kept, now)
	return true
}

// rateLimitAllow 超限返回 false 并直接写 429 响应。
func rateLimitAllow(w http.ResponseWriter, key string, max int, window time.Duration) bool {
	if !apiRateLimiter.allow(key, max, window) {
		http.Error(w, "请求过于频繁，请稍后再试", http.StatusTooManyRequests)
		return false
	}
	return true
}

// securityHeaders 为所有响应添加基础安全头。
// CSP 暂不启用：页面大量内联脚本，需要专项改造后才能收紧。
// http500 统一处理 500：细节只进服务端日志，不把内部错误（可能含文件路径）返回给客户端。
func http500(w http.ResponseWriter, err error) {
	log.Printf("[500] %v", err)
	http.Error(w, "服务器内部错误", http.StatusInternalServerError)
}

// sameOriginCheck 同源校验（CSRF 防护）：状态变更请求若携带 Origin 头，其主机必须与请求目标一致。
// 浏览器对跨站 POST 会带 Origin；非浏览器客户端（curl 等）不带 Origin，直接放行。
// 配合 SameSite=Lax cookie 构成双层防护。
func sameOriginCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host {
					http.Error(w, "跨站请求被拒绝", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// 页面仍使用内联脚本与内联事件，script-src 必须保留 'unsafe-inline'；
		// 但已禁止任意外部源、object 与跨站表单提交，并锁定 frame-ancestors。
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: blob: https:; "+
				"font-src 'self' data:; "+
				"connect-src 'self'; "+
				"object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		if r.TLS != nil || (trustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// bodySizeLimit 全局请求体上限 12MB，防止内存/磁盘耗尽（导入备份接口在自身 handler 内放宽）。
func bodySizeLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/import-data") {
			r.Body = http.MaxBytesReader(w, r.Body, 12<<20)
		}
		next.ServeHTTP(w, r)
	})
}

// noDirListing 禁用 http.FileServer 的目录列表，避免泄露文件清单。
// 注意：StripPrefix 会先把前缀剥掉，目录请求到这里时路径是空串或以 / 结尾。
func noDirListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == "" || strings.HasSuffix(p, "/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type Post struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Slug      string    `json:"slug"`
	Date      time.Time `json:"date"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
	Category  string    `json:"category,omitempty"`
	Tags      []string  `json:"tags"`
	Excerpt   string    `json:"excerpt"`
	Cover     string    `json:"cover,omitempty"`
}

type SocialLink struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
	Icon     string `json:"icon"`
}

type Metadata struct {
	Posts             []Post                      `json:"posts"`
	Admin             *AdminConfig                `json:"admin,omitempty"`
	Users             []User                      `json:"users,omitempty"`
	SMTP              *SMTPConfig                 `json:"smtp,omitempty"`
	CustomBackground  string                      `json:"customBackground,omitempty"`
	SiteName          string                      `json:"siteName,omitempty"`
	GitHubURL         string                      `json:"githubUrl,omitempty"`
	EmailAddress      string                      `json:"emailAddress,omitempty"`
	Avatar            string                      `json:"avatar,omitempty"`
	Nickname          string                      `json:"nickname,omitempty"`
	Bio               string                      `json:"bio,omitempty"`
	SocialLinks       []SocialLink                `json:"socialLinks,omitempty"`
	Categories        []string                    `json:"categories,omitempty"`
	Tags              []string                    `json:"tags,omitempty"`
	Notice            string                      `json:"notice,omitempty"`
	SiteStartDate     string                      `json:"siteStartDate,omitempty"`
	VisitorCount      int                         `json:"visitorCount"`
	SetupCompleted    bool                        `json:"setupCompleted"`
	VerificationCodes map[string]VerificationCode `json:"verificationCodes,omitempty"`
	AboutTitle        string                      `json:"aboutTitle,omitempty"`
	AboutContent      string                      `json:"aboutContent,omitempty"`
}

type VerificationCode struct {
	Code      string    `json:"code"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expiresAt"`
	Type      string    `json:"type"` // register or login
	Attempts  int       `json:"attempts,omitempty"`
}

type AdminConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
	// SessionVersion 与 User.SessionVersion 同步递增，用于让旧会话失效。
	SessionVersion int `json:"sessionVersion,omitempty"`
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"passwordHash"`
	Nickname     string    `json:"nickname,omitempty"`
	Avatar       string    `json:"avatar,omitempty"`
	IsAdmin      bool      `json:"isAdmin"`
	CreatedAt    time.Time `json:"createdAt"`
	Verified     bool      `json:"verified"`
	// SessionVersion 每次改密/改角色/改邮箱递增；会话里保存登录时的值，
	// 中间件对不上即拒绝，实现服务端吊销。
	SessionVersion int `json:"sessionVersion,omitempty"`
}

type SMTPConfig struct {
	Server      string `json:"server"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName"`
	Encryption  string `json:"encryption"` // SSL, TLS, or NONE
}

type CreatePostRequest struct {
	Title    string   `json:"title"`
	Content  string   `json:"content"`
	Category string   `json:"category"`
	Tags     []string `json:"tags"`
	Cover    string   `json:"cover"`
	Slug     string   `json:"slug"` // 可选自定义英文 slug，留空则按标题生成
}

// Comment 文章评论（需登录后发表）
type Comment struct {
	ID          string    `json:"id"`
	PostSlug    string    `json:"postSlug"`
	UserID      string    `json:"userID"`
	Username    string    `json:"username"`
	Nickname    string    `json:"nickname,omitempty"`
	Avatar      string    `json:"avatar,omitempty"`
	Content     string    `json:"content"`
	CreatedAt   time.Time `json:"createdAt"`
	ParentID    string    `json:"parentId,omitempty"`
	ReplyToID   string    `json:"replyToId,omitempty"`
	ReplyToName string    `json:"replyToName,omitempty"`
	// 展示用：位置与浏览环境（不公开完整 IP）
	Location string `json:"location,omitempty"`
	Browser  string `json:"browser,omitempty"`
	OS       string `json:"os,omitempty"`
	// 仅服务端存储，接口返回时会清空
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
}

type CommentsData struct {
	Comments []Comment `json:"comments"`
}

// GuestbookMessage 全站留言（需登录后发表）
type GuestbookMessage struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userID"`
	Username  string    `json:"username"`
	Nickname  string    `json:"nickname,omitempty"`
	Avatar    string    `json:"avatar,omitempty"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"createdAt"`
	Location  string    `json:"location,omitempty"`
	Browser   string    `json:"browser,omitempty"`
	OS        string    `json:"os,omitempty"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"userAgent,omitempty"`
}

type MessagesData struct {
	Messages []GuestbookMessage `json:"messages"`
}

func main() {
	// 命令行参数
	exportCmd := flag.Bool("export", false, "导出所有数据")
	importCmd := flag.String("import", "", "导入数据文件路径")
	port := flag.String("port", "3000", "服务器端口")
	flag.Parse()

	// 初始化数据目录
	if err := initDirectories(); err != nil {
		log.Fatal("初始化目录失败:", err)
	}

	// 初始化会话存储（必须在处理任何请求之前）
	initSessionStore()

	// 站点未完成初始化时生成一次性口令，只有能看到服务端日志的人才能完成 setup。
	initSetupToken()

	// 处理导出命令
	if *exportCmd {
		path, err := exportData()
		if err != nil {
			log.Fatal("导出失败:", err)
		}
		fmt.Println("数据导出成功: " + path)
		return
	}

	// 处理导入命令
	if *importCmd != "" {
		if err := importData(*importCmd); err != nil {
			log.Fatal("导入失败:", err)
		}
		fmt.Println("数据导入成功")
		return
	}

	// 启动 Web 服务器
	r := mux.NewRouter()

	// 全局中间件：panic 恢复 → 访问日志 → gzip → 安全响应头 → 请求体上限 → 同源校验
	r.Use(recoverMiddleware)
	r.Use(requestLogMiddleware)
	r.Use(gzipMiddleware)
	r.Use(securityHeaders)
	r.Use(bodySizeLimit)
	r.Use(sameOriginCheck)

	// API 路由
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/posts", getPosts).Methods("GET")
	api.HandleFunc("/post/{slug}", getPost).Methods("GET")
	api.HandleFunc("/search", searchPosts).Methods("GET")
	api.HandleFunc("/visitor-stats", getVisitorStats).Methods("GET")
	api.HandleFunc("/login", login).Methods("POST")
	api.HandleFunc("/logout", logout).Methods("POST")
	api.HandleFunc("/posts", requireAuth(createPost)).Methods("POST")
	api.HandleFunc("/posts/{id}", requireAuth(updatePost)).Methods("PUT")
	api.HandleFunc("/posts/{id}", requireAuth(deletePost)).Methods("DELETE")
	api.HandleFunc("/upload", requireAuth(uploadFile)).Methods("POST")
	api.HandleFunc("/files", requireAuth(listFiles)).Methods("GET")
	api.HandleFunc("/files/{filename}", requireAuth(deleteFile)).Methods("DELETE")
	api.HandleFunc("/export-data", requireAuth(exportDataAPI)).Methods("GET")
	api.HandleFunc("/import-data", requireAuth(importDataAPI)).Methods("POST")
	api.HandleFunc("/upload-background", requireAuth(uploadBackground)).Methods("POST")
	api.HandleFunc("/reset-background", requireAuth(resetBackground)).Methods("POST")
	api.HandleFunc("/settings", getSettings).Methods("GET")
	api.HandleFunc("/settings", requireAuth(updateSettings)).Methods("POST")
	api.HandleFunc("/setup", setupSite).Methods("POST")
	api.HandleFunc("/user-register", userRegister).Methods("POST")
	api.HandleFunc("/user-login", userLogin).Methods("POST")
	api.HandleFunc("/user-info", requireUserAuth(getUserInfo)).Methods("GET")
	api.HandleFunc("/user-profile", requireUserAuth(updateUserProfile)).Methods("PUT")
	api.HandleFunc("/users", requireAuth(getAllUsers)).Methods("GET")
	api.HandleFunc("/user-role", requireAuth(updateUserRole)).Methods("POST")
	api.HandleFunc("/users/{id}", requireAuth(deleteUser)).Methods("DELETE")
	api.HandleFunc("/send-verification-code", sendVerificationCode).Methods("POST")
	api.HandleFunc("/smtp-config", requireAuth(getSMTPConfig)).Methods("GET")
	api.HandleFunc("/smtp-config", requireAuth(updateSMTPConfig)).Methods("POST")
	api.HandleFunc("/test-smtp", requireAuth(testSMTP)).Methods("POST")
	api.HandleFunc("/check-setup", checkSetupStatus).Methods("GET")
	api.HandleFunc("/debug-metadata", requireAuth(debugMetadata)).Methods("GET")
	api.HandleFunc("/about", getAbout).Methods("GET")
	api.HandleFunc("/about", requireAuth(updateAbout)).Methods("POST")
	api.HandleFunc("/about-page", getAbout).Methods("GET")
	api.HandleFunc("/about-page", requireAuth(updateAbout)).Methods("POST")
	api.HandleFunc("/server-status", requireAuth(getServerStatus)).Methods("GET")
	api.HandleFunc("/reset-site", requireAuth(resetSite)).Methods("POST")
	api.HandleFunc("/change-password", requireUserAuth(changePassword)).Methods("POST")
	api.HandleFunc("/reset-password", resetPassword).Methods("POST")
	api.HandleFunc("/change-email", requireAuth(changeEmail)).Methods("POST")
	api.HandleFunc("/comments/{slug}", getComments).Methods("GET")
	// 评论：允许游客发表，鉴权在 handler 内部区分登录用户与游客
	api.HandleFunc("/comments", createComment).Methods("POST")
	api.HandleFunc("/comments/{id}", requireUserAuth(deleteComment)).Methods("DELETE")
	api.HandleFunc("/notifications", requireUserAuth(getNotifications)).Methods("GET")
	api.HandleFunc("/notifications/read", requireUserAuth(readNotifications)).Methods("POST")
	api.HandleFunc("/default-avatar", serveDefaultAvatar).Methods("GET")
	api.HandleFunc("/default-cover", serveDefaultCover).Methods("GET")
	api.HandleFunc("/upload-avatar", requireUserAuth(uploadAvatar)).Methods("POST")
	api.HandleFunc("/messages", getMessages).Methods("GET")
	// 留言：允许游客发表，鉴权在 handler 内部区分登录用户与游客
	api.HandleFunc("/messages", createMessage).Methods("POST")
	api.HandleFunc("/messages/{id}", requireUserAuth(deleteMessage)).Methods("DELETE")

	// 静态文件（禁止目录列表；非图片强制附件下载，避免上传内容被当作 HTML 执行）
	r.PathPrefix("/uploads/").HandlerFunc(serveUploads)
	r.PathPrefix("/BG/").Handler(http.StripPrefix("/BG/", noDirListing(http.FileServer(http.Dir("BG")))))

	// 搜索引擎基础文件
	r.HandleFunc("/robots.txt", serveRobotsTXT).Methods("GET")
	r.HandleFunc("/sitemap.xml", serveSitemapXML).Methods("GET")
	r.HandleFunc("/rss.xml", serveRSS).Methods("GET")

	// 浏览器默认会请求 /favicon.ico
	r.HandleFunc("/favicon.ico", func(w http.ResponseWriter, req *http.Request) {
		path := filepath.Join("BG", "favicon.png")
		if _, err := os.Stat(path); err != nil {
			path = filepath.Join("BG", "icon.jpg")
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, req, path)
	}).Methods("GET")

	// 前台页面
	r.HandleFunc("/", checkSetup(trackVisitor(servePage("public/index.html")))).Methods("GET")
	r.HandleFunc("/post/{slug}", checkSetup(servePage("public/post.html"))).Methods("GET")
	r.HandleFunc("/archive", checkSetup(servePage("public/archive.html"))).Methods("GET")
	r.HandleFunc("/about", checkSetup(servePage("public/about.html"))).Methods("GET")
	r.HandleFunc("/guestbook", checkSetup(servePage("public/guestbook.html"))).Methods("GET")
	r.HandleFunc("/login", checkSetup(servePage("public/login.html"))).Methods("GET")
	r.HandleFunc("/search", checkSetup(servePage("public/search.html"))).Methods("GET")
	r.HandleFunc("/reset-password", checkSetup(servePage("public/reset-password.html"))).Methods("GET")
	r.HandleFunc("/profile", checkSetup(servePage("public/profile.html"))).Methods("GET")
	r.HandleFunc("/admin", checkSetup(requireAuth(servePage("admin/posts.html")))).Methods("GET")
	r.HandleFunc("/admin/posts", checkSetup(requireAuth(servePage("admin/posts.html")))).Methods("GET")
	r.HandleFunc("/admin/files", checkSetup(requireAuth(servePage("admin/files.html")))).Methods("GET")
	r.HandleFunc("/admin/settings", checkSetup(requireAuth(servePage("admin/settings.html")))).Methods("GET")
	r.HandleFunc("/setup", blockSetupIfCompleted(servePage("public/setup.html"))).Methods("GET")

	// 静态资源
	r.PathPrefix("/public/").Handler(http.HandlerFunc(serveEmbedded))
	// /admin/ 下的内嵌页面（如 /admin/posts.html）同样要求管理员登录，
	// 防止未登录者直接下载后台前端源码（泄露全部接口与参数结构）
	r.PathPrefix("/admin/").Handler(checkSetupMiddleware(requireAuth(http.HandlerFunc(serveEmbedded))))

	addr := ":" + *port
	fmt.Printf("🚀 博客服务器启动成功！\n")
	fmt.Printf("📝 前台地址: http://localhost:%s\n", *port)
	fmt.Printf("⚙️  管理后台: http://localhost:%s/admin\n", *port)
	fmt.Printf("💾 数据目录: %s\n\n", dataDir)

	go backfillStoredLocations()

	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// 优雅关闭：收到 SIGINT/SIGTERM 后停止接收新请求并等待在途请求完成，
	// 避免容器重启时正好中断 metadata / 正文写盘。
	shutdownDone := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		select {
		case <-sigCh:
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				log.Printf("关闭服务器失败: %v", err)
			}
		case <-shutdownDone:
		}
	}()

	log.Printf("HTTP 服务监听 %s（超时已配置：读头 10s / 读 60s / 写 120s）", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	close(shutdownDone)
}

func initDirectories() error {
	dirs := []string{dataDir, postsDir, uploadsDir}
	for _, dir := range dirs {
		// 0700：data/ 里有 bcrypt 哈希、SMTP 密码与会话相关文件。
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	// 初始化 metadata.json
	if _, err := os.Stat(metadataFile); os.IsNotExist(err) {
		metadata := Metadata{Posts: []Post{}}
		return saveMetadata(&metadata)
	}
	return nil
}

var metadataMu sync.Mutex

func loadMetadataUnlocked() (*Metadata, error) {
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return nil, err
	}

	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func saveMetadataUnlocked(metadata *Metadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	// 0600：metadata 里有 bcrypt 哈希与 SMTP 密码，同主机其他用户不应可读。
	if err := writeFileAtomic(metadataFile, data, 0600); err != nil {
		return err
	}
	setMetadataCache(metadata)
	return nil
}

func loadMetadata() (*Metadata, error) {
	// 命中内存快照时直接返回深拷贝，省掉每个请求的读盘与 JSON 解析。
	if cached := cachedMetadataCopy(); cached != nil {
		return cached, nil
	}
	metadataMu.Lock()
	defer metadataMu.Unlock()
	m, err := loadMetadataUnlocked()
	if err != nil {
		return nil, err
	}
	setMetadataCache(m)
	return cloneMetadata(m), nil
}

func saveMetadata(metadata *Metadata) error {
	metadataMu.Lock()
	defer metadataMu.Unlock()
	return saveMetadataUnlocked(metadata)
}

func withMetadata(fn func(*Metadata) error) error {
	metadataMu.Lock()
	defer metadataMu.Unlock()
	metadata, err := loadMetadataUnlocked()
	if err != nil {
		return err
	}
	if err := fn(metadata); err != nil {
		return err
	}
	return saveMetadataUnlocked(metadata)
}

func loadComments() (*CommentsData, error) {
	if _, err := os.Stat(commentsFile); os.IsNotExist(err) {
		return &CommentsData{Comments: []Comment{}}, nil
	}
	data, err := os.ReadFile(commentsFile)
	if err != nil {
		return nil, err
	}
	var store CommentsData
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	if store.Comments == nil {
		store.Comments = []Comment{}
	}
	return &store, nil
}

func commentDisplayName(c Comment) string {
	if name := strings.TrimSpace(c.Nickname); name != "" {
		return name
	}
	if name := strings.TrimSpace(c.Username); name != "" {
		return name
	}
	return "用户"
}

func resolveCommentReply(store *CommentsData, postSlug, parentID, userID string) (rootID, replyToID, replyToName string, err error) {
	parentID = strings.TrimSpace(parentID)
	if parentID == "" {
		return "", "", "", nil
	}
	if store == nil {
		return "", "", "", errors.New("回复的评论不存在")
	}
	var parent *Comment
	for i := range store.Comments {
		if store.Comments[i].ID == parentID {
			parent = &store.Comments[i]
			break
		}
	}
	if parent == nil {
		return "", "", "", errors.New("回复的评论不存在")
	}
	if parent.PostSlug != postSlug && normalizePostKey(parent.PostSlug) != normalizePostKey(postSlug) {
		return "", "", "", errors.New("不能回复其他文章的评论")
	}
	if userID != "" && parent.UserID == userID {
		return "", "", "", errors.New("不能回复自己的评论")
	}
	replyToID = parent.ID
	replyToName = commentDisplayName(*parent)
	if parent.ParentID != "" {
		return parent.ParentID, replyToID, replyToName, nil
	}
	return parent.ID, replyToID, replyToName, nil
}

func saveComments(store *CommentsData) error {
	if store.Comments == nil {
		store.Comments = []Comment{}
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(commentsFile, data, 0600)
}

func loadMessages() (*MessagesData, error) {
	if _, err := os.Stat(messagesFile); os.IsNotExist(err) {
		return &MessagesData{Messages: []GuestbookMessage{}}, nil
	}
	data, err := os.ReadFile(messagesFile)
	if err != nil {
		return nil, err
	}
	var store MessagesData
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	if store.Messages == nil {
		store.Messages = []GuestbookMessage{}
	}
	return &store, nil
}

func saveMessages(store *MessagesData) error {
	if store.Messages == nil {
		store.Messages = []GuestbookMessage{}
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(messagesFile, data, 0600)
}

// comments.json / messages.json 的读-改-写必须在同一把锁内完成，
// 否则并发评论/留言/删除/归属地回填会互相覆盖导致丢数据。
var (
	commentsMu sync.Mutex
	messagesMu sync.Mutex
)

// readComments 加锁读取评论（供 API 只读场景）。
func readComments() (*CommentsData, error) {
	commentsMu.Lock()
	defer commentsMu.Unlock()
	return loadComments()
}

// withComments 在锁内执行 读-改-写；fn 返回错误时不落盘。
func withComments(fn func(*CommentsData) error) error {
	commentsMu.Lock()
	defer commentsMu.Unlock()
	store, err := loadComments()
	if err != nil {
		return err
	}
	if err := fn(store); err != nil {
		return err
	}
	return saveComments(store)
}

// readMessages 加锁读取留言。
func readMessages() (*MessagesData, error) {
	messagesMu.Lock()
	defer messagesMu.Unlock()
	return loadMessages()
}

// withMessages 在锁内执行留言的 读-改-写。
func withMessages(fn func(*MessagesData) error) error {
	messagesMu.Lock()
	defer messagesMu.Unlock()
	store, err := loadMessages()
	if err != nil {
		return err
	}
	if err := fn(store); err != nil {
		return err
	}
	return saveMessages(store)
}

func findUserByID(metadata *Metadata, userID string) *User {
	for i := range metadata.Users {
		if metadata.Users[i].ID == userID {
			return &metadata.Users[i]
		}
	}
	return nil
}

func isPlaceholderAvatar(avatar string) bool {
	avatar = strings.TrimSpace(avatar)
	return avatar == "" || avatar == "/BG/icon.jpg" || avatar == "BG/icon.jpg"
}

func defaultAvatarURL(seed string) string {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		seed = "user"
	}
	return "/api/default-avatar?seed=" + url.QueryEscape(seed)
}

func resolveUserAvatar(user *User) string {
	if user == nil {
		return defaultAvatarURL("user")
	}
	if isPlaceholderAvatar(user.Avatar) {
		return defaultAvatarURL(user.ID)
	}
	return user.Avatar
}

// 按 seed 生成彩色字母头像（每人不同）
func serveDefaultAvatar(w http.ResponseWriter, r *http.Request) {
	seed := strings.TrimSpace(r.URL.Query().Get("seed"))
	if seed == "" {
		seed = "user"
	}

	colors := []string{
		"#6366f1", "#8b5cf6", "#ec4899", "#f43f5e", "#f97316",
		"#eab308", "#22c55e", "#14b8a6", "#06b6d4", "#3b82f6",
		"#a855f7", "#d946ef", "#0ea5e9", "#84cc16", "#f59e0b",
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	color := colors[int(h.Sum32())%len(colors)]

	letter := "?"
	for _, ch := range seed {
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) {
			letter = strings.ToUpper(string(ch))
			if ch >= 0x4e00 && ch <= 0x9fff {
				letter = string(ch)
			}
			break
		}
	}
	// 优先用 seed 里更像名字的部分：若含非数字，取第一个字母/汉字
	for _, ch := range seed {
		if unicode.IsLetter(ch) {
			if ch >= 0x4e00 && ch <= 0x9fff {
				letter = string(ch)
			} else {
				letter = strings.ToUpper(string(ch))
			}
			break
		}
	}

	// 简单转义
	letter = strings.ReplaceAll(letter, "&", "&amp;")
	letter = strings.ReplaceAll(letter, "<", "&lt;")
	letter = strings.ReplaceAll(letter, ">", "&gt;")
	letter = strings.ReplaceAll(letter, "\"", "&quot;")

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
  <defs>
    <linearGradient id="g" x1="0%%" y1="0%%" x2="100%%" y2="100%%">
      <stop offset="0%%" stop-color="%s"/>
      <stop offset="100%%" stop-color="%s" stop-opacity="0.85"/>
    </linearGradient>
  </defs>
  <rect width="128" height="128" rx="64" fill="url(#g)"/>
  <text x="64" y="64" dy="0.36em" text-anchor="middle" fill="#fff" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="56" font-weight="700">%s</text>
</svg>`, color, color, letter)

	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write([]byte(svg))
}

// 登录用户上传自己的头像
func uploadAvatar(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID, _ := session.Values["userID"].(string)
	if userID == "" {
		http.Error(w, "未授权", http.StatusUnauthorized)
		return
	}
	// 按用户限流，避免任何登录账号无上限刷盘。
	if !rateLimitAllow(w, "avatar:"+userID, 10, time.Hour) {
		return
	}
	if uploadsDirBytes() > maxUploadsDirBytes {
		http.Error(w, "存储空间已满，请联系管理员", http.StatusInsufficientStorage)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 3<<20)
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		http.Error(w, "上传失败或文件过大", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "上传失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if handler.Size > 2<<20 {
		http.Error(w, "头像不能超过 2MB", http.StatusRequestEntityTooLarge)
		return
	}

	ext := strings.ToLower(filepath.Ext(handler.Filename))
	allowed := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true}
	if !allowed[ext] {
		http.Error(w, "仅支持 jpg/png/gif/webp 图片", http.StatusBadRequest)
		return
	}

	filename := fmt.Sprintf("avatar-%s-%d%s", userID, time.Now().UnixNano(), ext)
	if err := writeUploadAtomic(filename, file, 2<<20); err != nil {
		http500(w, err)
		return
	}

	// 写入用户记录并回收旧头像，避免每次换头像都永久占用磁盘。
	var oldAvatar string
	userFound := false
	err = withMetadata(func(metadata *Metadata) error {
		u := findUserByID(metadata, userID)
		if u == nil {
			return errSkipSave
		}
		userFound = true
		oldAvatar = u.Avatar
		u.Avatar = "/uploads/" + filename
		return nil
	})
	if err != nil && !errors.Is(err, errSkipSave) {
		removeUploadByURL("/uploads/" + filename)
		http500(w, err)
		return
	}
	if !userFound {
		removeUploadByURL("/uploads/" + filename)
		http.Error(w, "用户不存在", http.StatusUnauthorized)
		return
	}
	removeUploadByURL(oldAvatar)

	writeJSON(w, http.StatusOK, map[string]string{
		"url":      "/uploads/" + filename,
		"filename": filename,
	})
}

// 获取某篇文章的评论（公开；支持 slug 或文章 id）
func getComments(w http.ResponseWriter, r *http.Request) {
	key := normalizePostKey(mux.Vars(r)["slug"])
	// 若 key 是文章 id，换成标准 slug 再筛
	canonicalSlug := key
	if metadata, err := loadMetadata(); err == nil {
		if p := findPostByKey(metadata, key); p != nil {
			canonicalSlug = p.Slug
		}
	}

	cstore, err := readComments()
	if err != nil {
		http500(w, err)
		return
	}

	list := make([]Comment, 0)
	for _, c := range cstore.Comments {
		if c.PostSlug == canonicalSlug || c.PostSlug == key || normalizePostKey(c.PostSlug) == key {
			// 旧评论若仍是统一默认头像，按用户 ID 生成不同头像
			if isPlaceholderAvatar(c.Avatar) {
				c.Avatar = defaultAvatarURL(c.UserID)
			}
			c.Location = displayLocation(c.Location, c.IP)
			// 不向前端暴露完整 IP 与原始 UA
			c.IP = ""
			c.UserAgent = ""
			list = append(list, c)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})

	// 分页：默认 500 条，防止评论量增长后单次响应无限膨胀。
	total := len(list)
	limit, offset := paginateParams(r)
	if offset > len(list) {
		offset = len(list)
	}
	end := offset + limit
	if end > len(list) {
		end = len(list)
	}
	list = list[offset:end]

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	json.NewEncoder(w).Encode(list)
}

// 发表评论（需登录）
// guestUserID 为未登录访客生成稳定的匿名标识。
// 用 IP 的 FNV 哈希而非明文：既能区分不同访客，又不会把真实 IP 暴露给前端。
func guestUserID(clientIP string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.TrimSpace(clientIP)))
	return fmt.Sprintf("guest-%08x", h.Sum32())
}

// adminSessionUser 返回应绑定到管理员会话的用户记录。
// 登录接口此前只写入 admin=true，从不写入 userID，导致管理员重新登录后
// 无法通过 requireUserAuth（评论等接口一律 401）。这里补上绑定。
func adminSessionUser(metadata *Metadata) *User {
	for i := range metadata.Users {
		if metadata.Users[i].IsAdmin {
			return &metadata.Users[i]
		}
	}
	if metadata.Admin != nil && metadata.Admin.Username != "" {
		for i := range metadata.Users {
			if metadata.Users[i].Username == metadata.Admin.Username {
				return &metadata.Users[i]
			}
		}
	}
	return nil
}

func createComment(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	sessionUserID, _ := session.Values["userID"].(string)

	var req struct {
		PostSlug string `json:"postSlug"`
		PostID   string `json:"postId"`
		Content  string `json:"content"`
		ParentID string `json:"parentId"`
		Nickname string `json:"nickname"` // 游客昵称；登录用户忽略此字段
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.PostSlug = strings.TrimSpace(req.PostSlug)
	req.PostID = strings.TrimSpace(req.PostID)
	req.Content = strings.TrimSpace(req.Content)
	if (req.PostSlug == "" && req.PostID == "") || req.Content == "" {
		http.Error(w, "评论内容和文章不能为空", http.StatusBadRequest)
		return
	}
	if len([]rune(req.Content)) > 1000 {
		http.Error(w, "评论不能超过1000字", http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	// 优先 ID，再 slug（兼容中文 slug / URL 编码差异）
	var post *Post
	if req.PostID != "" {
		post = findPostByKey(metadata, req.PostID)
	}
	if post == nil && req.PostSlug != "" {
		post = findPostByKey(metadata, req.PostSlug)
	}
	if post == nil {
		http.Error(w, "文章不存在", http.StatusNotFound)
		return
	}

	user := findUserByID(metadata, sessionUserID)

	// IP 归属地解析涉及外部 HTTP 请求，放在锁外执行
	clientIP := getClientIP(r)

	// 身份判定：已登录走账号信息；未登录按游客处理（独立限流 + 自填昵称）
	commenter := User{}
	avatar := ""
	if user != nil {
		commenter = *user
		avatar = resolveUserAvatar(user)
		if !rateLimitAllow(w, "comment-user:"+user.ID, 20, 10*time.Minute) {
			return
		}
	} else {
		// 游客：每 IP 10 分钟最多 5 条，防止刷屏
		if !rateLimitAllow(w, "comment-guest:"+clientIP, 5, 10*time.Minute) {
			return
		}
		nick := sanitizeDisplayText(strings.TrimSpace(req.Nickname))
		if runes := []rune(nick); len(runes) > 20 {
			nick = string(runes[:20])
		}
		if nick == "" {
			nick = "匿名游客"
		}
		guestID := guestUserID(clientIP)
		commenter = User{ID: guestID, Username: "guest", Nickname: nick}
		// 同一 IP 的游客共用固定头像，避免每次评论头像乱跳
		avatar = defaultAvatarURL(guestID)
	}

	ua := r.Header.Get("User-Agent")
	browser, osName := parseUserAgent(ua)
	location := resolveIPLocation(clientIP)

	var comment Comment
	var snapshot *CommentsData
	var replyErr error
	err = withComments(func(cstore *CommentsData) error {
		rootID, replyToID, replyToName, err := resolveCommentReply(cstore, post.Slug, strings.TrimSpace(req.ParentID), commenter.ID)
		if err != nil {
			replyErr = err
			return err
		}

		comment = Comment{
			ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
			PostSlug:    post.Slug, // 始终存库内标准 slug
			UserID:      commenter.ID,
			Username:    commenter.Username,
			Nickname:    commenter.Nickname,
			Avatar:      avatar,
			Content:     sanitizeDisplayText(req.Content),
			CreatedAt:   time.Now(),
			ParentID:    rootID,
			ReplyToID:   replyToID,
			ReplyToName: replyToName,
			Location:    location,
			Browser:     browser,
			OS:          osName,
			IP:          clientIP,
			UserAgent:   ua,
		}

		cstore.Comments = append(cstore.Comments, comment)
		// 通知 goroutine 在锁外运行，只给它一份快照，避免数据竞争
		snapshot = &CommentsData{Comments: append([]Comment{}, cstore.Comments...)}
		return nil
	})
	if replyErr != nil {
		http.Error(w, replyErr.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http500(w, err)
		return
	}

	baseURL := publicBaseURL(r)
	go notifyNewComment(metadata, *post, comment, commenter, snapshot, baseURL)

	// 返回时不带敏感字段
	resp := comment
	resp.IP = ""
	resp.UserAgent = ""
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// 删除评论：本人或管理员
func deleteComment(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	session, _ := store.Get(r, "session")
	userID, _ := session.Values["userID"].(string)
	isAdmin, _ := session.Values["isAdmin"].(bool)
	if !isAdmin {
		// 兼容部分管理员会话只写了 admin
		if auth, ok := session.Values["admin"].(bool); ok && auth {
			isAdmin = true
		}
	}

	notFound := false
	forbidden := false
	err := withComments(func(cstore *CommentsData) error {
		idx := -1
		for i, c := range cstore.Comments {
			if c.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			notFound = true
			return errors.New("not found")
		}

		if cstore.Comments[idx].UserID != userID && !isAdmin {
			forbidden = true
			return errors.New("forbidden")
		}

		removeID := cstore.Comments[idx].ID
		kept := make([]Comment, 0, len(cstore.Comments)-1)
		for _, c := range cstore.Comments {
			if c.ID == removeID || c.ParentID == removeID {
				continue
			}
			kept = append(kept, c)
		}
		cstore.Comments = kept
		return nil
	})
	if notFound {
		http.Error(w, "评论不存在", http.StatusNotFound)
		return
	}
	if forbidden {
		http.Error(w, "无权删除该评论", http.StatusForbidden)
		return
	}
	if err != nil {
		http500(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// 获取留言板（公开，新→旧）
func getMessages(w http.ResponseWriter, r *http.Request) {
	mstore, err := readMessages()
	if err != nil {
		http500(w, err)
		return
	}

	list := make([]GuestbookMessage, 0, len(mstore.Messages))
	for _, m := range mstore.Messages {
		if isPlaceholderAvatar(m.Avatar) {
			m.Avatar = defaultAvatarURL(m.UserID)
		}
		m.Location = displayLocation(m.Location, m.IP)
		m.IP = ""
		m.UserAgent = ""
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})

	total := len(list)
	limit, offset := paginateParams(r)
	if offset > len(list) {
		offset = len(list)
	}
	end := offset + limit
	if end > len(list) {
		end = len(list)
	}
	list = list[offset:end]

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	json.NewEncoder(w).Encode(list)
}

// 发表留言（登录用户与游客均可）
func createMessage(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	sessionUserID, _ := session.Values["userID"].(string)

	var req struct {
		Content  string `json:"content"`
		Nickname string `json:"nickname"` // 游客昵称；登录用户忽略此字段
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" {
		http.Error(w, "留言内容不能为空", http.StatusBadRequest)
		return
	}
	if len([]rune(req.Content)) > 1000 {
		http.Error(w, "留言不能超过1000字", http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	clientIP := getClientIP(r)

	// 身份判定：已登录用账号信息；未登录按游客处理（独立限流 + 自填昵称）
	commenter := User{}
	avatar := ""
	if user := findUserByID(metadata, sessionUserID); user != nil {
		commenter = *user
		avatar = resolveUserAvatar(user)
		if !rateLimitAllow(w, "message-user:"+user.ID, 10, 10*time.Minute) {
			return
		}
	} else {
		// 游客：每 IP 10 分钟最多 3 条，留言板更显眼，收紧一些
		if !rateLimitAllow(w, "message-guest:"+clientIP, 3, 10*time.Minute) {
			return
		}
		nick := sanitizeDisplayText(strings.TrimSpace(req.Nickname))
		if runes := []rune(nick); len(runes) > 20 {
			nick = string(runes[:20])
		}
		if nick == "" {
			nick = "匿名游客"
		}
		guestID := guestUserID(clientIP)
		commenter = User{ID: guestID, Username: "guest", Nickname: nick}
		avatar = defaultAvatarURL(guestID)
	}

	ua := r.Header.Get("User-Agent")
	browser, osName := parseUserAgent(ua)
	location := resolveIPLocation(clientIP)

	msg := GuestbookMessage{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		UserID:    commenter.ID,
		Username:  commenter.Username,
		Nickname:  commenter.Nickname,
		Avatar:    avatar,
		Content:   sanitizeDisplayText(req.Content),
		CreatedAt: time.Now(),
		Location:  location,
		Browser:   browser,
		OS:        osName,
		IP:        clientIP,
		UserAgent: ua,
	}

	if err := withMessages(func(mstore *MessagesData) error {
		mstore.Messages = append(mstore.Messages, msg)
		return nil
	}); err != nil {
		http500(w, err)
		return
	}

	resp := msg
	resp.IP = ""
	resp.UserAgent = ""
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// 删除留言：本人或管理员
func deleteMessage(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	session, _ := store.Get(r, "session")
	userID, _ := session.Values["userID"].(string)
	isAdmin, _ := session.Values["isAdmin"].(bool)
	if !isAdmin {
		if auth, ok := session.Values["admin"].(bool); ok && auth {
			isAdmin = true
		}
	}

	notFound := false
	forbidden := false
	err := withMessages(func(mstore *MessagesData) error {
		idx := -1
		for i, m := range mstore.Messages {
			if m.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			notFound = true
			return errors.New("not found")
		}
		if mstore.Messages[idx].UserID != userID && !isAdmin {
			forbidden = true
			return errors.New("forbidden")
		}

		mstore.Messages = append(mstore.Messages[:idx], mstore.Messages[idx+1:]...)
		return nil
	})
	if notFound {
		http.Error(w, "留言不存在", http.StatusNotFound)
		return
	}
	if forbidden {
		http.Error(w, "无权删除该留言", http.StatusForbidden)
		return
	}
	if err != nil {
		http500(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func slugify(title string) string {
	slug := strings.ToLower(title)
	slug = strings.ReplaceAll(slug, " ", "-")
	// 简单的中文处理：保留中文字符
	var result strings.Builder
	for _, r := range slug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r >= 0x4e00 && r <= 0x9fff {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func servePage(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		content, err := staticFiles.ReadFile(path)
		if err != nil {
			http.Error(w, "页面不存在", http.StatusNotFound)
			return
		}
		writeHTMLPage(w, content)
	}
}

// API Handlers

func getPosts(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	// 按日期排序
	posts := metadata.Posts
	sort.Slice(posts, func(i, j int) bool {
		return posts[i].Date.After(posts[j].Date)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(posts)
}

// normalizePostKey 解码 URL 中的 slug/id，避免编码不一致导致“文章不存在”
func normalizePostKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return key
	}
	if u, err := url.PathUnescape(key); err == nil && u != "" {
		key = u
	}
	if u, err := url.QueryUnescape(key); err == nil && u != "" {
		key = u
	}
	return strings.TrimSpace(key)
}

func findPostByKey(metadata *Metadata, key string) *Post {
	key = normalizePostKey(key)
	if key == "" || metadata == nil {
		return nil
	}
	for i := range metadata.Posts {
		p := &metadata.Posts[i]
		if p.ID == key || p.Slug == key {
			return p
		}
		// 再比一遍解码后的 slug
		if normalizePostKey(p.Slug) == key {
			return p
		}
	}
	return nil
}

func getPost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["slug"]

	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	post := findPostByKey(metadata, key)
	if post == nil {
		http.Error(w, "文章不存在", http.StatusNotFound)
		return
	}

	// 读取文章内容
	content, err := readPostContent(post.ID)
	if err != nil {
		http500(w, err)
		return
	}

	response := map[string]interface{}{
		"id":        post.ID,
		"title":     post.Title,
		"slug":      post.Slug,
		"date":      post.Date,
		"updatedAt": post.UpdatedAt,
		"category":  post.Category,
		"tags":      post.Tags,
		"excerpt":   post.Excerpt,
		"content":   content,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func login(w http.ResponseWriter, r *http.Request) {
	if !rateLimitAllow(w, "admin-login:"+getClientIP(r), 10, 15*time.Minute) {
		return
	}
	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	// 站点未初始化时，登录接口不再承担“首次设置密码”的职责。
	// 旧实现会在 Admin 为空时用请求体密码创建管理员，任何先扫到端口的人都能接管后台。
	if metadata.Admin == nil || metadata.Admin.PasswordHash == "" {
		writeJSONError(w, http.StatusConflict, "站点尚未初始化，请先访问 /setup 完成初始化")
		return
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(metadata.Admin.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "密码错误", http.StatusUnauthorized)
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["admin"] = true
	if u := adminSessionUser(metadata); u != nil {
		session.Values["userID"] = u.ID
		session.Values["username"] = u.Username
		session.Values["isAdmin"] = u.IsAdmin
		session.Values["sessionVersion"] = u.SessionVersion
	}
	session.Save(r, w)

	auditLog("admin-login", r, "username="+metadata.Admin.Username)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Values["admin"] = false
	session.Options.MaxAge = -1
	session.Save(r, w)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func createPost(w http.ResponseWriter, r *http.Request) {
	var req CreatePostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求", http.StatusBadRequest)
		return
	}

	now := time.Now()
	var created Post
	var slugErr error
	err := withMetadata(func(metadata *Metadata) error {
		slug, e := resolvePostSlug(metadata, req.Slug, req.Title, "")
		if e != nil {
			slugErr = e
			return e
		}
		created = Post{
			ID:        strconv.FormatInt(now.UnixNano(), 10),
			Title:     req.Title,
			Slug:      slug,
			Date:      now,
			CreatedAt: now,
			Category:  req.Category,
			Tags:      req.Tags,
			Excerpt:   getExcerpt(req.Content, 150),
			Cover:     req.Cover,
		}
		// 正文先落盘再保存 metadata：失败最多留下一个孤儿文件，不会出现“有记录无内容”。
		if e := writeFileAtomic(filepath.Join(postsDir, created.ID+".md"), []byte(req.Content), 0600); e != nil {
			return e
		}
		metadata.Posts = append(metadata.Posts, created)
		return nil
	})
	if slugErr != nil {
		http.Error(w, slugErr.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http500(w, err)
		return
	}
	invalidatePostContent(created.ID)
	auditLog("post-created", r, "slug="+created.Slug)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(created)
}

func updatePost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req CreatePostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 校验与写入放在同一临界区，避免两个管理员同时编辑时互相覆盖。
	var slugErr error
	var postMissing bool
	err := withMetadata(func(metadata *Metadata) error {
		for i := range metadata.Posts {
			if metadata.Posts[i].ID == id {
				slug, e := resolvePostSlug(metadata, req.Slug, req.Title, id)
				if e != nil {
					slugErr = e
					return e
				}
				metadata.Posts[i].Title = req.Title
				metadata.Posts[i].Slug = slug
				metadata.Posts[i].Category = req.Category
				metadata.Posts[i].Tags = req.Tags
				metadata.Posts[i].Excerpt = getExcerpt(req.Content, 150)
				metadata.Posts[i].Cover = req.Cover
				metadata.Posts[i].UpdatedAt = time.Now()
				// 正文原子写，避免崩溃后留下半截文章。
				if e := writeFileAtomic(filepath.Join(postsDir, id+".md"), []byte(req.Content), 0600); e != nil {
					return e
				}
				return nil
			}
		}
		postMissing = true
		return errSkipSave
	})
	if slugErr != nil {
		http.Error(w, slugErr.Error(), http.StatusBadRequest)
		return
	}
	if postMissing {
		http.Error(w, "文章不存在", http.StatusNotFound)
		return
	}
	if err != nil && !errors.Is(err, errSkipSave) {
		http500(w, err)
		return
	}
	invalidatePostContent(id)
	auditLog("post-updated", r, "id="+id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var postMissing bool
	err := withMetadata(func(metadata *Metadata) error {
		newPosts := make([]Post, 0, len(metadata.Posts))
		for _, p := range metadata.Posts {
			if p.ID != id {
				newPosts = append(newPosts, p)
			}
		}
		if len(newPosts) == len(metadata.Posts) {
			postMissing = true
			return errSkipSave
		}
		metadata.Posts = newPosts
		return nil
	})
	if postMissing {
		http.Error(w, "文章不存在", http.StatusNotFound)
		return
	}
	if err != nil && !errors.Is(err, errSkipSave) {
		http500(w, err)
		return
	}

	// 先保存 metadata 再删正文：即使删除失败，也只会留下一个孤儿文件，
	// 不会出现“记录已删、正文还在”或“记录指向已删文件”。
	if err := os.Remove(filepath.Join(postsDir, id+".md")); err != nil && !os.IsNotExist(err) {
		log.Printf("删除文章正文失败 id=%s: %v", id, err)
	}
	invalidatePostContent(id)
	auditLog("post-deleted", r, "id="+id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	if !rateLimitAllow(w, "upload:"+getClientIP(r), 30, time.Hour) {
		return
	}
	if uploadsDirBytes() > maxUploadsDirBytes {
		http.Error(w, "存储空间已满，请联系管理员", http.StatusInsufficientStorage)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 12<<20)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "上传失败或文件过大", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "上传失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if handler.Size > 10<<20 {
		http.Error(w, "文件不能超过 10MB", http.StatusRequestEntityTooLarge)
		return
	}

	ext := strings.ToLower(filepath.Ext(handler.Filename))
	allowedExts := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true,
		".pdf": true, ".zip": true, ".txt": true, ".md": true,
		".mp3": true, ".mp4": true, ".webm": true,
	}
	if !allowedExts[ext] {
		http.Error(w, "不支持的文件类型", http.StatusBadRequest)
		return
	}

	// 只保留文件名部分并替换特殊字符，防止路径穿越与危险文件上传
	safeName := strings.Map(func(c rune) rune {
		switch c {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', '\x00', '\'':
			return '-'
		}
		return c
	}, filepath.Base(handler.Filename))
	if safeName == "." || safeName == ".." || strings.TrimSpace(strings.TrimSuffix(safeName, ext)) == "" {
		http.Error(w, "文件名不合法", http.StatusBadRequest)
		return
	}

	filename := fmt.Sprintf("%d-%s", time.Now().UnixNano(), safeName)
	if err := writeUploadAtomic(filename, file, 10<<20); err != nil {
		http500(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"url":      "/uploads/" + filename,
		"filename": handler.Filename,
	})
}

// requireAuth 校验管理员身份。除会话标记外，每次都回查 metadata：
// 用户被删除、被降权或 sessionVersion 已变化时，旧 cookie 立即失效。
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		if auth, ok := session.Values["admin"].(bool); !ok || !auth {
			http.Error(w, "未授权", http.StatusUnauthorized)
			return
		}
		metadata, err := loadMetadata()
		if err != nil {
			http500(w, err)
			return
		}
		if metadata.Admin == nil {
			http.Error(w, "未授权", http.StatusUnauthorized)
			return
		}
		userID, _ := session.Values["userID"].(string)
		if userID == "" {
			// 只有会话里没有用户记录的历史管理员会话才回退到 Admin 配置校验。
			if metadata.Admin.PasswordHash == "" {
				http.Error(w, "未授权", http.StatusUnauthorized)
				return
			}
			next(w, r)
			return
		}
		u := findUserByID(metadata, userID)
		if u == nil || !u.IsAdmin {
			http.Error(w, "登录状态已失效，请重新登录", http.StatusUnauthorized)
			return
		}
		if v, _ := session.Values["sessionVersion"].(int); v != u.SessionVersion {
			http.Error(w, "登录状态已失效，请重新登录", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func requireUserAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		userID, ok := session.Values["userID"].(string)
		if !ok || userID == "" {
			http.Error(w, "未授权", http.StatusUnauthorized)
			return
		}
		metadata, err := loadMetadata()
		if err != nil {
			http500(w, err)
			return
		}
		u := findUserByID(metadata, userID)
		if u == nil {
			http.Error(w, "登录状态已失效，请重新登录", http.StatusUnauthorized)
			return
		}
		if v, _ := session.Values["sessionVersion"].(int); v != u.SessionVersion {
			http.Error(w, "登录状态已失效，请重新登录", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func getExcerpt(content string, length int) string {
	// 移除 Markdown 标记
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs
	p := parser.NewWithExtensions(extensions)
	doc := p.Parse([]byte(content))

	htmlFlags := html.CommonFlags | html.HrefTargetBlank
	opts := html.RendererOptions{Flags: htmlFlags}
	renderer := html.NewRenderer(opts)

	htmlOut := string(markdown.Render(doc, renderer))

	// 剥离全部 HTML 标签：原实现只处理 <p>/<br>，标题、列表、代码块的标签会残留在摘要里
	var sb strings.Builder
	inTag := false
	for _, r := range htmlOut {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			sb.WriteRune(' ')
		case !inTag:
			sb.WriteRune(r)
		}
	}

	// 还原常见实体，并压缩连续空白
	text := strings.NewReplacer(
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", "\"",
		"&#39;", "'",
		"&nbsp;", " ",
	).Replace(sb.String())
	text = strings.Join(strings.Fields(text), " ")

	runes := []rune(text)
	if len(runes) > length {
		return string(runes[:length]) + "..."
	}
	return string(runes)
}

func uploadBackground(w http.ResponseWriter, r *http.Request) {
	if !rateLimitAllow(w, "bg-upload:"+getClientIP(r), 10, time.Hour) {
		return
	}
	if uploadsDirBytes() > maxUploadsDirBytes {
		http.Error(w, "存储空间已满，请联系管理员", http.StatusInsufficientStorage)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 6<<20)
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		http.Error(w, "上传失败或文件过大", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("background")
	if err != nil {
		http.Error(w, "上传失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if handler.Size > 5<<20 {
		http.Error(w, "背景图不能超过 5MB", http.StatusRequestEntityTooLarge)
		return
	}

	// 扩展名白名单 + Content-Type 双重校验（Content-Type 客户端可伪造，不能单独依赖）
	ext := strings.ToLower(filepath.Ext(handler.Filename))
	allowedBG := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".webp": true}
	if !allowedBG[ext] || !strings.HasPrefix(handler.Header.Get("Content-Type"), "image/") {
		http.Error(w, "只能上传 jpg/png/webp 图片", http.StatusBadRequest)
		return
	}

	filename := fmt.Sprintf("custom-bg-%d%s", time.Now().UnixNano(), ext)
	if err := writeUploadAtomic(filename, file, 5<<20); err != nil {
		http500(w, err)
		return
	}

	// 更新元数据并回收旧背景，避免反复更换把磁盘占满。
	var oldBackground string
	err = withMetadata(func(metadata *Metadata) error {
		oldBackground = metadata.CustomBackground
		metadata.CustomBackground = "/uploads/" + filename
		return nil
	})
	if err != nil {
		removeUploadByURL("/uploads/" + filename)
		http500(w, err)
		return
	}
	if oldBackground != "/uploads/"+filename {
		removeUploadByURL(oldBackground)
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"url": "/uploads/" + filename,
	})
}

func resetBackground(w http.ResponseWriter, r *http.Request) {
	var oldBackground string
	err := withMetadata(func(metadata *Metadata) error {
		oldBackground = metadata.CustomBackground
		metadata.CustomBackground = ""
		return nil
	})
	if err != nil {
		http500(w, err)
		return
	}
	removeUploadByURL(oldBackground)
	auditLog("background-reset", r, "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func resetSite(w http.ResponseWriter, r *http.Request) {
	// 删除所有文章
	files, err := os.ReadDir(postsDir)
	if err == nil {
		for _, file := range files {
			if !file.IsDir() {
				os.Remove(filepath.Join(postsDir, file.Name()))
			}
		}
	}

	// 删除所有上传文件
	files, err = os.ReadDir(uploadsDir)
	if err == nil {
		for _, file := range files {
			if !file.IsDir() {
				os.Remove(filepath.Join(uploadsDir, file.Name()))
			}
		}
	}

	// 创建默认的metadata
	defaultMetadata := &Metadata{
		SiteName:       "Ser1oux-Blog",
		SetupCompleted: false,
		SiteStartDate:  time.Now().Format("2006-01-02"),
		Posts: []Post{
			{
				ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
				Title:     "欢迎使用 Ser1oux-Blog",
				Slug:      "welcome-to-ser1oux-blog",
				Date:      time.Now().Add(-2 * time.Hour),
				CreatedAt: time.Now().Add(-2 * time.Hour),
				UpdatedAt: time.Now().Add(-2 * time.Hour),
				Category:  "技术",
				Tags:      []string{"Go", "前端"},
				Excerpt:   "欢迎使用 Ser1oux-Blog，这是一个极简、优雅的个人博客系统。本文介绍了主要特性和使用方法。",
				Cover:     "",
			},
		},
		Admin:        nil,
		SocialLinks:  []SocialLink{},
		Nickname:     "博主",
		Bio:          "这个人很懒，什么都没有留下~",
		Avatar:       "/BG/icon.jpg",
		Notice:       "欢迎来到我的博客！",
		Categories:   []string{"技术", "生活", "随笔"},
		Tags:         []string{"Go", "前端", "后端", "Docker"},
		VisitorCount: 0,
		Users:        []User{},
		AboutTitle:   "关于本站",
		AboutContent: "# 欢迎来到 Ser1oux-Blog\n\n这是一个极简、优雅的个人博客系统。\n\n## 关于博主\n\n这里的内容还没有填写。站长可以在后台「设置 → 关于页」中修改本页面。",
	}

	if err := saveMetadata(defaultMetadata); err != nil {
		http500(w, err)
		return
	}

	// 创建示例文章的内容文件
	sampleContents := map[string]string{
		"welcome-to-ser1oux-blog": "# 欢迎使用 Ser1oux-Blog\n\n这是您的第一篇示例文章！Ser1oux-Blog 是一个极简、优雅的个人博客系统。\n\n## 主要特性\n\n- 🎨 现代化的界面设计\n- 📱 完美的响应式布局\n- ✍️ Markdown 编辑支持\n- 🏷️ 分类和标签管理\n- 📊 访问统计功能\n- 🔐 用户权限管理\n\n开始您的博客之旅吧！",
	}

	// 为每篇示例文章创建内容文件
	for _, post := range defaultMetadata.Posts {
		if content, exists := sampleContents[post.Slug]; exists {
			if err := writeFileAtomic(filepath.Join(postsDir, post.ID+".md"), []byte(content), 0600); err != nil {
				log.Printf("创建示例文章内容失败: %v", err)
			}
		}
	}

	// 重置后站点回到未初始化状态：清缓存并发放新的初始化口令，
	// 否则没人能完成 setup（口令只在启动时打印过）。
	invalidateMetadataCache()
	invalidateAllPostContent()
	token := regenerateSetupToken()
	auditLog("site-reset", r, "新的初始化口令已输出到服务端日志")
	fmt.Printf("\n🔐 站点已重置。请访问 /setup 并填入一次性初始化口令: %s\n\n", token)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求", http.StatusBadRequest)
		return
	}

	if err := validateNewPassword(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http500(w, err)
		return
	}

	var smtpConfig *SMTPConfig
	var verifyErr error
	var userMissing bool
	err = withMetadata(func(metadata *Metadata) error {
		if e := verifyVerificationCode(req.Email, req.Code, "password-reset"); e != nil {
			verifyErr = e
			return e
		}
		for i := range metadata.Users {
			if emailsEqual(metadata.Users[i].Email, req.Email) {
				metadata.Users[i].PasswordHash = string(hashedPassword)
				// 改密后旧会话立即失效。
				metadata.Users[i].SessionVersion++
				syncAdminCredential(metadata, &metadata.Users[i])
				if metadata.Admin != nil {
					metadata.Admin.SessionVersion = metadata.Users[i].SessionVersion
				}
				if metadata.SMTP != nil {
					c := *metadata.SMTP
					smtpConfig = &c
				}
				return nil
			}
		}
		userMissing = true
		return errSkipSave
	})
	if verifyErr != nil {
		http.Error(w, verifyErr.Error(), http.StatusBadRequest)
		return
	}
	if userMissing {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}
	if err != nil && !errors.Is(err, errSkipSave) {
		http500(w, err)
		return
	}

	_ = deleteVerificationCode(req.Email)
	auditLog("password-changed", r, "email="+normalizeEmail(req.Email))

	// 发送密码修改成功通知邮件
	if smtpConfig != nil {
		clientIP := getClientIP(r)
		location := resolveIPLocation(clientIP)
		subject := "您的密码已修改成功"
		body := fmt.Sprintf(`您好！

您的账户密码已成功修改。

修改时间：%s
修改IP：%s
IP归属地：%s

如果这不是您的操作，请立即联系管理员！`,
			time.Now().Format("2006-01-02 15:04:05"),
			clientIP,
			location)

		sendEmail(smtpConfig, req.Email, subject, body)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func changeEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewEmail string `json:"newEmail"`
		Code     string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求", http.StatusBadRequest)
		return
	}

	// 从session获取当前用户
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}

	// 验证码校验、用户查找与写入放在同一临界区。
	var oldEmail string
	var newVersion int
	var smtpConfig *SMTPConfig
	var verifyErr error
	var userMissing bool
	err := withMetadata(func(metadata *Metadata) error {
		if e := verifyVerificationCode(req.NewEmail, req.Code, "email-change"); e != nil {
			verifyErr = e
			return e
		}
		for i := range metadata.Users {
			if metadata.Users[i].ID == userID {
				oldEmail = metadata.Users[i].Email
				metadata.Users[i].Email = req.NewEmail
				// 邮箱是登录凭据之一，换绑后其它会话必须重新登录。
				metadata.Users[i].SessionVersion++
				newVersion = metadata.Users[i].SessionVersion
				if metadata.SMTP != nil {
					c := *metadata.SMTP
					smtpConfig = &c
				}
				return nil
			}
		}
		userMissing = true
		return errSkipSave
	})
	if verifyErr != nil {
		http.Error(w, verifyErr.Error(), http.StatusBadRequest)
		return
	}
	if userMissing {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}
	if err != nil && !errors.Is(err, errSkipSave) {
		http500(w, err)
		return
	}

	_ = deleteVerificationCode(req.NewEmail)

	// 当前会话同步到新版本，其他设备上的旧会话失效。
	session.Values["sessionVersion"] = newVersion
	session.Save(r, w)
	auditLog("email-changed", r, "email="+normalizeEmail(req.NewEmail))

	// 发送换绑成功通知邮件到旧邮箱
	if smtpConfig != nil && oldEmail != "" {
		clientIP := getClientIP(r)
		location := resolveIPLocation(clientIP)
		subject := "您的账号邮箱已换绑"
		body := fmt.Sprintf(`您好！

您的账户邮箱已成功换绑。

换绑时间：%s
换绑IP：%s
IP归属地：%s
新邮箱：%s

如果这不是您的操作，请立即联系管理员！`,
			time.Now().Format("2006-01-02 15:04:05"),
			clientIP,
			location,
			req.NewEmail)

		sendEmail(smtpConfig, oldEmail, subject, body)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	if !rateLimitAllow(w, "reset-pw:"+getClientIP(r), 10, time.Hour) {
		return
	}
	var req struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求", http.StatusBadRequest)
		return
	}

	if err := validateNewPassword(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http500(w, err)
		return
	}

	var smtpConfig *SMTPConfig
	var verifyErr error
	var userMissing bool
	err = withMetadata(func(metadata *Metadata) error {
		if e := verifyVerificationCode(req.Email, req.Code, "password-reset"); e != nil {
			verifyErr = e
			return e
		}
		for i := range metadata.Users {
			if emailsEqual(metadata.Users[i].Email, req.Email) {
				metadata.Users[i].PasswordHash = string(hashedPassword)
				metadata.Users[i].SessionVersion++
				syncAdminCredential(metadata, &metadata.Users[i])
				if metadata.Admin != nil {
					metadata.Admin.SessionVersion = metadata.Users[i].SessionVersion
				}
				if metadata.SMTP != nil {
					c := *metadata.SMTP
					smtpConfig = &c
				}
				return nil
			}
		}
		userMissing = true
		return errSkipSave
	})
	if verifyErr != nil {
		http.Error(w, verifyErr.Error(), http.StatusBadRequest)
		return
	}
	if userMissing {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}
	if err != nil && !errors.Is(err, errSkipSave) {
		http500(w, err)
		return
	}

	_ = deleteVerificationCode(req.Email)
	auditLog("password-reset", r, "email="+normalizeEmail(req.Email))

	// 发送密码修改成功通知邮件
	if smtpConfig != nil {
		clientIP := getClientIP(r)
		location := resolveIPLocation(clientIP)
		subject := "您的密码已修改成功"
		body := fmt.Sprintf(`您好！

您的账户密码已成功修改（找回密码）。

修改时间：%s
修改IP：%s
IP归属地：%s

如果这不是您的操作，请立即联系管理员！`,
			time.Now().Format("2006-01-02 15:04:05"),
			clientIP,
			location)

		sendEmail(smtpConfig, req.Email, subject, body)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// publicSettings 公开的站点设置。此接口前台页面任何人可访问，
// 因此只允许暴露非敏感字段；管理员、用户、SMTP 等数据绝不能出现在响应里。
type publicSettings struct {
	SiteName         string       `json:"siteName,omitempty"`
	Nickname         string       `json:"nickname,omitempty"`
	Avatar           string       `json:"avatar,omitempty"`
	Bio              string       `json:"bio,omitempty"`
	GitHubURL        string       `json:"githubUrl,omitempty"`
	EmailAddress     string       `json:"emailAddress,omitempty"`
	SocialLinks      []SocialLink `json:"socialLinks,omitempty"`
	Notice           string       `json:"notice,omitempty"`
	CustomBackground string       `json:"customBackground,omitempty"`
	Categories       []string     `json:"categories,omitempty"`
	Tags             []string     `json:"tags,omitempty"`
	SiteStartDate    string       `json:"siteStartDate,omitempty"`
	VisitorCount     int          `json:"visitorCount"`
	SetupCompleted   bool         `json:"setupCompleted"`
}

func getSettings(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	resp := publicSettings{
		SiteName:         metadata.SiteName,
		Nickname:         metadata.Nickname,
		Avatar:           metadata.Avatar,
		Bio:              metadata.Bio,
		GitHubURL:        metadata.GitHubURL,
		EmailAddress:     metadata.EmailAddress,
		SocialLinks:      metadata.SocialLinks,
		Notice:           metadata.Notice,
		CustomBackground: metadata.CustomBackground,
		Categories:       metadata.Categories,
		Tags:             metadata.Tags,
		SiteStartDate:    metadata.SiteStartDate,
		VisitorCount:     metadata.VisitorCount,
		SetupCompleted:   metadata.SetupCompleted,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdateSettingsRequest 采用指针字段，用于区分"未提交"与"提交了空值"。
// 前端设置页并不会每次提交所有字段（例如未换头像时不发 avatar），
// 若用值类型接收，未提交的字段会被零值覆盖，导致头像 / 邮箱 / GitHub 链接被清空。
type UpdateSettingsRequest struct {
	SiteName      *string       `json:"siteName"`
	GitHubURL     *string       `json:"githubUrl"`
	EmailAddress  *string       `json:"emailAddress"`
	Avatar        *string       `json:"avatar"`
	Nickname      *string       `json:"nickname"`
	Bio           *string       `json:"bio"`
	SocialLinks   *[]SocialLink `json:"socialLinks"`
	Categories    *[]string     `json:"categories"`
	Tags          *[]string     `json:"tags"`
	Notice        *string       `json:"notice"`
	SiteStartDate *string       `json:"siteStartDate"`
}

func updateSettings(w http.ResponseWriter, r *http.Request) {
	var req UpdateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 逐个字段判断：只有请求中显式出现的字段才更新，未出现的保留原值。
	// 整个读-改-写放在同一临界区，避免设置页与其它写操作互相覆盖。
	err := withMetadata(func(metadata *Metadata) error {
		if req.SiteName != nil {
			metadata.SiteName = *req.SiteName
		}
		if req.GitHubURL != nil {
			metadata.GitHubURL = *req.GitHubURL
		}
		if req.EmailAddress != nil {
			metadata.EmailAddress = *req.EmailAddress
		}
		if req.Avatar != nil {
			metadata.Avatar = *req.Avatar
		}
		if req.Nickname != nil {
			metadata.Nickname = *req.Nickname
		}
		if req.Bio != nil {
			metadata.Bio = *req.Bio
		}
		if req.SocialLinks != nil {
			// 社交链接允许留空：过滤空壳条目，并且只保留 http/https 地址，
			// 防止管理员（或被接管的账号）写入 javascript: 造成点击即执行。
			cleaned := make([]SocialLink, 0, len(*req.SocialLinks))
			for _, l := range *req.SocialLinks {
				if strings.TrimSpace(l.URL) == "" {
					continue
				}
				if !isSafePublicURL(l.URL) {
					continue
				}
				cleaned = append(cleaned, l)
			}
			metadata.SocialLinks = cleaned
		}
		if req.Categories != nil {
			metadata.Categories = *req.Categories
		}
		if req.Tags != nil {
			metadata.Tags = *req.Tags
		}
		if req.Notice != nil {
			metadata.Notice = *req.Notice
		}
		if req.SiteStartDate != nil {
			metadata.SiteStartDate = *req.SiteStartDate
		}
		return nil
	})
	if err != nil {
		http500(w, err)
		return
	}
	auditLog("settings-updated", r, "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func checkSetup(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata, err := loadMetadata()
		if err != nil {
			http500(w, err)
			return
		}

		// 如果未完成设置，重定向到设置页面
		if !metadata.SetupCompleted {
			http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
			return
		}

		next(w, r)
	}
}

func checkSetupMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata, err := loadMetadata()
		if err != nil {
			http500(w, err)
			return
		}

		// 如果未完成设置，重定向到设置页面
		if !metadata.SetupCompleted {
			http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func blockSetupIfCompleted(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata, err := loadMetadata()
		if err != nil {
			http500(w, err)
			return
		}

		// 如果已经完成设置，重定向到首页
		if metadata.SetupCompleted {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		next(w, r)
	}
}

// 访客去重：同一 IP + UA 每天只计一次，避免刷新页面重复累加。
// 内存态即可：进程重启后当天已访问者会再计一次，对个人站点可接受。
var (
	visitMu   sync.Mutex
	visitDay  string
	visitSeen = make(map[string]struct{})
)

// visitorFingerprint 生成访客指纹（IP + User-Agent 的哈希，不落盘明文）
func visitorFingerprint(r *http.Request) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(getClientIP(r)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(r.Header.Get("User-Agent")))
	return strconv.FormatUint(h.Sum64(), 16)
}

// isCrawler 过滤机器流量：只把带浏览器特征（Mozilla/）且不含爬虫关键字的请求算作访客。
// 这样 curl / python-requests / RSS 阅读器等脚本不会被计入访客数。
func isCrawler(r *http.Request) bool {
	ua := strings.ToLower(strings.TrimSpace(r.Header.Get("User-Agent")))
	if !strings.Contains(ua, "mozilla") {
		return true
	}
	for _, k := range []string{"bot", "spider", "crawl", "scan", "headless", "monitor", "preview", "phantom", "slurp", "lighthouse"} {
		if strings.Contains(ua, k) {
			return true
		}
	}
	return false
}

// shouldCountVisit 判断本次访问是否应计入统计
func shouldCountVisit(r *http.Request) bool {
	if isCrawler(r) {
		return false
	}
	today := time.Now().Format("2006-01-02")
	fp := visitorFingerprint(r)

	visitMu.Lock()
	defer visitMu.Unlock()

	if visitDay != today {
		visitDay = today
		visitSeen = make(map[string]struct{})
	}
	if _, ok := visitSeen[fp]; ok {
		return false
	}
	// 防御：伪造海量指纹撑爆内存时整体重置
	if len(visitSeen) > 200000 {
		visitSeen = make(map[string]struct{})
	}
	visitSeen[fp] = struct{}{}
	return true
}

func trackVisitor(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 按“独立访客/天”计，而非每次请求
		if shouldCountVisit(r) {
			_ = withMetadata(func(metadata *Metadata) error {
				metadata.VisitorCount++
				return nil
			})
			bumpDailyVisitor()
		}
		next(w, r)
	}
}

func checkSetupStatus(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"setupCompleted": metadata.SetupCompleted,
		"siteName":       metadata.SiteName,
	})
}

func debugMetadata(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":              err.Error(),
			"metadataFileExists": false,
		})
		return
	}

	// 检查metadata.json文件是否存在
	_, fileErr := os.Stat(metadataFile)

	adminUsername := ""
	if metadata.Admin != nil {
		adminUsername = metadata.Admin.Username
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"setupCompleted":     metadata.SetupCompleted,
		"siteName":           metadata.SiteName,
		"adminUsername":      adminUsername,
		"metadataFileExists": fileErr == nil,
		"metadataFilePath":   metadataFile,
		"hasUsers":           len(metadata.Users) > 0,
		"userCount":          len(metadata.Users),
	})
}

type SetupRequest struct {
	SiteName string `json:"siteName"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	// SetupToken 一次性初始化口令，由服务端启动日志输出。
	SetupToken string `json:"setupToken"`
}

func setupSite(w http.ResponseWriter, r *http.Request) {
	// 初始化只允许成功一次：串行化避免并发请求各自创建一个管理员。
	setupMu.Lock()
	defer setupMu.Unlock()

	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	// 如果已经完成设置，拒绝请求
	if metadata.SetupCompleted {
		http.Error(w, "站点已经完成设置", http.StatusBadRequest)
		return
	}

	var req SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求", http.StatusBadRequest)
		return
	}

	// 一次性口令：没有它，任何人抢先访问 /api/setup 都能注册成管理员。
	token := req.SetupToken
	if token == "" {
		token = r.Header.Get("X-Setup-Token")
	}
	if !validSetupToken(token) {
		auditLog("setup-rejected", r, "初始化口令不正确")
		http.Error(w, "初始化口令无效，请查看服务端日志", http.StatusForbidden)
		return
	}

	// 验证输入
	if req.SiteName == "" || req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "所有字段都是必填的", http.StatusBadRequest)
		return
	}

	if uname, err := validateUsername(req.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else {
		req.Username = uname
	}

	if err := validateNewPassword(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 加密密码
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http500(w, err)
		return
	}

	// 创建管理员用户
	adminUser := User{
		ID:             fmt.Sprintf("%d", time.Now().UnixNano()),
		Username:       req.Username,
		Email:          req.Email,
		PasswordHash:   string(hash),
		Avatar:         "/BG/icon.jpg",
		IsAdmin:        true,
		CreatedAt:      time.Now(),
		Verified:       true,
		SessionVersion: 1,
	}

	// 保存设置
	metadata.SiteName = req.SiteName
	metadata.Admin = &AdminConfig{
		Username:       req.Username,
		PasswordHash:   string(hash),
		SessionVersion: 1,
	}
	metadata.Users = append(metadata.Users, adminUser)
	metadata.SetupCompleted = true

	// 创建默认内容（如果还没有）
	if len(metadata.Posts) == 0 {
		// 创建默认文章
		metadata.Posts = []Post{
			{
				ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
				Title:     "欢迎使用 Ser1oux-Blog",
				Slug:      "welcome-to-ser1oux-blog",
				Date:      time.Now().Add(-2 * time.Hour),
				CreatedAt: time.Now().Add(-2 * time.Hour),
				UpdatedAt: time.Now().Add(-2 * time.Hour),
				Category:  "技术",
				Tags:      []string{"Go", "前端"},
				Excerpt:   "欢迎使用 Ser1oux-Blog，这是一个极简、优雅的个人博客系统。本文介绍了主要特性和使用方法。",
				Cover:     "",
			},
		}
	}

	// 设置默认分类和标签（如果还没有）
	if len(metadata.Categories) == 0 {
		metadata.Categories = []string{"技术", "生活", "随笔"}
	}
	if len(metadata.Tags) == 0 {
		metadata.Tags = []string{"Go", "前端", "后端", "Docker"}
	}

	// 设置默认个人信息（如果还没有）
	if metadata.Nickname == "" {
		metadata.Nickname = "博主"
	}
	if metadata.Bio == "" {
		metadata.Bio = "这个人很懒，什么都没有留下~"
	}
	if metadata.Avatar == "" {
		metadata.Avatar = "/BG/icon.jpg"
	}
	if metadata.Notice == "" {
		metadata.Notice = "欢迎来到我的博客！"
	}
	if metadata.AboutTitle == "" {
		metadata.AboutTitle = "关于本站"
	}
	if metadata.AboutContent == "" {
		metadata.AboutContent = "# 欢迎来到 Ser1oux-Blog\n\n这是一个极简、优雅的个人博客系统。\n\n## 关于博主\n\n这里的内容还没有填写。站长可以在后台「设置 → 关于页」中修改本页面。"
	}

	if err := saveMetadata(metadata); err != nil {
		http500(w, err)
		return
	}

	// 创建示例文章的内容文件（如果文章是新创建的）
	if len(metadata.Posts) > 0 {
		sampleContents := map[string]string{
			"welcome-to-ser1oux-blog": "# 欢迎使用 Ser1oux-Blog\n\n这是您的第一篇示例文章！Ser1oux-Blog 是一个极简、优雅的个人博客系统。\n\n## 主要特性\n\n- 🎨 现代化的界面设计\n- 📱 完美的响应式布局\n- ✍️ Markdown 编辑支持\n- 🏷️ 分类和标签管理\n- 📊 访问统计功能\n- 🔐 用户权限管理\n\n开始您的博客之旅吧！",
		}

		// 为每篇示例文章创建内容文件
		for _, post := range metadata.Posts {
			if content, exists := sampleContents[post.Slug]; exists {
				filePath := filepath.Join(postsDir, post.ID+".md")
				// 只有文件不存在时才创建
				if _, err := os.Stat(filePath); os.IsNotExist(err) {
					if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
						log.Printf("创建示例文章内容失败: %v", err)
					}
				}
			}
		}
	}

	// 自动登录
	session, _ := store.Get(r, "session")
	session.Values["admin"] = true
	session.Values["userID"] = adminUser.ID
	session.Values["username"] = adminUser.Username
	session.Values["isAdmin"] = true
	session.Values["sessionVersion"] = adminUser.SessionVersion
	session.Save(r, w)

	auditLog("setup-completed", r, "username="+adminUser.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

type FileInfo struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Size int64  `json:"size"`
}

func listFiles(w http.ResponseWriter, r *http.Request) {
	files, err := os.ReadDir(uploadsDir)
	if err != nil {
		http500(w, err)
		return
	}

	var fileList []FileInfo
	for _, file := range files {
		if !file.IsDir() {
			info, err := file.Info()
			if err != nil {
				continue
			}
			fileList = append(fileList, FileInfo{
				Name: file.Name(),
				URL:  "/uploads/" + file.Name(),
				Size: info.Size(),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fileList)
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := vars["filename"]

	// 安全检查：拒绝路径分隔符（含 Windows 反斜杠）、穿越与任何非基名输入
	if strings.ContainsAny(filename, "/\\") || strings.Contains(filename, "..") || filename != filepath.Base(filename) {
		http.Error(w, "无效的文件名", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(uploadsDir, filename)
	root, err := filepath.Abs(uploadsDir)
	if err != nil {
		http500(w, err)
		return
	}
	abs, err := filepath.Abs(filePath)
	if err != nil || abs != filepath.Join(root, filename) {
		http.Error(w, "无效的文件名", http.StatusBadRequest)
		return
	}
	if err := os.Remove(abs); err != nil {
		http500(w, err)
		return
	}
	auditLog("file-deleted", r, "name="+filename)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func exportDataAPI(w http.ResponseWriter, r *http.Request) {
	path, err := exportData()
	if err != nil {
		http500(w, err)
		return
	}
	defer os.Remove(path)

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=gl-blog-backup-%s.tar.gz", time.Now().Format("20060102-150405")))
	// 直接流式发送，避免把整个备份读进内存（峰值内存约为包大小的两倍）。
	http.ServeFile(w, r, path)

	auditLog("export-completed", r, "")
}

func importDataAPI(w http.ResponseWriter, r *http.Request) {
	// 导入合法上限 256MB；仍然有界，不会把内存/磁盘写穿。
	r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Error(w, "上传失败或文件过大", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "上传失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp(dataDir, "import-*.tar.gz")
	if err != nil {
		http500(w, err)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, io.LimitReader(file, 256<<20)); err != nil {
		tmp.Close()
		http500(w, err)
		return
	}
	if err := tmp.Close(); err != nil {
		http500(w, err)
		return
	}

	if err := importData(tmpName); err != nil {
		auditLog("import-failed", r, err.Error())
		http500(w, err)
		return
	}

	// 导入会替换磁盘上的 data/，必须同时清掉内存缓存，否则页面仍读旧数据。
	invalidateMetadataCache()
	invalidateAllPostContent()
	auditLog("import-completed", r, "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 用户注册
func userRegister(w http.ResponseWriter, r *http.Request) {
	if !rateLimitAllow(w, "register:"+getClientIP(r), 5, time.Hour) {
		return
	}
	var req struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求")
		return
	}

	username, err := validateUsername(req.Username)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Email = normalizeEmail(req.Email)

	if err := validateNewPassword(req.Password); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 创建用户
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http500(w, err)
		return
	}

	userID := fmt.Sprintf("%d", time.Now().UnixNano())
	user := User{
		ID:             userID,
		Username:       username,
		Email:          req.Email,
		PasswordHash:   string(hashedPassword),
		Avatar:         defaultAvatarURL(userID),
		IsAdmin:        false,
		CreatedAt:      time.Now(),
		Verified:       true,
		SessionVersion: 1,
	}

	// 验证码、邮箱/用户名查重与写入必须在同一临界区，
	// 否则并发注册会互相覆盖 metadata，出现“返回成功但账号不存在”。
	var bizErr error
	err = withMetadata(func(metadata *Metadata) error {
		if e := verifyVerificationCode(req.Email, req.Code, "register"); e != nil {
			bizErr = e
			return e
		}
		for _, u := range metadata.Users {
			if emailsEqual(u.Email, req.Email) {
				bizErr = errors.New("该邮箱已被注册")
				return bizErr
			}
		}
		if usernameTaken(metadata, username, "") {
			bizErr = errors.New("该用户名已被占用")
			return bizErr
		}
		metadata.Users = append(metadata.Users, user)
		return nil
	})
	if bizErr != nil {
		writeJSONError(w, http.StatusBadRequest, bizErr.Error())
		return
	}
	if err != nil {
		http500(w, err)
		return
	}

	_ = deleteVerificationCode(req.Email)
	auditLog("user-registered", r, "username="+user.Username)

	// 自动登录
	session, _ := store.Get(r, "session")
	session.Values["userID"] = user.ID
	session.Values["username"] = user.Username
	session.Values["isAdmin"] = user.IsAdmin
	session.Values["sessionVersion"] = user.SessionVersion
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user":    toPublicUser(&user),
	})
}

// 用户登录
func userLogin(w http.ResponseWriter, r *http.Request) {
	if !rateLimitAllow(w, "user-login:"+getClientIP(r), 15, 15*time.Minute) {
		return
	}
	var req struct {
		Email    string `json:"email"`
		Account  string `json:"account"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求")
		return
	}

	account := strings.TrimSpace(req.Account)
	if account == "" {
		account = strings.TrimSpace(req.Email)
	}
	if account == "" {
		account = strings.TrimSpace(req.Username)
	}

	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	user := findUserByLogin(metadata, account)
	if user == nil {
		// 账号不存在时也做一次 bcrypt 比较，抹平“存在/不存在”的响应时间差。
		dummyPasswordCompare(req.Password)
		writeJSONError(w, http.StatusUnauthorized, "邮箱/用户名或密码错误")
		return
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "邮箱/用户名或密码错误")
		return
	}

	// 设置会话。admin 必须显式赋值：同一浏览器残留的管理员标记
	// 不能被普通账号继承（旧实现只在 IsAdmin 为真时写成 true）。
	session, _ := store.Get(r, "session")
	session.Values["userID"] = user.ID
	session.Values["username"] = user.Username
	session.Values["isAdmin"] = user.IsAdmin
	session.Values["admin"] = user.IsAdmin
	session.Values["sessionVersion"] = user.SessionVersion
	session.Save(r, w)

	// 发送登录提醒邮件（受限异步，不阻塞登录）
	if metadata.SMTP != nil {
		// handler 返回后 *http.Request 可能被复用，先取好 IP 再进 goroutine
		loginIP := getClientIP(r)
		smtpCfg := metadata.SMTP
		sendEmailAsync(func() {
			location := getIPLocation(loginIP)
			username := user.Username
			if user.Nickname != "" {
				username = user.Nickname
			}
			siteName := metadata.SiteName
			if siteName == "" {
				siteName = "博客"
			}
			sendLoginNotification(smtpCfg, user.Email, username, siteName, loginIP, location, time.Now())
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user":    toPublicUser(user),
	})
}

// 获取用户信息
func getUserInfo(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "未授权", http.StatusUnauthorized)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	// 查找用户
	for i := range metadata.Users {
		if metadata.Users[i].ID == userID {
			writeJSON(w, http.StatusOK, toPublicUser(&metadata.Users[i]))
			return
		}
	}

	http.Error(w, "用户不存在", http.StatusNotFound)
}

// 更新用户资料
func updateUserProfile(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "未授权", http.StatusUnauthorized)
		return
	}

	var req struct {
		Username string `json:"username"`
		Nickname string `json:"nickname"`
		Avatar   string `json:"avatar"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求")
		return
	}

	username, err := validateUsername(req.Username)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 头像仅允许站内路径，昵称去控制字符并限长，防止存储型 XSS 与属性注入
	avatar := strings.TrimSpace(req.Avatar)
	if !isValidAvatarURL(avatar) {
		writeJSONError(w, http.StatusBadRequest, "头像地址不合法，请重新上传头像")
		return
	}
	nickname := sanitizeDisplayText(strings.TrimSpace(req.Nickname))
	if utf8.RuneCountInString(nickname) > 30 {
		writeJSONError(w, http.StatusBadRequest, "昵称不能超过30个字符")
		return
	}

	// 查重与写入在同一临界区。
	var nameTaken bool
	var userMissing bool
	err = withMetadata(func(metadata *Metadata) error {
		if usernameTaken(metadata, username, userID) {
			nameTaken = true
			return errSkipSave
		}
		for i := range metadata.Users {
			if metadata.Users[i].ID == userID {
				metadata.Users[i].Username = username
				metadata.Users[i].Nickname = nickname
				metadata.Users[i].Avatar = avatar

				// 如果是管理员，同时更新首页显示的头像和昵称
				if metadata.Users[i].IsAdmin {
					metadata.Avatar = avatar
					metadata.Nickname = nickname
				}
				return nil
			}
		}
		userMissing = true
		return errSkipSave
	})
	if nameTaken {
		writeJSONError(w, http.StatusBadRequest, "该用户名已被占用")
		return
	}
	if userMissing {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}
	if err != nil && !errors.Is(err, errSkipSave) {
		http500(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 获取所有用户（管理员功能）。只返回公开字段，绝不带 passwordHash。
func getAllUsers(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	users := make([]publicUser, 0, len(metadata.Users))
	for i := range metadata.Users {
		users = append(users, toPublicUser(&metadata.Users[i]))
	}

	writeJSON(w, http.StatusOK, users)
}

// 更新用户角色（管理员功能）
func updateUserRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID  string `json:"userId"`
		IsAdmin bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 查找并更新用户角色
	var bizErr error
	var roleMissing bool
	err := withMetadata(func(metadata *Metadata) error {
		for i := range metadata.Users {
			if metadata.Users[i].ID == req.UserID {
				// 不能修改第一个用户（站长）的权限
				if i == 0 {
					bizErr = errors.New("不能修改站长权限")
					return errSkipSave
				}
				metadata.Users[i].IsAdmin = req.IsAdmin
				// 角色变化后旧会话立即失效。
				metadata.Users[i].SessionVersion++
				return nil
			}
		}
		roleMissing = true
		return errSkipSave
	})
	if bizErr != nil {
		http.Error(w, bizErr.Error(), http.StatusForbidden)
		return
	}
	if roleMissing {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}
	if err != nil && !errors.Is(err, errSkipSave) {
		http500(w, err)
		return
	}

	auditLog("user-role-changed", r, fmt.Sprintf("target=%s isAdmin=%v", req.UserID, req.IsAdmin))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 删除用户（管理员功能）
func deleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	// 查找与删除在同一临界区，避免并发写覆盖彼此。
	var bizErr error
	var userMissing bool
	err := withMetadata(func(metadata *Metadata) error {
		userIndex := -1
		for i := range metadata.Users {
			if metadata.Users[i].ID == userID {
				// 不能删除第一个用户（站长）
				if i == 0 {
					bizErr = errors.New("不能删除站长账号")
					return errSkipSave
				}
				userIndex = i
				break
			}
		}
		if userIndex == -1 {
			userMissing = true
			return errSkipSave
		}
		metadata.Users = append(metadata.Users[:userIndex], metadata.Users[userIndex+1:]...)
		return nil
	})
	if bizErr != nil {
		http.Error(w, bizErr.Error(), http.StatusForbidden)
		return
	}
	if userMissing {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}
	if err != nil && !errors.Is(err, errSkipSave) {
		http500(w, err)
		return
	}

	auditLog("user-deleted", r, "target="+userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 发送验证码
func sendVerificationCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Type  string `json:"type"` // register or login
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Email = normalizeEmail(req.Email)
	if req.Email == "" {
		http.Error(w, "请输入邮箱", http.StatusBadRequest)
		return
	}
	if !strings.Contains(req.Email, "@") || !strings.Contains(req.Email, ".") {
		http.Error(w, "请输入有效的邮箱地址", http.StatusBadRequest)
		return
	}
	// 限流：同 IP 每小时 10 次、同邮箱每 10 分钟 3 次，防止邮件轰炸
	if !rateLimitAllow(w, "sendcode-ip:"+getClientIP(r), 10, time.Hour) {
		return
	}
	if !rateLimitAllow(w, "sendcode-email:"+req.Email, 3, 10*time.Minute) {
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	// 检查SMTP配置
	if metadata.SMTP == nil {
		http.Error(w, "邮件服务未配置，请联系管理员", http.StatusInternalServerError)
		return
	}

	code, err := generateDigitCode(6)
	if err != nil {
		http.Error(w, "生成验证码失败", http.StatusInternalServerError)
		return
	}

	// 验证码单独存，避免首页访客统计等写 metadata 时把未使用的码覆盖掉
	if err := saveVerificationCode(req.Email, code, req.Type); err != nil {
		http500(w, err)
		return
	}

	// 根据类型设置邮件主题和内容
	subject := "邮箱验证码"
	if req.Type == "register" {
		subject = "注册验证码"
	} else if req.Type == "login" {
		subject = "登录验证码"
	} else if req.Type == "password-reset" {
		subject = "找回密码"
	} else if req.Type == "email-change" {
		subject = "账号邮箱换绑"
	}

	body := fmt.Sprintf(`您好！

您的验证码是：%s

验证码将在10分钟后过期，请尽快使用。

如果这不是您的操作，请忽略此邮件。`, code)

	// 发送邮件
	if err := sendEmail(metadata.SMTP, req.Email, subject, body); err != nil {
		http.Error(w, "发送邮件失败："+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 解析浏览器与操作系统（简化版，够评论展示用）
func parseUserAgent(ua string) (browser, osName string) {
	if strings.TrimSpace(ua) == "" {
		return "未知浏览器", "未知系统"
	}
	u := ua

	switch {
	case strings.Contains(u, "Windows NT 10") || strings.Contains(u, "Windows NT 11"):
		osName = "Windows"
	case strings.Contains(u, "Windows"):
		osName = "Windows"
	case strings.Contains(u, "iPhone"):
		osName = "iPhone"
	case strings.Contains(u, "iPad"):
		osName = "iPad"
	case strings.Contains(u, "Android"):
		osName = "Android"
	case strings.Contains(u, "Mac OS X") || strings.Contains(u, "Macintosh"):
		osName = "macOS"
	case strings.Contains(u, "Linux"):
		osName = "Linux"
	default:
		osName = "未知系统"
	}

	switch {
	case strings.Contains(u, "MicroMessenger"):
		browser = "微信"
	case strings.Contains(u, "Edg/"):
		browser = "Edge"
	case strings.Contains(u, "OPR/") || strings.Contains(u, "Opera"):
		browser = "Opera"
	case strings.Contains(u, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(u, "Chrome/") && !strings.Contains(u, "Edg/"):
		browser = "Chrome"
	case strings.Contains(u, "Safari/") && !strings.Contains(u, "Chrome"):
		browser = "Safari"
	default:
		browser = "未知浏览器"
	}
	return browser, osName
}

// 发送登录提醒邮件（站点名称取自后台设置的 siteName，不再写死原作者站名）
func sendLoginNotification(smtpConfig *SMTPConfig, email, username, siteName, ip, location string, loginTime time.Time) error {
	if siteName == "" {
		siteName = "博客"
	}
	subject := siteName + " - 登录提醒"
	body := fmt.Sprintf(`尊敬的 %s：

您刚刚登录了「%s」。

登录信息：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
登录时间：%s
IP地址：  %s
IP归属地：%s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

如果这不是您本人的操作，请立即修改密码并联系管理员。

此邮件由系统自动发送，请勿直接回复。`,
		username,
		siteName,
		loginTime.Format("2006年01月02日 15:04:05"),
		ip,
		location)

	return sendEmail(smtpConfig, email, subject, body)
}

func sendEmail(smtpConfig *SMTPConfig, to, subject, body string) error {
	from := smtpConfig.Username
	password := smtpConfig.Password
	host := smtpConfig.Server
	addr := net.JoinHostPort(host, strconv.Itoa(smtpConfig.Port))

	// 构建邮件内容（头部字段过滤换行，防止 CRLF 头注入）
	msg := []byte("To: " + sanitizeHeader(to) + "\r\n" +
		"From: " + sanitizeHeader(smtpConfig.DisplayName) + " <" + sanitizeHeader(from) + ">\r\n" +
		"Subject: " + sanitizeHeader(subject) + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body + "\r\n")

	// 认证信息
	auth := smtp.PlainAuth("", from, password, host)

	// 根据加密方式选择不同的发送方法
	if smtpConfig.Encryption == "SSL" {
		// SSL加密 (端口465)
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: false,
		}

		// 建立TLS连接（带连接超时，避免邮件服务器不响应时请求永久挂起）
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: smtpDialTimeout}, "tcp", addr, tlsConfig)
		if err != nil {
			log.Printf("SSL连接失败: %v", err)
			return fmt.Errorf("SSL连接失败: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(smtpIOTimeout))

		// 创建SMTP客户端
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			log.Printf("创建SMTP客户端失败: %v", err)
			return fmt.Errorf("创建SMTP客户端失败: %v", err)
		}
		defer client.Close()

		// 认证
		if err = client.Auth(auth); err != nil {
			log.Printf("SMTP认证失败: %v", err)
			return fmt.Errorf("SMTP认证失败，请检查用户名和密码: %v", err)
		}

		// 设置发件人
		if err = client.Mail(from); err != nil {
			return fmt.Errorf("设置发件人失败: %v", err)
		}

		// 设置收件人
		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("设置收件人失败: %v", err)
		}

		// 发送邮件正文
		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("发送邮件数据失败: %v", err)
		}
		_, err = w.Write(msg)
		if err != nil {
			return fmt.Errorf("写入邮件内容失败: %v", err)
		}
		err = w.Close()
		if err != nil {
			return fmt.Errorf("关闭邮件写入失败: %v", err)
		}

		client.Quit()
	} else if smtpConfig.Encryption == "TLS" {
		// STARTTLS (端口587)
		conn, err := net.DialTimeout("tcp", addr, smtpDialTimeout)
		if err != nil {
			log.Printf("连接SMTP服务器失败: %v", err)
			return fmt.Errorf("连接SMTP服务器失败: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(smtpIOTimeout))

		client, err := smtp.NewClient(conn, host)
		if err != nil {
			log.Printf("创建SMTP客户端失败: %v", err)
			return fmt.Errorf("创建SMTP客户端失败: %v", err)
		}
		defer client.Close()

		// STARTTLS
		tlsConfig := &tls.Config{ServerName: host}
		if err = client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS失败: %v", err)
		}

		// 认证
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP认证失败: %v", err)
		}

		// 设置发件人和收件人
		if err = client.Mail(from); err != nil {
			return fmt.Errorf("设置发件人失败: %v", err)
		}
		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("设置收件人失败: %v", err)
		}

		// 发送邮件
		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("发送邮件数据失败: %v", err)
		}
		_, err = w.Write(msg)
		if err != nil {
			return fmt.Errorf("写入邮件内容失败: %v", err)
		}
		w.Close()
		client.Quit()
	} else {
		// 无加密。smtp.SendMail 内部使用无超时的 Dial，这里改用带超时的连接。
		conn, err := net.DialTimeout("tcp", addr, smtpDialTimeout)
		if err != nil {
			log.Printf("连接SMTP服务器失败: %v", err)
			return fmt.Errorf("连接SMTP服务器失败: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(smtpIOTimeout))

		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("创建SMTP客户端失败: %v", err)
		}
		defer client.Close()

		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP认证失败: %v", err)
		}
		if err = client.Mail(from); err != nil {
			return fmt.Errorf("设置发件人失败: %v", err)
		}
		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("设置收件人失败: %v", err)
		}
		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("发送邮件数据失败: %v", err)
		}
		if _, err = w.Write(msg); err != nil {
			return fmt.Errorf("写入邮件内容失败: %v", err)
		}
		if err = w.Close(); err != nil {
			return fmt.Errorf("关闭邮件写入失败: %v", err)
		}
		client.Quit()
	}

	log.Printf("成功发送邮件到 %s: %s", to, subject)
	return nil
}

// 获取SMTP配置
func getSMTPConfig(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	if metadata.SMTP == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"configured": false,
		})
		return
	}

	// 返回包括密码在内的所有配置（管理员可见）
	config := map[string]interface{}{
		"configured":  true,
		"server":      metadata.SMTP.Server,
		"port":        metadata.SMTP.Port,
		"username":    metadata.SMTP.Username,
		"password":    metadata.SMTP.Password,
		"displayName": metadata.SMTP.DisplayName,
		"encryption":  metadata.SMTP.Encryption,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// 更新SMTP配置
func updateSMTPConfig(w http.ResponseWriter, r *http.Request) {
	var config SMTPConfig

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := withMetadata(func(metadata *Metadata) error {
		// 如果密码为空且已有配置，保留原密码
		if config.Password == "" && metadata.SMTP != nil {
			config.Password = metadata.SMTP.Password
		}
		metadata.SMTP = &config
		return nil
	})
	if err != nil {
		http500(w, err)
		return
	}
	auditLog("smtp-updated", r, "server="+config.Server)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 测试SMTP配置
func testSMTP(w http.ResponseWriter, r *http.Request) {
	var config SMTPConfig

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 发送测试邮件
	testSubject := "SMTP配置测试"
	testBody := "这是一封测试邮件，用于验证SMTP配置是否正确。\n\n如果您收到这封邮件，说明SMTP配置成功！\n\n" + config.DisplayName

	err := sendEmail(&config, config.Username, testSubject, testBody)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "测试邮件已发送",
	})
}

// 获取关于页内容
func getAbout(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http500(w, err)
		return
	}

	// 如果没有设置关于页内容，返回默认内容
	title := metadata.AboutTitle
	content := metadata.AboutContent

	if title == "" {
		title = "关于本站"
	}

	if content == "" {
		content = `# 欢迎来到 Ser1oux-Blog

这是一个极致轻量化的个人博客系统，专注于简洁、优雅的写作与阅读体验。

## 关于博主

这里的内容还没有填写。站长可以在后台「设置 → 关于页」中修改本页面。

## 博客特色

- ✨ **极简设计** - 专注内容，去除冗余
- 🚀 **高性能** - Go 语言开发，响应迅速
- 📝 **Markdown支持** - 原生支持Markdown写作
- 🎨 **优雅动画** - 流畅的交互体验
- 🔒 **隐私保护** - 数据本地存储，完全掌控

## 技术栈

- **后端**: Go 语言
- **前端**: 原生 HTML/CSS/JavaScript
- **部署**: Docker 容器化
- **存储**: 本地文件系统

---

感谢你的访问！🎉`
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"title":   title,
		"content": content,
	})
}

// 更新关于页内容
func updateAbout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 读-改-写放在同一临界区。
	err := withMetadata(func(metadata *Metadata) error {
		metadata.AboutTitle = req.Title
		metadata.AboutContent = req.Content
		return nil
	})
	if err != nil {
		http500(w, err)
		return
	}
	auditLog("about-updated", r, "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "关于页更新成功",
	})
}

// 服务器状态缓存：该接口被首页公开调用，且原始实现每次请求都
// fork 子进程并 sleep 100ms，可被廉价放大成资源耗尽，改为 30 秒缓存。
var (
	serverStatusMu     sync.Mutex
	serverStatusCached map[string]interface{}
	serverStatusAt     time.Time
)

// 获取服务器状态
func getServerStatus(w http.ResponseWriter, r *http.Request) {
	serverStatusMu.Lock()
	defer serverStatusMu.Unlock()
	if serverStatusCached == nil || time.Since(serverStatusAt) > 30*time.Second {
		serverStatusCached = collectServerStatus()
		serverStatusAt = time.Now()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(serverStatusCached)
}

func collectServerStatus() map[string]interface{} {
	// 获取真实的系统CPU使用率
	cpuUsage, err := getSystemCPUUsage()
	if err != nil {
		cpuUsage = 0.0
	}

	// 获取真实的系统内存使用情况
	memInfo, err := getSystemMemoryInfo()
	if err != nil {
		memInfo = SystemMemoryInfo{UsedPercent: 0.0, Used: 0, Total: 0}
	}

	// 获取系统负载
	loadAvg, err := getSystemLoadAverage()
	if err != nil {
		loadAvg = 0.0
	}

	// 获取真实的操作系统信息
	osInfo, err := getSystemOSInfo()
	if err != nil {
		osInfo = SystemOSInfo{Name: "Unknown", Arch: runtime.GOARCH}
	}

	return map[string]interface{}{
		"cpu": map[string]interface{}{
			"usage": fmt.Sprintf("%.1f", cpuUsage),
			"cores": runtime.NumCPU(),
		},
		"memory": map[string]interface{}{
			"usage": fmt.Sprintf("%.1f", memInfo.UsedPercent),
			"used":  fmt.Sprintf("%.1f", float64(memInfo.Used)/(1024*1024*1024)),  // GB
			"total": fmt.Sprintf("%.1f", float64(memInfo.Total)/(1024*1024*1024)), // GB
			"unit":  "GB",
		},
		"load": map[string]interface{}{
			"average": fmt.Sprintf("%.2f", loadAvg),
		},
		"system": map[string]interface{}{
			"os":   osInfo.Name,
			"arch": strings.ToUpper(osInfo.Arch),
		},
	}
}

// serveRobotsTXT 搜索引擎爬取规则。
func serveRobotsTXT(w http.ResponseWriter, r *http.Request) {
	content := "User-agent: *\n" +
		"Allow: /\n" +
		"Disallow: /admin\n" +
		"Disallow: /api/\n" +
		"Disallow: /profile\n" +
		"Disallow: /login\n" +
		"Disallow: /reset-password\n" +
		"Sitemap: " + externalBaseURL(r) + "/sitemap.xml\n"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(content))
}

// externalBaseURL 根据请求推断对外的站点根地址。
func externalBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host
}

// serveSitemapXML 动态生成站点地图。
func serveSitemapXML(w http.ResponseWriter, r *http.Request) {
	base := externalBaseURL(r)
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n")
	pages := []string{"/", "/archive", "/about", "/guestbook"}
	for _, p := range pages {
		fmt.Fprintf(&b, "  <url><loc>%s%s</loc></url>\n", base, p)
	}
	if metadata, err := loadMetadata(); err == nil {
		for _, p := range metadata.Posts {
			if p.Slug == "" {
				continue
			}
			lastmod := ""
			if !p.UpdatedAt.IsZero() {
				lastmod = p.UpdatedAt.Format("2006-01-02")
			} else if !p.Date.IsZero() {
				lastmod = p.Date.Format("2006-01-02")
			}
			if lastmod != "" {
				fmt.Fprintf(&b, "  <url><loc>%s/post/%s</loc><lastmod>%s</lastmod></url>\n", base, url.PathEscape(p.Slug), lastmod)
			} else {
				fmt.Fprintf(&b, "  <url><loc>%s/post/%s</loc></url>\n", base, url.PathEscape(p.Slug))
			}
		}
	}
	b.WriteString("</urlset>\n")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	io.WriteString(w, b.String())
}

// 系统内存信息结构体
type SystemMemoryInfo struct {
	Total       uint64
	Used        uint64
	UsedPercent float64
}

// 系统OS信息结构体
type SystemOSInfo struct {
	Name string
	Arch string
}

// 获取系统CPU使用率
func getSystemCPUUsage() (float64, error) {
	if runtime.GOOS == "linux" {
		// 在Docker容器中，/proc/stat 实际上反映的是宿主机的CPU信息
		// 因为容器与宿主机共享内核
		return getLinuxCPUUsage()
	}
	// 其他系统暂时返回0
	return 0.0, fmt.Errorf("unsupported OS")
}

// 获取Linux系统CPU使用率
func getLinuxCPUUsage() (float64, error) {
	// 读取 /proc/stat 两次，计算差值
	stat1, err := readProcStat()
	if err != nil {
		return 0, err
	}

	time.Sleep(100 * time.Millisecond) // 短暂等待

	stat2, err := readProcStat()
	if err != nil {
		return 0, err
	}

	// 计算CPU使用率
	totalDiff := stat2.Total - stat1.Total
	idleDiff := stat2.Idle - stat1.Idle

	if totalDiff == 0 {
		return 0, nil
	}

	cpuUsage := (1.0 - float64(idleDiff)/float64(totalDiff)) * 100.0
	return cpuUsage, nil
}

// CPU统计信息
type CPUStat struct {
	Total uint64
	Idle  uint64
}

// 读取 /proc/stat
func readProcStat() (CPUStat, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return CPUStat{}, err
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return CPUStat{}, fmt.Errorf("empty /proc/stat")
	}

	// 解析第一行 (总CPU统计)
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return CPUStat{}, fmt.Errorf("invalid /proc/stat format")
	}

	var values []uint64
	for i := 1; i < len(fields) && i <= 8; i++ {
		val, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return CPUStat{}, err
		}
		values = append(values, val)
	}

	// user, nice, system, idle, iowait, irq, softirq, steal
	var total uint64
	for _, v := range values {
		total += v
	}

	idle := values[3] // idle time
	if len(values) > 4 {
		idle += values[4] // + iowait
	}

	return CPUStat{Total: total, Idle: idle}, nil
}

// 获取系统内存信息
func getSystemMemoryInfo() (SystemMemoryInfo, error) {
	if runtime.GOOS == "linux" {
		// 在Docker容器中，/proc/meminfo 反映的是宿主机的内存信息
		// 除非容器设置了内存限制
		return getLinuxMemoryInfo()
	}
	return SystemMemoryInfo{}, fmt.Errorf("unsupported OS")
}

// 获取Linux系统内存信息
func getLinuxMemoryInfo() (SystemMemoryInfo, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return SystemMemoryInfo{}, err
	}

	lines := strings.Split(string(data), "\n")
	memInfo := make(map[string]uint64)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			key := strings.TrimSuffix(fields[0], ":")
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				memInfo[key] = value * 1024 // 转换为字节
			}
		}
	}

	total := memInfo["MemTotal"]
	free := memInfo["MemFree"]
	buffers := memInfo["Buffers"]
	cached := memInfo["Cached"]
	sReclaimable := memInfo["SReclaimable"]

	// 计算实际使用的内存
	used := total - free - buffers - cached - sReclaimable
	usedPercent := float64(used) / float64(total) * 100.0

	return SystemMemoryInfo{
		Total:       total,
		Used:        used,
		UsedPercent: usedPercent,
	}, nil
}

// 获取系统负载平均值
func getSystemLoadAverage() (float64, error) {
	if runtime.GOOS == "linux" {
		return getLinuxLoadAverage()
	}
	return 0.0, fmt.Errorf("unsupported OS")
}

// 获取Linux系统负载平均值
func getLinuxLoadAverage() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("invalid /proc/loadavg format")
	}

	loadAvg, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	// 转换为百分比（基于CPU核心数）
	numCPU := float64(runtime.NumCPU())
	loadPercent := (loadAvg / numCPU) * 100.0

	return loadPercent, nil
}

// 获取系统OS信息
func getSystemOSInfo() (SystemOSInfo, error) {
	if runtime.GOOS == "linux" {
		return getLinuxOSInfo()
	}
	return SystemOSInfo{Name: runtime.GOOS, Arch: runtime.GOARCH}, nil
}

// 获取Linux系统OS信息
func getLinuxOSInfo() (SystemOSInfo, error) {
	// 检查是否在Docker容器中运行
	if isRunningInDocker() {
		// 尝试从宿主机获取真实系统信息
		if hostOSInfo, err := getHostOSInfo(); err == nil {
			return hostOSInfo, nil
		}

		// 如果无法获取宿主机信息，检查环境变量
		if hostOS := os.Getenv("HOST_OS"); hostOS != "" {
			return SystemOSInfo{Name: hostOS, Arch: runtime.GOARCH}, nil
		}

		// 最后尝试通过其他方法检测
		return detectHostOSFromContainer()
	}

	// 直接在宿主机上运行，读取本地系统信息
	return readLocalOSInfo()
}

// 读取本地系统信息
func readLocalOSInfo() (SystemOSInfo, error) {
	// 尝试读取 /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		// 如果失败，尝试其他文件
		data, err = os.ReadFile("/etc/lsb-release")
		if err != nil {
			return SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}, nil
		}
	}

	return parseOSRelease(string(data))
}

// 解析os-release文件内容
func parseOSRelease(content string) (SystemOSInfo, error) {
	lines := strings.Split(content, "\n")
	osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

	for _, line := range lines {
		if strings.HasPrefix(line, "NAME=") || strings.HasPrefix(line, "DISTRIB_ID=") {
			// 提取OS名称
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.Trim(parts[1], "\"")
				// 简化名称
				if strings.Contains(strings.ToLower(name), "ubuntu") {
					osInfo.Name = "Ubuntu"
				} else if strings.Contains(strings.ToLower(name), "debian") {
					osInfo.Name = "Debian"
				} else if strings.Contains(strings.ToLower(name), "centos") {
					osInfo.Name = "CentOS"
				} else if strings.Contains(strings.ToLower(name), "red hat") || strings.Contains(strings.ToLower(name), "rhel") {
					osInfo.Name = "RHEL"
				} else if strings.Contains(strings.ToLower(name), "fedora") {
					osInfo.Name = "Fedora"
				} else if strings.Contains(strings.ToLower(name), "alpine") {
					osInfo.Name = "Alpine"
				} else {
					// 取第一个单词作为OS名称
					words := strings.Fields(name)
					if len(words) > 0 {
						osInfo.Name = words[0]
					}
				}
				break
			}
		}
	}

	return osInfo, nil
}

// 从容器中检测宿主机OS信息
func getHostOSInfo() (SystemOSInfo, error) {
	// 方法1: 尝试读取宿主机的/proc/version（如果挂载了的话）
	if data, err := os.ReadFile("/proc/version"); err == nil {
		if osInfo := parseKernelVersion(string(data)); osInfo.Name != "Linux" {
			return osInfo, nil
		}
	}

	// 方法2: 尝试通过/proc/sys/kernel/osrelease
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		if osInfo := parseKernelRelease(string(data)); osInfo.Name != "Linux" {
			return osInfo, nil
		}
	}

	// 方法3: 尝试通过uname命令
	if osInfo, err := getOSInfoFromUname(); err == nil {
		return osInfo, nil
	}

	return SystemOSInfo{}, fmt.Errorf("无法获取宿主机OS信息")
}

// 解析内核版本信息
func parseKernelVersion(version string) SystemOSInfo {
	version = strings.ToLower(version)
	osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

	if strings.Contains(version, "ubuntu") {
		osInfo.Name = "Ubuntu"
	} else if strings.Contains(version, "debian") {
		osInfo.Name = "Debian"
	} else if strings.Contains(version, "centos") {
		osInfo.Name = "CentOS"
	} else if strings.Contains(version, "red hat") || strings.Contains(version, "rhel") {
		osInfo.Name = "RHEL"
	} else if strings.Contains(version, "fedora") {
		osInfo.Name = "Fedora"
	}

	return osInfo
}

// 解析内核发布信息
func parseKernelRelease(release string) SystemOSInfo {
	release = strings.ToLower(strings.TrimSpace(release))
	osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

	// 根据内核版本字符串推断发行版
	if strings.Contains(release, "ubuntu") {
		osInfo.Name = "Ubuntu"
	} else if strings.Contains(release, "debian") {
		osInfo.Name = "Debian"
	} else if strings.Contains(release, "el7") || strings.Contains(release, "el8") || strings.Contains(release, "el9") {
		osInfo.Name = "RHEL"
	} else if strings.Contains(release, "fc") {
		osInfo.Name = "Fedora"
	}

	return osInfo
}

// 通过uname命令获取系统信息
func getOSInfoFromUname() (SystemOSInfo, error) {
	// 尝试执行uname -a命令
	cmd := "uname -a 2>/dev/null || echo 'unknown'"
	if output, err := executeCommand(cmd); err == nil {
		output = strings.ToLower(output)
		osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

		if strings.Contains(output, "ubuntu") {
			osInfo.Name = "Ubuntu"
		} else if strings.Contains(output, "debian") {
			osInfo.Name = "Debian"
		} else if strings.Contains(output, "centos") {
			osInfo.Name = "CentOS"
		} else if strings.Contains(output, "red hat") || strings.Contains(output, "rhel") {
			osInfo.Name = "RHEL"
		} else if strings.Contains(output, "fedora") {
			osInfo.Name = "Fedora"
		}

		return osInfo, nil
	}

	return SystemOSInfo{}, fmt.Errorf("无法执行uname命令")
}

// 执行shell命令
func executeCommand(cmd string) (string, error) {
	// 使用sh执行命令
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// 从容器中检测宿主机OS的备用方法
func detectHostOSFromContainer() (SystemOSInfo, error) {
	// 检查常见的发行版特征文件或命令
	osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

	// 方法1: 尝试通过lsb_release命令
	if output, err := executeCommand("lsb_release -i 2>/dev/null | cut -f2"); err == nil {
		output = strings.ToLower(strings.TrimSpace(output))
		if output == "ubuntu" {
			osInfo.Name = "Ubuntu"
			return osInfo, nil
		} else if output == "debian" {
			osInfo.Name = "Debian"
			return osInfo, nil
		}
	}

	// 方法2: 尝试通过hostnamectl命令（如果可用）
	if output, err := executeCommand("hostnamectl 2>/dev/null | grep 'Operating System'"); err == nil {
		output = strings.ToLower(output)
		if strings.Contains(output, "ubuntu") {
			osInfo.Name = "Ubuntu"
			return osInfo, nil
		} else if strings.Contains(output, "debian") {
			osInfo.Name = "Debian"
			return osInfo, nil
		} else if strings.Contains(output, "centos") {
			osInfo.Name = "CentOS"
			return osInfo, nil
		} else if strings.Contains(output, "red hat") || strings.Contains(output, "rhel") {
			osInfo.Name = "RHEL"
			return osInfo, nil
		} else if strings.Contains(output, "fedora") {
			osInfo.Name = "Fedora"
			return osInfo, nil
		}
	}

	// 方法3: 尝试检查特定的发行版文件
	distroFiles := map[string]string{
		"/etc/debian_version": "Debian",
		"/etc/ubuntu-release": "Ubuntu",
		"/etc/redhat-release": "RHEL",
		"/etc/centos-release": "CentOS",
		"/etc/fedora-release": "Fedora",
	}

	for file, distro := range distroFiles {
		if _, err := os.Stat(file); err == nil {
			osInfo.Name = distro
			return osInfo, nil
		}
	}

	// 方法4: 尝试通过cat /etc/issue
	if output, err := executeCommand("cat /etc/issue 2>/dev/null | head -1"); err == nil {
		output = strings.ToLower(output)
		if strings.Contains(output, "ubuntu") {
			osInfo.Name = "Ubuntu"
			return osInfo, nil
		} else if strings.Contains(output, "debian") {
			osInfo.Name = "Debian"
			return osInfo, nil
		} else if strings.Contains(output, "centos") {
			osInfo.Name = "CentOS"
			return osInfo, nil
		} else if strings.Contains(output, "red hat") || strings.Contains(output, "rhel") {
			osInfo.Name = "RHEL"
			return osInfo, nil
		} else if strings.Contains(output, "fedora") {
			osInfo.Name = "Fedora"
			return osInfo, nil
		}
	}

	// 方法5: 通过包管理器检测
	packageManagers := map[string]string{
		"apt":    "Debian/Ubuntu",
		"yum":    "RHEL/CentOS",
		"dnf":    "Fedora",
		"pacman": "Arch",
		"zypper": "openSUSE",
	}

	for pm, distro := range packageManagers {
		if _, err := executeCommand(fmt.Sprintf("which %s 2>/dev/null", pm)); err == nil {
			if pm == "apt" {
				// 进一步区分Debian和Ubuntu
				if _, err := os.Stat("/etc/debian_version"); err == nil {
					if output, err := executeCommand("cat /etc/debian_version 2>/dev/null"); err == nil {
						if strings.Contains(strings.ToLower(output), "ubuntu") {
							osInfo.Name = "Ubuntu"
						} else {
							osInfo.Name = "Debian"
						}
					} else {
						osInfo.Name = "Debian" // 默认为Debian
					}
				}
			} else if strings.Contains(distro, "/") {
				// 对于RHEL/CentOS，尝试进一步区分
				if pm == "yum" {
					if _, err := os.Stat("/etc/centos-release"); err == nil {
						osInfo.Name = "CentOS"
					} else {
						osInfo.Name = "RHEL"
					}
				}
			} else {
				osInfo.Name = distro
			}
			return osInfo, nil
		}
	}

	return osInfo, nil
}

// 检查是否在Docker容器中运行
func isRunningInDocker() bool {
	// 检查 /.dockerenv 文件
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// 检查 /proc/1/cgroup 中是否包含docker
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		return strings.Contains(string(data), "docker") || strings.Contains(string(data), "containerd")
	}

	return false
}
