package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// setupTestData 把 data 相关全局变量指向临时目录，并重置内存缓存。
func setupTestData(t *testing.T) {
	t.Helper()
	oldData, oldPosts, oldUploads := dataDir, postsDir, uploadsDir
	oldMeta, oldComments, oldMessages := metadataFile, commentsFile, messagesFile
	oldStore := store

	dir := t.TempDir()
	dataDir = dir
	postsDir = filepath.Join(dir, "posts")
	uploadsDir = filepath.Join(dir, "uploads")
	metadataFile = filepath.Join(dir, "metadata.json")
	commentsFile = filepath.Join(dir, "comments.json")
	messagesFile = filepath.Join(dir, "messages.json")
	store = sessions.NewCookieStore([]byte("test-session-secret"))

	if err := os.MkdirAll(postsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(uploadsDir, 0700); err != nil {
		t.Fatal(err)
	}
	invalidateMetadataCache()

	t.Cleanup(func() {
		dataDir, postsDir, uploadsDir = oldData, oldPosts, oldUploads
		metadataFile, commentsFile, messagesFile = oldMeta, oldComments, oldMessages
		store = oldStore
		setupTokenMu.Lock()
		setupToken = ""
		setupTokenMu.Unlock()
		invalidateMetadataCache()
	})
}

func writeMetadata(t *testing.T, m *Metadata) {
	t.Helper()
	if err := saveMetadata(m); err != nil {
		t.Fatal(err)
	}
}

func sessionRequest(t *testing.T, values map[interface{}]interface{}) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	sess, err := store.Get(req, "session")
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range values {
		sess.Values[k] = v
	}
	if err := sess.Save(req, rec); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	for _, c := range rec.Result().Cookies() {
		out.AddCookie(c)
	}
	return out
}

func TestLoginDoesNotCreateAdminWhenUninitialized(t *testing.T) {
	setupTestData(t)
	writeMetadata(t, &Metadata{Posts: []Post{}})

	body := strings.NewReader(`{"password":"anything"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/login", body)
	rec := httptest.NewRecorder()
	login(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409 (未初始化必须拒绝)", rec.Code)
	}
	m, err := loadMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if m.Admin != nil {
		t.Fatal("登录接口不得创建管理员")
	}
}

func TestSetupRequiresToken(t *testing.T) {
	setupTestData(t)
	writeMetadata(t, &Metadata{Posts: []Post{}})

	payload := `{"siteName":"测试","username":"admin","email":"a@example.com","password":"strong-pass-123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	setupSite(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("无口令 status=%d want 403", rec.Code)
	}

	setupTokenMu.Lock()
	setupToken = "test-setup-token"
	setupTokenMu.Unlock()

	payload = `{"siteName":"测试","username":"admin","email":"a@example.com","password":"strong-pass-123","setupToken":"test-setup-token"}`
	req = httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(payload))
	rec = httptest.NewRecorder()
	setupSite(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("带口令 status=%d body=%s", rec.Code, rec.Body.String())
	}
	m, _ := loadMetadata()
	if !m.SetupCompleted || m.Admin == nil {
		t.Fatal("初始化未生效")
	}

	// 已初始化后再次调用必须被拒绝
	req = httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(payload))
	rec = httptest.NewRecorder()
	setupSite(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("重复初始化 status=%d want 400", rec.Code)
	}
}

func TestRequireAuthInvalidatesOnVersionChange(t *testing.T) {
	setupTestData(t)
	admin := User{ID: "u1", Username: "admin", IsAdmin: true, SessionVersion: 1}
	writeMetadata(t, &Metadata{
		Posts: []Post{},
		Admin: &AdminConfig{Username: "admin", PasswordHash: "x", SessionVersion: 1},
		Users: []User{admin},
	})

	h := requireAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	okReq := sessionRequest(t, map[interface{}]interface{}{
		"admin": true, "userID": "u1", "sessionVersion": 1,
	})
	rec := httptest.NewRecorder()
	h(rec, okReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("合法会话 status=%d want 200", rec.Code)
	}

	// 模拟改密：递增 sessionVersion
	admin.SessionVersion = 2
	writeMetadata(t, &Metadata{
		Posts: []Post{},
		Admin: &AdminConfig{Username: "admin", PasswordHash: "x", SessionVersion: 2},
		Users: []User{admin},
	})

	rec = httptest.NewRecorder()
	h(rec, okReq)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("旧会话 status=%d want 401", rec.Code)
	}
}

func TestRequireAuthRejectsDeletedUser(t *testing.T) {
	setupTestData(t)
	writeMetadata(t, &Metadata{
		Posts: []Post{},
		Admin: &AdminConfig{Username: "admin", PasswordHash: "x", SessionVersion: 1},
		Users: []User{{ID: "u1", Username: "admin", IsAdmin: true, SessionVersion: 1}},
	})
	h := requireAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	req := sessionRequest(t, map[interface{}]interface{}{
		"admin": true, "userID": "u1", "sessionVersion": 1,
	})
	// 删号后，旧 cookie 不应继续有效
	writeMetadata(t, &Metadata{
		Posts: []Post{},
		Admin: &AdminConfig{Username: "admin", PasswordHash: "x", SessionVersion: 1},
		Users: []User{},
	})
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("删号后 status=%d want 401", rec.Code)
	}
}

func TestServeUploadsForcesDownloadForNonImages(t *testing.T) {
	setupTestData(t)

	mdPath := filepath.Join(uploadsDir, "note.md")
	if err := os.WriteFile(mdPath, []byte("# hi\n<img src=x onerror=alert(1)>"), 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/uploads/note.md", nil)
	rec := httptest.NewRecorder()
	serveUploads(rec, req)
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("md 应强制下载，headers=%v", rec.Header())
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
		t.Fatalf("md 不能被当作 html: %s", ct)
	}

	pngPath := filepath.Join(uploadsDir, "a.png")
	if err := os.WriteFile(pngPath, []byte("\x89PNG\r\n\x1a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/uploads/a.png", nil)
	rec = httptest.NewRecorder()
	serveUploads(rec, req)
	if strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("图片应内联展示")
	}

	// 目录请求必须 404，不能列目录
	req = httptest.NewRequest(http.MethodGet, "/uploads/", nil)
	rec = httptest.NewRecorder()
	serveUploads(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("目录 status=%d want 404", rec.Code)
	}
}

func TestSafeArchivePath(t *testing.T) {
	ok := []string{"data/metadata.json", "data/posts/a.md", "BG/icon.jpg"}
	for _, p := range ok {
		if _, valid := safeArchivePath(p); !valid {
			t.Errorf("%q should be allowed", p)
		}
	}
	bad := []string{"etc/passwd", "../data/x", "databak/x", "BGx/y", "/etc/passwd", "data/../../x"}
	for _, p := range bad {
		if _, valid := safeArchivePath(p); valid {
			t.Errorf("%q should be rejected", p)
		}
	}
}

func TestPaginateParamsCaps(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/messages?limit=99999&offset=-3", nil)
	limit, offset := paginateParams(req)
	if limit != 1000 {
		t.Fatalf("limit=%d want 1000", limit)
	}
	if offset != 0 {
		t.Fatalf("offset=%d want 0", offset)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/messages?limit=abc", nil)
	if limit, _ = paginateParams(req); limit != 500 {
		t.Fatalf("非法 limit 应回退 500, got %d", limit)
	}
}

func TestPasswordPolicy(t *testing.T) {
	if err := validateNewPassword("1234567"); err == nil {
		t.Fatal("7 位应被拒绝")
	}
	if err := validateNewPassword("12345678"); err != nil {
		t.Fatalf("8 位应通过: %v", err)
	}
}

func TestRateLimiterWindowAndCap(t *testing.T) {
	l := &slidingWindowLimiter{entries: make(map[string][]time.Time)}
	for i := 0; i < 3; i++ {
		if !l.allow("k", 3, time.Minute) {
			t.Fatalf("第 %d 次应通过", i+1)
		}
	}
	if l.allow("k", 3, time.Minute) {
		t.Fatal("第 4 次应被限流")
	}
	// 超长 key 必须被截断，不能无限占用内存
	longKey := strings.Repeat("a", 1000)
	l.allow(longKey, 1, time.Minute)
	for k := range l.entries {
		if len(k) > 256 {
			t.Fatalf("key 未被截断: %d", len(k))
		}
	}
}

func TestPublicUserHidesPasswordHash(t *testing.T) {
	u := &User{ID: "1", Username: "alice", Email: "a@b.c", PasswordHash: "secret-hash", IsAdmin: false}
	b, err := json.Marshal(toPublicUser(u))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-hash") || strings.Contains(string(b), "passwordHash") {
		t.Fatalf("公开视图泄露了密码哈希: %s", b)
	}
}
