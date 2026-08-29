package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type Notification struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Link      string    `json:"link"`
	Read      bool      `json:"read"`
	CreatedAt time.Time `json:"createdAt"`
}

type notificationStore struct {
	Items []Notification `json:"items"`
}

var notifyMu sync.Mutex

func notificationsFilePath() string {
	return filepath.Join(dataDir, "notifications.json")
}

func loadNotificationsUnlocked() (*notificationStore, error) {
	store := &notificationStore{Items: []Notification{}}
	data, err := os.ReadFile(notificationsFilePath())
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
		return nil, err
	}
	if store.Items == nil {
		store.Items = []Notification{}
	}
	return store, nil
}

func saveNotificationsUnlocked(store *notificationStore) error {
	if store.Items == nil {
		store.Items = []Notification{}
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(notificationsFilePath(), data, 0644)
}

func addNotifications(items []Notification) error {
	if len(items) == 0 {
		return nil
	}
	notifyMu.Lock()
	defer notifyMu.Unlock()
	store, err := loadNotificationsUnlocked()
	if err != nil {
		return err
	}
	store.Items = append(store.Items, items...)
	if len(store.Items) > 300 {
		store.Items = store.Items[len(store.Items)-300:]
	}
	return saveNotificationsUnlocked(store)
}

func listUserNotifications(userID string) []Notification {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	store, err := loadNotificationsUnlocked()
	if err != nil {
		return nil
	}
	out := make([]Notification, 0)
	for i := len(store.Items) - 1; i >= 0; i-- {
		if store.Items[i].UserID == userID {
			out = append(out, store.Items[i])
			if len(out) >= 50 {
				break
			}
		}
	}
	return out
}

func markNotificationsRead(userID, id string, all bool) error {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	store, err := loadNotificationsUnlocked()
	if err != nil {
		return err
	}
	for i := range store.Items {
		if store.Items[i].UserID != userID {
			continue
		}
		if all || store.Items[i].ID == id {
			store.Items[i].Read = true
		}
	}
	return saveNotificationsUnlocked(store)
}

func unreadNotificationCount(userID string) int {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	store, err := loadNotificationsUnlocked()
	if err != nil {
		return 0
	}
	n := 0
	for _, item := range store.Items {
		if item.UserID == userID && !item.Read {
			n++
		}
	}
	return n
}

func siteOwnerUser(metadata *Metadata) *User {
	if metadata == nil {
		return nil
	}
	for i := range metadata.Users {
		if metadata.Users[i].IsAdmin {
			return &metadata.Users[i]
		}
	}
	if len(metadata.Users) > 0 {
		return &metadata.Users[0]
	}
	return nil
}

func findCommentByID(store *CommentsData, id string) *Comment {
	if store == nil || id == "" {
		return nil
	}
	for i := range store.Comments {
		if store.Comments[i].ID == id {
			return &store.Comments[i]
		}
	}
	return nil
}

func commentNotifyTargets(metadata *Metadata, comment Comment, commenterID string, cstore *CommentsData) []string {
	seen := map[string]bool{commenterID: true}
	var ids []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if comment.ParentID != "" && comment.ReplyToID != "" {
		if parent := findCommentByID(cstore, comment.ReplyToID); parent != nil {
			add(parent.UserID)
		}
	} else if owner := siteOwnerUser(metadata); owner != nil {
		add(owner.ID)
	}
	return ids
}

func clipRunes(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func publicBaseURL(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	host = strings.TrimSpace(strings.Split(host, ",")[0])
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func userDisplayName(u *User) string {
	if u == nil {
		return "有人"
	}
	if name := strings.TrimSpace(u.Nickname); name != "" {
		return name
	}
	if name := strings.TrimSpace(u.Username); name != "" {
		return name
	}
	return "有人"
}

func notifyNewComment(metadata *Metadata, post Post, comment Comment, commenter User, cstore *CommentsData, baseURL string) {
	if metadata == nil {
		return
	}
	targets := commentNotifyTargets(metadata, comment, commenter.ID, cstore)
	if len(targets) == 0 {
		return
	}
	fromName := userDisplayName(&commenter)
	siteName := strings.TrimSpace(metadata.SiteName)
	if siteName == "" {
		siteName = "博客"
	}
	link := "/post/" + post.Slug + "#comment-" + comment.ID
	excerpt := clipRunes(comment.Content, 80)
	kind := "comment"
	title := fromName + " 评论了你的文章"
	if comment.ParentID != "" {
		kind = "reply"
		title = fromName + " 回复了你的评论"
	}

	items := make([]Notification, 0, len(targets))
	now := time.Now()
	for _, uid := range targets {
		items = append(items, Notification{
			ID:        fmtNotifyID(now, uid),
			UserID:    uid,
			Kind:      kind,
			Title:     title,
			Body:      excerpt,
			Link:      link,
			CreatedAt: now,
		})
	}
	_ = addNotifications(items)

	if metadata.SMTP == nil {
		return
	}
	fullLink := link
	if baseURL != "" {
		fullLink = strings.TrimRight(baseURL, "/") + link
	}
	for _, uid := range targets {
		u := findUserByID(metadata, uid)
		if u == nil || strings.TrimSpace(u.Email) == "" {
			continue
		}
		to := u.Email
		subject := siteName + " - " + title
		body := fmtNotifyEmail(userDisplayName(u), fromName, post.Title, excerpt, fullLink, kind)
		go func(toAddr, subj, text string) {
			_ = sendEmail(metadata.SMTP, toAddr, subj, text)
		}(to, subject, body)
	}
}

func fmtNotifyID(now time.Time, userID string) string {
	return now.Format("20060102150405") + "-" + userID + "-" + generateNotifySuffix()
}

func generateNotifySuffix() string {
	code, err := generateDigitCode(6)
	if err != nil {
		return time.Now().Format("000000")
	}
	return code
}

func fmtNotifyEmail(toName, fromName, postTitle, excerpt, link, kind string) string {
	action := "评论了你的文章"
	if kind == "reply" {
		action = "回复了你的评论"
	}
	if postTitle == "" {
		postTitle = "一篇文章"
	}
	return "您好，" + toName + "：\n\n" +
		fromName + " 在「" + postTitle + "」中" + action + "：\n\n" +
		excerpt + "\n\n" +
		"查看：" + link + "\n\n" +
		"此邮件由系统自动发送，请勿直接回复。"
}

func getNotifications(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID, _ := session.Values["userID"].(string)
	list := listUserNotifications(userID)
	if list == nil {
		list = []Notification{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":  list,
		"unread": unreadNotificationCount(userID),
	})
}

func readNotifications(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID, _ := session.Values["userID"].(string)
	var req struct {
		ID  string `json:"id"`
		All bool   `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求", http.StatusBadRequest)
		return
	}
	if err := markNotificationsRead(userID, strings.TrimSpace(req.ID), req.All); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"unread":  unreadNotificationCount(userID),
	})
}
