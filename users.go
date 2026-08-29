package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"
)

func normalizeUsername(s string) string {
	return strings.TrimSpace(s)
}

func usernamesEqual(a, b string) bool {
	na := normalizeUsername(a)
	return na != "" && na == normalizeUsername(b)
}

func validateUsername(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("请输入用户名")
	}
	n := utf8.RuneCountInString(s)
	if n < 3 {
		return "", errors.New("用户名至少3个字符")
	}
	if n > 20 {
		return "", errors.New("用户名不能超过20个字符")
	}
	if strings.ContainsAny(s, " \t\n\r@<>\"'`&") {
		return "", errors.New("用户名不能包含空格、@ 或特殊符号")
	}
	return s, nil
}

func usernameTaken(metadata *Metadata, username, exceptUserID string) bool {
	for _, u := range metadata.Users {
		if exceptUserID != "" && u.ID == exceptUserID {
			continue
		}
		if usernamesEqual(u.Username, username) {
			return true
		}
	}
	return false
}

func findUserByLogin(metadata *Metadata, account string) *User {
	account = strings.TrimSpace(account)
	if account == "" || metadata == nil {
		return nil
	}
	for i := range metadata.Users {
		if emailsEqual(metadata.Users[i].Email, account) {
			return &metadata.Users[i]
		}
	}
	for i := range metadata.Users {
		if usernamesEqual(metadata.Users[i].Username, account) {
			return &metadata.Users[i]
		}
	}
	return nil
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
