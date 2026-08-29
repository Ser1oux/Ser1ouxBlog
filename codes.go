package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	errCodeNotFound        = errors.New("验证码不存在或已过期，请重新获取")
	errCodeExpired         = errors.New("验证码已过期，请重新获取")
	errCodeMismatch        = errors.New("验证码不正确")
	errCodeType            = errors.New("请使用本次操作对应的验证码")
	errCodeTooManyAttempts = errors.New("验证码错误次数过多，请重新获取")
)

// maxCodeAttempts 单个验证码允许的最大尝试次数，超过即销毁，防止 6 位码被无限爆破
const maxCodeAttempts = 5

type verificationCodeStore struct {
	Codes map[string]VerificationCode `json:"codes"`
}

var codesMu sync.Mutex

func codesFilePath() string {
	return filepath.Join(dataDir, "codes.json")
}

func normalizeEmail(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	// 过滤控制字符与内嵌空白，防止 CRLF 邮件头注入
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func normalizeCode(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\u00a0", "")
	return s
}

func emailsEqual(a, b string) bool {
	return normalizeEmail(a) == normalizeEmail(b)
}

func generateDigitCode(n int) (string, error) {
	if n <= 0 {
		n = 6
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", n, v.Int64()), nil
}

func loadCodesUnlocked() (*verificationCodeStore, error) {
	store := &verificationCodeStore{Codes: map[string]VerificationCode{}}
	data, err := os.ReadFile(codesFilePath())
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
	if store.Codes == nil {
		store.Codes = map[string]VerificationCode{}
	}
	return store, nil
}

func saveCodesUnlocked(store *verificationCodeStore) error {
	if store.Codes == nil {
		store.Codes = map[string]VerificationCode{}
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(codesFilePath(), data, 0644)
}

func pruneExpiredCodes(store *verificationCodeStore, now time.Time) {
	for k, v := range store.Codes {
		if now.After(v.ExpiresAt) {
			delete(store.Codes, k)
		}
	}
}

func saveVerificationCode(email, code, typ string) error {
	email = normalizeEmail(email)
	code = normalizeCode(code)
	if email == "" || code == "" {
		return errors.New("邮箱或验证码为空")
	}

	codesMu.Lock()
	defer codesMu.Unlock()

	store, err := loadCodesUnlocked()
	if err != nil {
		return err
	}
	now := time.Now()
	pruneExpiredCodes(store, now)
	store.Codes[email] = VerificationCode{
		Code:      code,
		Email:     email,
		ExpiresAt: now.Add(10 * time.Minute),
		Type:      typ,
	}
	return saveCodesUnlocked(store)
}

func verifyVerificationCode(email, code, expectType string) error {
	email = normalizeEmail(email)
	code = normalizeCode(code)

	codesMu.Lock()
	defer codesMu.Unlock()

	store, err := loadCodesUnlocked()
	if err != nil {
		return err
	}
	vc, ok := store.Codes[email]
	if !ok {
		return errCodeNotFound
	}
	if time.Now().After(vc.ExpiresAt) {
		delete(store.Codes, email)
		_ = saveCodesUnlocked(store)
		return errCodeExpired
	}
	if normalizeCode(vc.Code) != code {
		// 失败必须计数并落盘，达到上限立即销毁验证码
		vc.Attempts++
		if vc.Attempts >= maxCodeAttempts {
			delete(store.Codes, email)
			_ = saveCodesUnlocked(store)
			return errCodeTooManyAttempts
		}
		store.Codes[email] = vc
		_ = saveCodesUnlocked(store)
		return errCodeMismatch
	}
	if expectType != "" && vc.Type != expectType {
		return errCodeType
	}
	return nil
}

func deleteVerificationCode(email string) error {
	email = normalizeEmail(email)
	codesMu.Lock()
	defer codesMu.Unlock()

	store, err := loadCodesUnlocked()
	if err != nil {
		return err
	}
	delete(store.Codes, email)
	return saveCodesUnlocked(store)
}
