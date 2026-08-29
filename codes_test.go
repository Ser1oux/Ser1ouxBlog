package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeEmailAndCode(t *testing.T) {
	if got := normalizeEmail("  Foo.Bar@Example.COM "); got != "foo.bar@example.com" {
		t.Fatalf("email=%q", got)
	}
	if got := normalizeCode("  12 3456 "); got != "123456" {
		t.Fatalf("code=%q", got)
	}
	if !emailsEqual("A@x.com", "a@x.com") {
		t.Fatal("emailsEqual")
	}
}

func TestVerificationCodeRoundTrip(t *testing.T) {
	orig := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = orig }()

	if err := saveVerificationCode("User@Example.com", "123456", "password-reset"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "codes.json")); err != nil {
		t.Fatal(err)
	}
	if err := verifyVerificationCode("user@example.com", "123456", "password-reset"); err != nil {
		t.Fatal(err)
	}
	if err := verifyVerificationCode("user@example.com", "000000", "password-reset"); err != errCodeMismatch {
		t.Fatalf("want mismatch, got %v", err)
	}
	if err := deleteVerificationCode("USER@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := verifyVerificationCode("user@example.com", "123456", "password-reset"); err != errCodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestVerificationCodeExpiry(t *testing.T) {
	orig := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = orig }()

	if err := saveVerificationCode("a@b.com", "111111", "password-reset"); err != nil {
		t.Fatal(err)
	}
	codesMu.Lock()
	store, err := loadCodesUnlocked()
	if err != nil {
		codesMu.Unlock()
		t.Fatal(err)
	}
	vc := store.Codes["a@b.com"]
	vc.ExpiresAt = time.Now().Add(-time.Second)
	store.Codes["a@b.com"] = vc
	if err := saveCodesUnlocked(store); err != nil {
		codesMu.Unlock()
		t.Fatal(err)
	}
	codesMu.Unlock()

	if err := verifyVerificationCode("a@b.com", "111111", "password-reset"); err != errCodeExpired {
		t.Fatalf("want expired, got %v", err)
	}
}
