package main

import "testing"

func TestValidateUsername(t *testing.T) {
	if _, err := validateUsername("ab"); err == nil {
		t.Fatal("too short")
	}
	if _, err := validateUsername("has space"); err == nil {
		t.Fatal("space")
	}
	if _, err := validateUsername("a@b"); err == nil {
		t.Fatal("@")
	}
	got, err := validateUsername("  Ser1oux  ")
	if err != nil || got != "Ser1oux" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestFindUserByLogin(t *testing.T) {
	meta := &Metadata{Users: []User{
		{ID: "1", Username: "Alice", Email: "alice@example.com"},
		{ID: "2", Username: "Bob", Email: "bob@example.com"},
	}}
	if u := findUserByLogin(meta, "ALICE@example.com"); u == nil || u.ID != "1" {
		t.Fatal("email login")
	}
	if u := findUserByLogin(meta, "Alice"); u == nil || u.ID != "1" {
		t.Fatal("username login")
	}
	if u := findUserByLogin(meta, "alice"); u != nil {
		t.Fatal("username is case-sensitive")
	}
	if u := findUserByLogin(meta, "nobody"); u != nil {
		t.Fatal("missing")
	}
}

func TestUsernameTaken(t *testing.T) {
	meta := &Metadata{Users: []User{
		{ID: "1", Username: "Alice"},
		{ID: "2", Username: "Bob"},
	}}
	if !usernameTaken(meta, "Alice", "") {
		t.Fatal("should be taken")
	}
	if usernameTaken(meta, "alice", "") {
		t.Fatal("different case is a different username")
	}
	if usernameTaken(meta, "Alice", "1") {
		t.Fatal("own name is allowed")
	}
	if usernameTaken(meta, "Carol", "") {
		t.Fatal("new name")
	}
}
