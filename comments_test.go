package main

import "testing"

func TestResolveCommentReply(t *testing.T) {
	store := &CommentsData{Comments: []Comment{
		{ID: "root", PostSlug: "hello", UserID: "u1", Username: "Alice"},
		{ID: "child", PostSlug: "hello", ParentID: "root", UserID: "u2", Username: "Bob", Nickname: "小B"},
	}}

	rootID, replyToID, replyToName, err := resolveCommentReply(store, "hello", "", "u2")
	if err != nil || rootID != "" || replyToID != "" {
		t.Fatalf("empty parent: %q %q %v", rootID, replyToID, err)
	}

	rootID, replyToID, replyToName, err = resolveCommentReply(store, "hello", "root", "u2")
	if err != nil || rootID != "root" || replyToID != "root" || replyToName != "Alice" {
		t.Fatalf("reply root: %q %q %q %v", rootID, replyToID, replyToName, err)
	}

	rootID, replyToID, replyToName, err = resolveCommentReply(store, "hello", "child", "u1")
	if err != nil || rootID != "root" || replyToID != "child" || replyToName != "小B" {
		t.Fatalf("reply child stays 2-level: %q %q %q %v", rootID, replyToID, replyToName, err)
	}

	if _, _, _, err = resolveCommentReply(store, "hello", "root", "u1"); err == nil {
		t.Fatal("self-reply should fail")
	}
	if _, _, _, err = resolveCommentReply(store, "hello", "missing", "u2"); err == nil {
		t.Fatal("missing parent should fail")
	}
	if _, _, _, err = resolveCommentReply(store, "other", "root", "u2"); err == nil {
		t.Fatal("cross-post should fail")
	}
}
