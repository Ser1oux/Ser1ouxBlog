package main

import "testing"

func TestCommentNotifyTargets(t *testing.T) {
	meta := &Metadata{Users: []User{
		{ID: "owner", Username: "Boss", IsAdmin: true},
		{ID: "u1", Username: "Alice"},
		{ID: "u2", Username: "Bob"},
	}}
	store := &CommentsData{Comments: []Comment{
		{ID: "c1", UserID: "u1", PostSlug: "p"},
	}}

	top := Comment{ID: "c2", UserID: "u2"}
	got := commentNotifyTargets(meta, top, "u2", store)
	if len(got) != 1 || got[0] != "owner" {
		t.Fatalf("top-level should notify owner, got %v", got)
	}

	reply := Comment{ID: "c3", UserID: "u2", ParentID: "c1", ReplyToID: "c1"}
	got = commentNotifyTargets(meta, reply, "u2", store)
	if len(got) != 1 || got[0] != "u1" {
		t.Fatalf("reply should notify parent author, got %v", got)
	}

	selfTop := Comment{ID: "c4", UserID: "owner"}
	got = commentNotifyTargets(meta, selfTop, "owner", store)
	if len(got) != 0 {
		t.Fatalf("owner commenting own post should not notify self, got %v", got)
	}
}

func TestClipRunes(t *testing.T) {
	if got := clipRunes("你好世界", 2); got != "你好…" {
		t.Fatalf("got %q", got)
	}
}
