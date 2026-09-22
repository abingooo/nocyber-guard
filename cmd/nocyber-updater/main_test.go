package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteImageOnlyAcceptsApprovedPinnedRepository(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("OTHER=value\nNCG_IMAGE=ghcr.io/abingooo/nocyber-guard@sha256:"+strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := imageRepository + "@sha256:" + strings.Repeat("b", 64)
	if err := writeImage(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := readImage(path)
	if err != nil || got != want {
		t.Fatalf("readImage = (%q, %v), want %q", got, err, want)
	}
	if err = writeImage(path, "docker.io/example/other@sha256:"+strings.Repeat("c", 64)); err == nil {
		t.Fatal("unapproved repository was accepted")
	}
}

func TestWriteImageAddsMissingSetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("OTHER=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := imageRepository + "@sha256:" + strings.Repeat("d", 64)
	if err := writeImage(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := readImage(path)
	if err != nil || got != want {
		t.Fatalf("readImage = (%q, %v), want %q", got, err, want)
	}
}

func TestLoadOptionsRejectsRelativePrivilegedPaths(t *testing.T) {
	t.Setenv("NCG_UPDATER_SOCKET", "relative.sock")
	if _, err := loadOptions(); err == nil {
		t.Fatal("relative socket was accepted")
	}
}
