package main

// Tests for the credential-store layer of the CLI. Command handlers call
// os.Exit on bad args, so they are exercised via the binary in the smoke pass;
// here we test the pure store logic that the handlers build on.

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oyi77/gc-lookup/internal/client"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GTC_CONFIG_DIR", dir)

	s, err := loadStore()
	if err != nil {
		t.Fatalf("loadStore on empty dir: %v", err)
	}
	if s.Active != "" || len(s.Credentials) != 0 {
		t.Fatalf("expected empty store, got active=%q creds=%d", s.Active, len(s.Credentials))
	}

	s.Credentials["acc-a"] = client.Credential{
		Description:    "acc-a",
		PhoneNumber:    "628111",
		ClientDeviceID: "dev-1",
		FinalKey:       "f",
		Token:          "tok",
	}
	s.Active = "acc-a"
	if err := saveStore(s); err != nil {
		t.Fatalf("saveStore: %v", err)
	}

	fi, err := os.Stat(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatalf("stat credentials.json: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("credentials.json mode = %o, want 600", fi.Mode().Perm())
	}

	loaded, err := loadStore()
	if err != nil {
		t.Fatalf("loadStore after save: %v", err)
	}
	cred, ok := loaded.Credentials["acc-a"]
	if !ok {
		t.Fatal("acc-a missing after round-trip")
	}
	if cred.Token != "tok" || cred.PhoneNumber != "628111" {
		t.Errorf("round-trip cred mismatch: %+v", cred)
	}
	if loaded.Active != "acc-a" {
		t.Errorf("active = %q, want acc-a", loaded.Active)
	}

	got, err := activeCred(loaded)
	if err != nil || got.Token != "tok" {
		t.Fatalf("activeCred = %+v, err=%v", got, err)
	}
}

func TestActiveCredErrors(t *testing.T) {
	s := &client.Store{Credentials: map[string]client.Credential{}}
	if _, err := activeCred(s); err == nil {
		t.Fatal("expected error when no active credential")
	}
	s.Active = "ghost"
	if _, err := activeCred(s); err == nil {
		t.Fatal("expected error when active credential not found")
	}
}

func TestStoreCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GTC_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil {
		t.Fatal("expected error for corrupt credentials.json")
	}
}

func TestConfigDirEnvOverride(t *testing.T) {
	t.Setenv("GTC_CONFIG_DIR", "/tmp/custom-gtc")
	if got := configDir(); got != "/tmp/custom-gtc" {
		t.Errorf("configDir = %q", got)
	}
	if got := credFilePath(); got != "/tmp/custom-gtc/credentials.json" {
		t.Errorf("credFilePath = %q", got)
	}
}

func TestShort(t *testing.T) {
	if got := short(""); got != "" {
		t.Errorf("short(empty) = %q", got)
	}
	if got := short("12345678"); got != "12345678" {
		t.Errorf("short(8) = %q", got)
	}
	if got := short("123456789"); got != "12345678" {
		t.Errorf("short(9) = %q", got)
	}
}

// captureStdout runs fn with os.Stdout pointed at a pipe and returns what it
// wrote. cmdCred success paths print and return (no os.Exit), so this is safe.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	os.Stdout = old
	_ = w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCmdCredListEmpty(t *testing.T) {
	t.Setenv("GTC_CONFIG_DIR", t.TempDir())
	out := captureStdout(t, func() { cmdCred([]string{"list"}) })
	if !strings.Contains(out, "no credentials stored") {
		t.Errorf("list empty = %q", out)
	}
}

func TestCmdCredLifecycle(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GTC_CONFIG_DIR", dir)
	s := &client.Store{Credentials: map[string]client.Credential{
		"acc-a": {Description: "acc-a", PhoneNumber: "628111", Token: "tok-1", FinalKey: "f1"},
		"acc-b": {Description: "acc-b", PhoneNumber: "628222", Token: "tok-2", FinalKey: "f2"},
	}}
	if err := saveStore(s); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { cmdCred([]string{"list"}) })
	if !strings.Contains(out, "acc-a") || !strings.Contains(out, "acc-b") {
		t.Errorf("list = %q, want both accounts", out)
	}
	if strings.Contains(out, "* acc-a") {
		t.Errorf("acc-a should not be active initially: %q", out)
	}

	captureStdout(t, func() { cmdCred([]string{"use", "acc-b"}) })
	loaded, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Active != "acc-b" {
		t.Errorf("active after use = %q, want acc-b", loaded.Active)
	}

	out = captureStdout(t, func() { cmdCred([]string{"list"}) })
	if !strings.Contains(out, "* acc-b") {
		t.Errorf("acc-b should be marked active: %q", out)
	}

	captureStdout(t, func() { cmdCred([]string{"remove", "acc-b"}) })
	loaded, err = loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Credentials["acc-b"]; ok {
		t.Error("acc-b should be removed")
	}
	if loaded.Active != "" {
		t.Errorf("active should reset after removing active cred, got %q", loaded.Active)
	}

	out = captureStdout(t, func() { cmdCred([]string{"path"}) })
	if !strings.Contains(out, filepath.Join(dir, "credentials.json")) {
		t.Errorf("path = %q, want %q", out, filepath.Join(dir, "credentials.json"))
	}
}
