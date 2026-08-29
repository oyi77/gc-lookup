package main

// Tests for the local result cache (quota preservation).

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oyi77/gc-lookup/internal/client"
)

func seedCacheStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GTC_CACHE_DIR", filepath.Join(dir, "cache"))
	t.Setenv("GTC_CONFIG_DIR", filepath.Join(dir, "cfg"))
	s := &client.Store{Active: "acc", Credentials: map[string]client.Credential{
		"acc": {Description: "acc", Token: "tok", FinalKey: testFinalKey, ClientDeviceID: "dev-1"},
	}}
	if err := saveStore(s); err != nil {
		t.Fatal(err)
	}
	return dir
}

// countMock wraps mockDo and counts API calls (proves cache hits skip the API).
func countMock(t *testing.T, calls *int) func(req *http.Request) (*http.Response, error) {
	inner := mockDo(testFinalKey)
	return func(req *http.Request) (*http.Response, error) {
		*calls++
		return inner(req)
	}
}

func TestCachePathSanitizesPhone(t *testing.T) {
	got := cachePath("+62 813-4724-1993")
	if !strings.Contains(got, "_62_813_4724_1993.json") {
		t.Errorf("cachePath = %q, want sanitized filename", got)
	}
}

func TestCacheSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GTC_CACHE_DIR", filepath.Join(dir, "cache"))
	if err := saveCached("+628123456789", map[string]any{"name": "Fikri"}, []any{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	e, ok := loadCached("+628123456789", 7*24*time.Hour)
	if !ok {
		t.Fatal("cached entry not loaded")
	}
	if e.Profile.(map[string]any)["name"] != "Fikri" {
		t.Errorf("profile = %v", e.Profile)
	}
	if len(e.Tags) != 2 {
		t.Errorf("tags = %v", e.Tags)
	}
}

func TestCacheExpiry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GTC_CACHE_DIR", filepath.Join(dir, "cache"))
	if err := os.MkdirAll(cacheDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	// Expired (fetched 48h ago, TTL 1 day).
	e := cacheEntry{Phone: "+628111", FetchedAt: time.Now().Add(-48 * time.Hour), TTLDays: 1, Profile: map[string]any{"name": "x"}}
	data, _ := json.Marshal(e)
	if err := os.WriteFile(cachePath("+628111"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCached("+628111", 24*time.Hour); ok {
		t.Fatal("expired cache should not load")
	}
	// Fresh.
	e.FetchedAt = time.Now()
	data, _ = json.Marshal(e)
	if err := os.WriteFile(cachePath("+628111"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCached("+628111", 24*time.Hour); !ok {
		t.Fatal("fresh cache should load")
	}
}

func TestSearchServesFromCache(t *testing.T) {
	seedCacheStore(t)
	calls := 0
	old := newClient
	newClient = func(cred client.Credential) *client.Client {
		return client.NewWithDo(cred, countMock(t, &calls))
	}
	t.Cleanup(func() { newClient = old })

	out1 := captureStdout(t, func() { cmdSearch([]string{"+628123456789"}) })
	if !strings.Contains(out1, "Test User") {
		t.Fatalf("first search = %q, want Test User", out1)
	}
	if calls != 1 {
		t.Fatalf("API calls after first = %d, want 1", calls)
	}

	// Second search must be served from cache (API not called again).
	out2 := captureStdout(t, func() { cmdSearch([]string{"+628123456789"}) })
	if !strings.Contains(out2, "Test User") {
		t.Fatalf("cached search = %q, want Test User", out2)
	}
	if calls != 1 {
		t.Fatalf("API calls after cached = %d, want 1 (cache served)", calls)
	}
}

func TestSearchNoCacheForcesFresh(t *testing.T) {
	seedCacheStore(t)
	calls := 0
	old := newClient
	newClient = func(cred client.Credential) *client.Client {
		return client.NewWithDo(cred, countMock(t, &calls))
	}
	t.Cleanup(func() { newClient = old })

	_ = captureStdout(t, func() { cmdSearch([]string{"+628123456789"}) }) // caches
	_ = captureStdout(t, func() { cmdSearch([]string{"--no-cache", "+628123456789"}) })
	if calls != 2 {
		t.Fatalf("API calls = %d, want 2 (--no-cache bypasses cache)", calls)
	}
}

func TestCachePathIsolationPerPhone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GTC_CACHE_DIR", filepath.Join(dir, "cache"))
	if err := saveCached("+628111", map[string]any{"name": "A"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCached("+628222", 7*24*time.Hour); ok {
		t.Fatal("different phone should not share cache entry")
	}
}
