package main

// Local result cache to preserve GetContact search quota. Cache files are JSON
// in $GTC_CACHE_DIR (default ~/.config/gtc/cache/), one file per phone.
// TTL defaults to 7 days; override with GTC_CACHE_TTL env or --ttl flag.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// cacheEntry holds the search result for one phone, independently of source
// (profile or tags — both are stored so one lookup serves both sources).
type cacheEntry struct {
	Phone     string    `json:"phone"`
	FetchedAt time.Time `json:"fetched_at"`
	TTLDays   int       `json:"ttl_days"`
	Profile   any       `json:"profile,omitempty"`
	Tags      []any     `json:"tags,omitempty"`
}

// cacheDir returns the cache directory (default ~/.config/gtc/cache).
func cacheDir() string {
	if d := os.Getenv("GTC_CACHE_DIR"); d != "" {
		return d
	}
	return filepath.Join(configDir(), "cache")
}

// cacheTTL returns the default TTL in days (env GTC_CACHE_TTL or 7).
func defaultCacheTTL() int {
	s := os.Getenv("GTC_CACHE_TTL")
	if s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 7
}

// cachePath returns the file path for a phone number's cache entry.
func cachePath(phone string) string {
	sanitized := strings.NewReplacer(
		"+", "_", " ", "_", "(", "_", ")", "_", "-", "_",
	).Replace(phone)
	return filepath.Join(cacheDir(), sanitized+".json")
}

// loadCached reads and validates a cache entry for phone. Returns (entry, ok).
// If ok and within TTL, use the cached data.
func loadCached(phone string, ttl time.Duration) (*cacheEntry, bool) {
	raw, err := os.ReadFile(cachePath(phone))
	if err != nil {
		return nil, false
	}
	var e cacheEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, false
	}
	if time.Since(e.FetchedAt) > ttl {
		return nil, false
	}
	// Basic sanity: must have at least one of profile/tags.
	if e.Profile == nil && len(e.Tags) == 0 {
		return nil, false
	}
	return &e, true
}

// saveCached writes a search result to the cache, merging with any existing
// entry so a profile-only search does not erase previously cached tags (and
// vice versa). tags may be any; it is normalized to []any for storage.
func saveCached(phone string, profile any, tags any) error {
	if err := os.MkdirAll(cacheDir(), 0o700); err != nil {
		return fmt.Errorf("cache mkdir: %w", err)
	}
	var tagList []any
	if t, ok := tags.([]any); ok {
		tagList = t
	}
	// Merge with any existing entry (accumulate profile + tags over time).
	if raw, err := os.ReadFile(cachePath(phone)); err == nil {
		var ex cacheEntry
		if json.Unmarshal(raw, &ex) == nil {
			if profile == nil {
				profile = ex.Profile
			}
			if len(tagList) == 0 {
				tagList = ex.Tags
			}
		}
	}
	e := cacheEntry{
		Phone:     phone,
		FetchedAt: time.Now(),
		TTLDays:   defaultCacheTTL(),
		Profile:   profile,
		Tags:      tagList,
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("cache marshal: %w", err)
	}
	if err := os.WriteFile(cachePath(phone), data, 0o600); err != nil {
		return fmt.Errorf("cache write: %w", err)
	}
	return nil
}
