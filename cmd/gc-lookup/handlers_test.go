package main

// In-process success-path tests for the command handlers. The handlers build
// their client through the injectable newClient variable; these tests
// substitute a client whose transport (NewWithDo) serves synthetic protocol
// responses — no network, and the request must decrypt under the credential's
// finalKey, proving the handler wired the right credential through.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/oyi77/gc-lookup/internal/client"
	"github.com/oyi77/gc-lookup/internal/crypto"
)

// testFinalKey is a valid 32-byte AES key used as the stored credential key.
const testFinalKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// mockDo returns a transport that answers the GTC endpoints the handlers use.
// It decrypts the incoming request body under finalKey (proving the client
// used that key) and replies with an encrypted envelope.
func mockDo(finalKey string) func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		var env struct {
			Data string `json:"data"`
		}
		if err := json.NewDecoder(req.Body).Decode(&env); err != nil {
			return nil, err
		}
		if _, err := crypto.DecryptFromB64(env.Data, finalKey); err != nil {
			return nil, fmt.Errorf("request body not encrypted under finalKey: %w", err)
		}

		var result map[string]any
		switch req.URL.Path {
		case "/v2.8/search":
			result = map[string]any{
				"profile": map[string]any{"name": "Test User", "phone": "628123"},
				"tags":    []any{},
			}
		case "/v2.8/number-detail":
			result = map[string]any{
				"profile": map[string]any{"name": "Test User"},
				"tags":    []any{map[string]any{"name": "telegram", "value": "tguser"}},
			}
		case "/v2.8/subscription":
			result = map[string]any{
				"subscriptionInfo": map[string]any{
					"usage": map[string]any{
						"search":       map[string]any{"remainingCount": 42, "limit": 100},
						"numberDetail": map[string]any{"remainingCount": 7, "limit": 20},
					},
					"renewDate": "2026-09-01T00:00:00Z",
				},
			}
		case "/v2.8/refresh-code":
			result = map[string]any{"code": "abc123"}
		case "/v2.8/verify-code":
			result = map[string]any{}
		default:
			return nil, fmt.Errorf("mock: unexpected path %s", req.URL.Path)
		}

		body := map[string]any{"meta": map[string]any{"httpStatusCode": 200}, "result": result}
		raw, _ := json.Marshal(body)
		enc, err := crypto.EncryptToB64(string(raw), finalKey)
		if err != nil {
			return nil, err
		}
		respBody, _ := json.Marshal(map[string]any{"data": enc})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	}
}

func withMockClient(t *testing.T) {
	t.Helper()
	old := newClient
	newClient = func(cred client.Credential) *client.Client {
		return client.NewWithDo(cred, mockDo(cred.FinalKey))
	}
	t.Cleanup(func() { newClient = old })
}

func seedStore(t *testing.T, active string) {
	t.Helper()
	t.Setenv("GTC_CONFIG_DIR", t.TempDir())
	s := &client.Store{Active: active, Credentials: map[string]client.Credential{
		"acc": {Description: "acc", Token: "tok", FinalKey: testFinalKey, ClientDeviceID: "dev-1"},
	}}
	if err := saveStore(s); err != nil {
		t.Fatal(err)
	}
}

func TestCmdSearchSuccess(t *testing.T) {
	withMockClient(t)
	seedStore(t, "acc")
	out := captureStdout(t, func() { cmdSearch([]string{"628123"}) })
	if !strings.Contains(out, "Test User") {
		t.Errorf("search output = %q, want Test User", out)
	}
}

func TestCmdSearchTagsSuccess(t *testing.T) {
	withMockClient(t)
	seedStore(t, "acc")
	out := captureStdout(t, func() { cmdSearch([]string{"--source", "tags", "628123"}) })
	if !strings.Contains(out, "tguser") {
		t.Errorf("tags output = %q, want tguser", out)
	}
}

func TestCmdSubscriptionSuccess(t *testing.T) {
	withMockClient(t)
	seedStore(t, "acc")
	out := captureStdout(t, func() { cmdSubscription(nil) })
	if !strings.Contains(out, "42/100") || !strings.Contains(out, "7/20") {
		t.Errorf("subscription output = %q, want 42/100 and 7/20", out)
	}
}

func TestCmdRefreshCodeSuccess(t *testing.T) {
	withMockClient(t)
	seedStore(t, "acc")
	out := captureStdout(t, func() { cmdRefreshCode(nil) })
	if !strings.Contains(out, "abc123") {
		t.Errorf("refresh-code output = %q, want abc123", out)
	}
}

func TestCmdVerifyCodeSuccess(t *testing.T) {
	withMockClient(t)
	seedStore(t, "acc")
	out := captureStdout(t, func() { cmdVerifyCode([]string{"ABC-123"}) })
	if !strings.Contains(out, "code accepted") {
		t.Errorf("verify-code output = %q, want 'code accepted'", out)
	}
}

// vfkFinalKeyHex is the protocol constant (same value as the client package's
// unexported vfkFinalKey) — needed by the register mock to decrypt vfk calls.
const vfkFinalKeyHex = "bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa"

// registerMockDo serves the full account-generation handshake: unencrypted
// /v2.8/register with a real DH server side, then encrypted gtc and vfk steps.
func registerMockDo() func(req *http.Request) (*http.Response, error) {
	const serverPriv int64 = 424242
	finalKey := ""
	return func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v2.8/register" {
			var payload map[string]any
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				return nil, err
			}
			peer, _ := payload["peerKey"].(float64)
			finalKey = crypto.DHFinalKey(serverPriv, int64(peer))
			raw, _ := json.Marshal(map[string]any{"result": map[string]any{
				"token":     "reg-token",
				"serverKey": crypto.DHExp(crypto.DH_G, serverPriv),
			}})
			return &http.Response{
				StatusCode: http.StatusCreated,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(raw)),
			}, nil
		}

		var env struct {
			Data string `json:"data"`
		}
		if err := json.NewDecoder(req.Body).Decode(&env); err != nil {
			return nil, err
		}
		key := finalKey
		if strings.HasPrefix(req.URL.Path, "/v2.0/") {
			key = vfkFinalKeyHex
		}
		if _, err := crypto.DecryptFromB64(env.Data, key); err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", req.URL.Path, err)
		}

		var result map[string]any
		var status int
		switch req.URL.Path {
		case "/v2.8/init-basic", "/v2.8/init-intro":
			status = http.StatusCreated
		case "/v2.8/ad-settings", "/v2.8/email-code-validate/start", "/v2.8/country", "/v2.8/validation-start":
			status = http.StatusOK
		case "/v2.0/init", "/v2.0/country":
			status = http.StatusOK
		case "/v2.0/start":
			status = http.StatusOK
			result = map[string]any{"deeplink": "https://wa.me/628123456789?text=*ABC-123*", "reference": "ref-1"}
		case "/v2.0/check":
			status = http.StatusOK
			result = map[string]any{"sessionId": "sess-1"}
		case "/v2.8/verifykit-result":
			status = http.StatusOK
			result = map[string]any{"validationDate": "2026-08-29T00:00:00Z"}
		default:
			return nil, fmt.Errorf("mock: unexpected path %s", req.URL.Path)
		}

		body := map[string]any{"meta": map[string]any{"httpStatusCode": 200}, "result": result}
		raw, _ := json.Marshal(body)
		enc, err := crypto.EncryptToB64(string(raw), key)
		if err != nil {
			return nil, err
		}
		respBody, _ := json.Marshal(map[string]any{"data": enc})
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	}
}

func TestCmdRegisterSuccess(t *testing.T) {
	old := newClient
	newClient = func(client.Credential) *client.Client {
		return client.NewWithDo(client.Credential{}, registerMockDo())
	}
	t.Cleanup(func() { newClient = old })
	t.Setenv("GTC_CONFIG_DIR", t.TempDir())

	out := captureStdout(t, func() { cmdRegister([]string{"--name", "acc", "628123456789"}) })
	if !strings.Contains(out, `registered 628123456789 as "acc"`) {
		t.Errorf("register output = %q", out)
	}
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := s.Credentials["acc"]
	if !ok || cred.Token != "reg-token" {
		t.Fatalf("credential not stored: %+v", s.Credentials)
	}
	if s.Active != "acc" {
		t.Errorf("active = %q, want acc", s.Active)
	}
}
