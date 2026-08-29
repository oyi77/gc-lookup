package client

// White-box tests: run the real client against httptest servers that speak the
// actual GTC protocol envelope (HMAC signatures + AES-256-ECB encrypted
// request/response bodies). No network leaves the machine.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oyi77/gc-lookup/internal/crypto"
)

// testFinalKey is a valid 32-byte (64 hex char) AES key standing in for a real
// DH final key in the single-credential tests.
const testFinalKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// testServerPriv is the mock server's fixed DH private exponent; the register
// handshake proves both sides derived the same finalKey when the subsequent
// encrypted steps decrypt successfully.
const testServerPriv int64 = 424242

// decryptBody decrypts an incoming {"data": b64(AES-ECB(plain))} envelope.
func decryptBody(t *testing.T, r *http.Request, keyHex string) string {
	t.Helper()
	var envelope struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		t.Fatalf("%s: decode request body: %v", r.URL.Path, err)
	}
	plain, err := crypto.DecryptFromB64(envelope.Data, keyHex)
	if err != nil {
		t.Fatalf("%s: decrypt request: %v", r.URL.Path, err)
	}
	return plain
}

// checkSig asserts the request carries the same x-req-signature the client
// should have computed for the plaintext body (gtc.py _sig(ts, raw, key)).
func checkSig(t *testing.T, r *http.Request, plain, keyHex string) {
	t.Helper()
	ts := r.Header.Get("x-req-timestamp")
	if ts == "" {
		t.Fatal("missing x-req-timestamp")
	}
	want, err := crypto.HMACSign(ts, plain, keyHex)
	if err != nil {
		t.Fatalf("compute expected sig: %v", err)
	}
	if got := r.Header.Get("x-req-signature"); got != want {
		t.Fatalf("signature mismatch: got %q want %q", got, want)
	}
}

// writeEncrypted responds with an encrypted {"data": ...} envelope carrying
// meta.httpStatusCode 200 and the given result.
func writeEncrypted(t *testing.T, w http.ResponseWriter, result map[string]any, keyHex string) {
	t.Helper()
	body := map[string]any{"meta": map[string]any{"httpStatusCode": 200}, "result": result}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	enc, err := crypto.EncryptToB64(string(raw), keyHex)
	if err != nil {
		t.Fatalf("encrypt response: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": enc})
}

// mockGTC serves the GTC endpoints used by Search/Subscription/RefreshCode/
// VerifyCode. Every request must carry a valid signature and the expected
// token; responses are encrypted with finalKey.
func mockGTC(t *testing.T, finalKey, token string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		plain := decryptBody(t, r, finalKey)
		checkSig(t, r, plain, hmacKey)
		if r.Header.Get("x-encrypted") != "1" {
			t.Fatalf("%s: x-encrypted = %q, want 1", r.URL.Path, r.Header.Get("x-encrypted"))
		}
		if got := r.Header.Get("x-token"); got != token {
			t.Fatalf("%s: x-token = %q, want %q", r.URL.Path, got, token)
		}

		var result map[string]any
		switch r.URL.Path {
		case "/v2.8/search":
			result = map[string]any{
				"profile": map[string]any{"name": "Test User", "phone": "1234567890"},
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
			http.NotFound(w, r)
			return
		}
		writeEncrypted(t, w, result, finalKey)
	}))
	return srv
}

func newTestClient(srv *httptest.Server, cred Credential) *Client {
	c := New(cred)
	c.gtcURL = srv.URL
	c.vfkURL = srv.URL
	return c
}

func testCred() Credential {
	return Credential{
		Description:    "test-account",
		PhoneNumber:    "1234567890",
		ClientDeviceID: "dev-1",
		FinalKey:       testFinalKey,
		Token:          "test-token",
	}
}

func TestSearchProfile(t *testing.T) {
	srv := mockGTC(t, testFinalKey, "test-token")
	defer srv.Close()
	c := newTestClient(srv, testCred())

	res, err := c.Search("1234567890", "profile")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	profile, ok := res.Profile.(map[string]any)
	if !ok {
		t.Fatalf("Profile type = %T, want map", res.Profile)
	}
	if profile["name"] != "Test User" {
		t.Errorf("profile name = %v, want Test User", profile["name"])
	}
	if res.Tags == nil {
		t.Error("Tags = nil, want empty list")
	}
}

func TestSearchTags(t *testing.T) {
	srv := mockGTC(t, testFinalKey, "test-token")
	defer srv.Close()
	c := newTestClient(srv, testCred())

	res, err := c.Search("1234567890", "tags")
	if err != nil {
		t.Fatalf("Search(tags): %v", err)
	}
	tags, ok := res.Tags.([]any)
	if !ok {
		t.Fatalf("Tags type = %T, want []any", res.Tags)
	}
	if len(tags) != 1 {
		t.Fatalf("len(tags) = %d, want 1", len(tags))
	}
}

func TestSearchMissingCredentialRejectedBeforeNetwork(t *testing.T) {
	c := New(Credential{})
	if _, err := c.Search("123", "profile"); err == nil {
		t.Fatal("expected error for empty credential")
	}
}

func TestSearchMetaError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain := decryptBody(t, r, testFinalKey)
		checkSig(t, r, plain, hmacKey)
		raw, _ := json.Marshal(map[string]any{
			"meta": map[string]any{"httpStatusCode": 400, "message": "bad request"},
		})
		enc, err := crypto.EncryptToB64(string(raw), testFinalKey)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": enc})
	}))
	defer srv.Close()
	c := newTestClient(srv, testCred())

	_, err := c.Search("1234567890", "profile")
	if err == nil {
		t.Fatal("expected error when meta.httpStatusCode != 200")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("error %q does not mention status 400", err)
	}
}

func TestSubscription(t *testing.T) {
	srv := mockGTC(t, testFinalKey, "test-token")
	defer srv.Close()
	c := newTestClient(srv, testCred())

	info, err := c.Subscription()
	if err != nil {
		t.Fatalf("Subscription: %v", err)
	}
	if info.Search.RemainingCount != 42 || info.Search.Limit != 100 {
		t.Errorf("search usage = %+v, want 42/100", info.Search)
	}
	if info.NumberDetail.RemainingCount != 7 || info.NumberDetail.Limit != 20 {
		t.Errorf("numberDetail usage = %+v, want 7/20", info.NumberDetail)
	}
	if info.RenewDate != "2026-09-01T00:00:00Z" {
		t.Errorf("renewDate = %q", info.RenewDate)
	}
}

func TestRefreshCode(t *testing.T) {
	srv := mockGTC(t, testFinalKey, "test-token")
	defer srv.Close()
	c := newTestClient(srv, testCred())

	parsed, err := c.RefreshCode()
	if err != nil {
		t.Fatalf("RefreshCode: %v", err)
	}
	if code := digStr(parsed, "result", "code"); code != "abc123" {
		t.Errorf("code = %q, want abc123", code)
	}
}

func TestVerifyCode(t *testing.T) {
	srv := mockGTC(t, testFinalKey, "test-token")
	defer srv.Close()
	c := newTestClient(srv, testCred())

	if err := c.VerifyCode("ABC-123"); err != nil {
		t.Fatalf("VerifyCode: %v", err)
	}
}

// TestRegisterHandshake drives the full account-generation flow against a mock
// that performs the real DH server side. If the client's DH finalKey did not
// agree with the server's, the encrypted follow-up steps would fail to decrypt
// and the test would abort — so reaching ValidationDate proves key agreement.
func TestRegisterHandshake(t *testing.T) {
	finalKey := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Unencrypted registerPost: raw JSON body, signed with hmacKey.
		if r.URL.Path == "/v2.8/register" {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			raw, _ := json.Marshal(payload)
			checkSig(t, r, string(raw), hmacKey)
			if payload["countryCode"] != "id" {
				t.Fatalf("register countryCode = %v, want id", payload["countryCode"])
			}
			peer, ok := payload["peerKey"].(float64)
			if !ok || peer == 0 {
				t.Fatalf("register peerKey = %v (ok=%v), want nonzero", payload["peerKey"], ok)
			}
			// Server side of the DH handshake.
			finalKey = crypto.DHFinalKey(testServerPriv, int64(peer))
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{
					"token":     "reg-token",
					"serverKey": crypto.DHExp(crypto.DH_G, testServerPriv),
				},
			})
			return
		}

		// VerifyKit calls: encrypted with vfkFinalKey, signed with vfkHMACKey.
		if strings.HasPrefix(r.URL.Path, "/v2.0/") {
			plain := decryptBody(t, r, vfkFinalKey)
			ts := r.Header.Get("X-VFK-Req-Timestamp")
			if ts == "" {
				t.Fatal("missing X-VFK-Req-Timestamp")
			}
			want, err := crypto.HMACSign(ts, plain, vfkHMACKey)
			if err != nil {
				t.Fatalf("compute vfk sig: %v", err)
			}
			if got := r.Header.Get("X-VFK-Req-Signature"); got != want {
				t.Fatalf("vfk signature mismatch: got %q want %q", got, want)
			}
			if got := r.Header.Get("X-VFK-Client-Key"); got != vfkClientKey {
				t.Fatalf("X-VFK-Client-Key = %q", got)
			}

			var result map[string]any
			switch r.URL.Path {
			case "/v2.0/start":
				result = map[string]any{
					"deeplink":  "https://wa.me/628123456789?text=%2AABC-123%2A",
					"reference": "ref-1",
				}
			case "/v2.0/check":
				result = map[string]any{"sessionId": "sess-1"}
			default:
				result = map[string]any{}
			}
			writeEncrypted(t, w, result, vfkFinalKey)
			return
		}

		// Encrypted gtc steps after registration: signed with hmacKey, the
		// request body must carry the token from the register response.
		plain := decryptBody(t, r, finalKey)
		checkSig(t, r, plain, hmacKey)
		var pl map[string]any
		if err := json.Unmarshal([]byte(plain), &pl); err != nil {
			t.Fatalf("%s: unmarshal plain: %v", r.URL.Path, err)
		}
		if pl["token"] != "reg-token" {
			t.Fatalf("%s: token = %v, want reg-token", r.URL.Path, pl["token"])
		}
		if got := r.Header.Get("x-token"); got != "reg-token" {
			t.Fatalf("%s: x-token header = %q", r.URL.Path, got)
		}

		var result map[string]any
		var status int
		switch r.URL.Path {
		case "/v2.8/init-basic", "/v2.8/init-intro":
			status = http.StatusCreated
		case "/v2.8/ad-settings", "/v2.8/email-code-validate/start", "/v2.8/country", "/v2.8/validation-start":
			status = http.StatusOK
		case "/v2.8/verifykit-result":
			status = http.StatusOK
			result = map[string]any{"validationDate": "2026-08-29T00:00:00Z"}
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		writeEncrypted(t, w, result, finalKey)
	}))
	defer srv.Close()

	c := newTestClient(srv, Credential{})
	cred, err := c.Register("628123456789", "test-account")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if cred.Token != "reg-token" {
		t.Errorf("cred.Token = %q, want reg-token", cred.Token)
	}
	if cred.FinalKey == "" {
		t.Error("cred.FinalKey is empty")
	}
	if cred.ClientDeviceID == "" {
		t.Error("cred.ClientDeviceID is empty")
	}
	if cred.PhoneNumber != "628123456789" {
		t.Errorf("cred.PhoneNumber = %q", cred.PhoneNumber)
	}
	if cred.ValidationDate != "2026-08-29T00:00:00Z" {
		t.Errorf("cred.ValidationDate = %q", cred.ValidationDate)
	}
}
