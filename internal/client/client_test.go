package client

// White-box tests: run the real client against httptest servers that speak the
// actual GTC protocol envelope (HMAC signatures + AES-256-ECB encrypted
// request/response bodies). No network leaves the machine.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
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
	vstart := 0
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
			raw, _ := marshalRaw(payload)
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

		// Fidelity: exact payload shapes as gtc.py defines them.
		switch r.URL.Path {
		case "/v2.8/ad-settings":
			if len(pl) != 2 || pl["source"] != "init" {
				t.Fatalf("ad-settings payload = %v, want exactly {source:init, token}", pl)
			}
		case "/v2.8/country":
			if len(pl) != 2 || pl["countryCode"] != "ID" {
				t.Fatalf("country payload = %v, want exactly {countryCode:ID, token}", pl)
			}
		case "/v2.8/email-code-validate/start":
			email, _ := pl["email"].(string)
			fullName, _ := pl["fullName"].(string)
			if !regexp.MustCompile(`^user[0-9]{8}@gmail\.com$`).MatchString(email) {
				t.Fatalf("email = %q, want user<8 digits>@gmail.com (gtc.py randint(10**7, 10**8-1))", email)
			}
			if !regexp.MustCompile(`^User[0-9]{4,6}$`).MatchString(fullName) {
				t.Fatalf("fullName = %q, want User<4-6 digits> (gtc.py randint(1000, 999999))", fullName)
			}
		}

		var result map[string]any
		var status int
		switch r.URL.Path {
		case "/v2.8/init-basic", "/v2.8/init-intro":
			status = http.StatusCreated
		case "/v2.8/ad-settings", "/v2.8/email-code-validate/start", "/v2.8/country":
			status = http.StatusOK
		case "/v2.8/validation-start":
			vstart++
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
	if vstart != 2 {
		t.Fatalf("validation-start calls = %d, want 2 (init steps + after VerifyKit start, as gtc.py)", vstart)
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

// --- error branches + small helpers ----------------------------------------

func TestNewWithDoDefaults(t *testing.T) {
	c := NewWithDo(testCred(), http.DefaultClient.Do)
	if c.Cred.Token != "test-token" {
		t.Errorf("cred not carried: %+v", c.Cred)
	}
	if c.gtcURL != gtcBase || c.vfkURL != vfkBase {
		t.Errorf("URL defaults: gtc=%q vfk=%q, want %q/%q", c.gtcURL, c.vfkURL, gtcBase, vfkBase)
	}
	if c.do == nil {
		t.Error("do is nil")
	}
}

func TestSearchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain := decryptBody(t, r, testFinalKey)
		checkSig(t, r, plain, hmacKey)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"httpStatusCode": 500}})
	}))
	defer srv.Close()
	c := newTestClient(srv, testCred())
	if _, err := c.Search("1234567890", "profile"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("Search error = %v, want mention of 500", err)
	}
}

func TestSubscriptionHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain := decryptBody(t, r, testFinalKey)
		checkSig(t, r, plain, hmacKey)
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"httpStatusCode": 403}})
	}))
	defer srv.Close()
	c := newTestClient(srv, testCred())
	if _, err := c.Subscription(); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("Subscription error = %v, want mention of 403", err)
	}
}

func TestRefreshCodeHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain := decryptBody(t, r, testFinalKey)
		checkSig(t, r, plain, hmacKey)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"httpStatusCode": 400}})
	}))
	defer srv.Close()
	c := newTestClient(srv, testCred())
	if _, err := c.RefreshCode(); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("RefreshCode error = %v, want mention of 400", err)
	}
}

func TestVerifyCodeHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain := decryptBody(t, r, testFinalKey)
		checkSig(t, r, plain, hmacKey)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"httpStatusCode": 401}})
	}))
	defer srv.Close()
	c := newTestClient(srv, testCred())
	if err := c.VerifyCode("ABC-123"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("VerifyCode error = %v, want mention of 401", err)
	}
}

func TestVerifyCodeMetaError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain := decryptBody(t, r, testFinalKey)
		checkSig(t, r, plain, hmacKey)
		w.WriteHeader(http.StatusOK)
		raw, _ := json.Marshal(map[string]any{
			"meta": map[string]any{"httpStatusCode": 401, "message": "invalid code"},
		})
		enc, _ := crypto.EncryptToB64(string(raw), testFinalKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": enc})
	}))
	defer srv.Close()
	c := newTestClient(srv, testCred())
	if err := c.VerifyCode("WRONG"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("VerifyCode meta error = %v, want mention of 401", err)
	}
}

func TestDigHelpers(t *testing.T) {
	obj := map[string]any{
		"a": map[string]any{"b": "str", "n": 7},
	}
	// dig on non-map intermediate returns nil.
	if got := dig(obj, "a", "b", "c"); got != nil {
		t.Errorf("dig nested-non-map = %v, want nil", got)
	}
	if got := digStr(obj, "a", "b"); got != "str" {
		t.Errorf("digStr = %q, want str", got)
	}
	// digStr on non-string value returns "".
	if got := digStr(obj, "a", "n"); got != "" {
		t.Errorf("digStr non-string = %q, want empty", got)
	}
	// digInt with native int value (not JSON float64).
	if got := digInt(map[string]any{"x": int(5)}, "x"); got != 5 {
		t.Errorf("digInt native int = %d, want 5", got)
	}
	if got := digInt(map[string]any{"x": "nope"}, "x"); got != 0 {
		t.Errorf("digInt wrong type = %d, want 0", got)
	}
	// digInt on missing key.
	if got := digInt(obj, "zzz"); got != 0 {
		t.Errorf("digInt missing = %d, want 0", got)
	}
}

func TestExtractCodeInvalid(t *testing.T) {
	// No valid code pattern (codeValidRe requires alnum-alnum).
	if got := extractCode("https://wa.me/628123456789?text=hello"); got != "" {
		t.Errorf("extractCode(invalid) = %q, want empty", got)
	}
	if got := extractCode(""); got != "" {
		t.Errorf("extractCode(empty) = %q, want empty", got)
	}
}

func TestRandIntEdges(t *testing.T) {
	if got := randInt(5, 5); got != 5 {
		t.Errorf("randInt(5,5) = %d, want 5", got)
	}
	if got := randInt(9, 3); got != 9 {
		t.Errorf("randInt(9,3) = %d, want 9", got)
	}
	for i := 0; i < 100; i++ {
		v := randInt(10, 20)
		if v < 10 || v >= 20 {
			t.Fatalf("randInt out of range: %d", v)
		}
	}
}

func TestBoolTo01(t *testing.T) {
	if got := boolTo01(true); got != "1" {
		t.Errorf("boolTo01(true) = %q", got)
	}
	if got := boolTo01(false); got != "0" {
		t.Errorf("boolTo01(false) = %q", got)
	}
}

// --- Register error branches + extractCode valid path -----------------------

func TestRegisterRejectsNon201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2.8/register" {
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			raw, _ := marshalRaw(payload)
			checkSig(t, r, string(raw), hmacKey)
			w.WriteHeader(http.StatusOK) // wrong: expects 201
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"token": "t", "serverKey": 1}})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := newTestClient(srv, Credential{})
	if _, err := c.Register("628123456789", "test"); err == nil || !strings.Contains(err.Error(), "201") {
		t.Fatalf("Register error = %v, want mention of 201", err)
	}
}

func TestRegisterRejectsMissingTokenServerKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2.8/register" {
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			raw, _ := marshalRaw(payload)
			checkSig(t, r, string(raw), hmacKey)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{}})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := newTestClient(srv, Credential{})
	if _, err := c.Register("628123456789", "test"); err == nil || !strings.Contains(err.Error(), "token/serverKey") {
		t.Fatalf("Register error = %v, want mention of token/serverKey", err)
	}
}

func TestExtractCodeValidAndSingleSegment(t *testing.T) {
	// Literal asterisks (as the real VerifyKit deeplink contains) yield a code.
	if got := extractCode("https://wa.me/628123456789?text=*ABC-123*"); got != "ABC-123" {
		t.Errorf("extractCode(valid) = %q, want ABC-123", got)
	}
	// Single segment fails the codeValidRe hyphen requirement.
	if got := extractCode("https://wa.me/628123456789?text=*ABC*"); got != "" {
		t.Errorf("extractCode(single segment) = %q, want empty", got)
	}
}

// --- vfk status-code fidelity (gtc.py checks code != 200 on vfk init/country) --

func TestRegisterVfkInitNon200(t *testing.T) {
	finalKey := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2.8/register" {
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			raw, _ := marshalRaw(payload)
			checkSig(t, r, string(raw), hmacKey)
			peer, _ := payload["peerKey"].(float64)
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
		if strings.HasPrefix(r.URL.Path, "/v2.0/") {
			_ = decryptBody(t, r, vfkFinalKey)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "boom"})
			return
		}
		plain := decryptBody(t, r, finalKey)
		checkSig(t, r, plain, hmacKey)
		status := http.StatusOK
		if r.URL.Path == "/v2.8/init-basic" || r.URL.Path == "/v2.8/init-intro" {
			status = http.StatusCreated
		}
		w.WriteHeader(status)
		writeEncrypted(t, w, map[string]any{}, finalKey)
	}))
	defer srv.Close()
	c := newTestClient(srv, Credential{})
	if _, err := c.Register("628123456789", "test"); err == nil || !strings.Contains(err.Error(), "vfk init: HTTP 500") {
		t.Fatalf("Register error = %v, want vfk init: HTTP 500", err)
	}
}

func TestRegisterVfkCountryNon200(t *testing.T) {
	finalKey := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2.8/register" {
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			raw, _ := marshalRaw(payload)
			checkSig(t, r, string(raw), hmacKey)
			peer, _ := payload["peerKey"].(float64)
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
		if strings.HasPrefix(r.URL.Path, "/v2.0/") {
			_ = decryptBody(t, r, vfkFinalKey)
			if r.URL.Path == "/v2.0/init" {
				writeEncrypted(t, w, map[string]any{}, vfkFinalKey)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad"})
			return
		}
		plain := decryptBody(t, r, finalKey)
		checkSig(t, r, plain, hmacKey)
		status := http.StatusOK
		if r.URL.Path == "/v2.8/init-basic" || r.URL.Path == "/v2.8/init-intro" {
			status = http.StatusCreated
		}
		w.WriteHeader(status)
		writeEncrypted(t, w, map[string]any{}, finalKey)
	}))
	defer srv.Close()
	c := newTestClient(srv, Credential{})
	if _, err := c.Register("628123456789", "test"); err == nil || !strings.Contains(err.Error(), "vfk country: HTTP 400") {
		t.Fatalf("Register error = %v, want vfk country: HTTP 400", err)
	}
}

func TestMarshalRawMatchesPythonReference(t *testing.T) {
	// This exact payload mirrors gtc.py's reg_body dict. The expected output
	// was computed from Python:
	//   json.dumps(reg_body, ensure_ascii=False)
	// Go's marshalRaw must produce the same bytes (alphabetical map-key order
	// happens to match the reference's insertion order for this payload).
	payload := map[string]any{
		"carrierCountryCode": "510",
		"carrierName":        "Indosat Ooredoo",
		"carrierNetworkCode": "01",
		"countryCode":        "id",
		"deepLink":           nil,
		"deviceName":         "SM-G977N",
		"deviceType":         "Android",
		"email":              nil,
		"notificationToken":  "",
		"oldToken":           nil,
		"peerKey":            int64(1234567),
		"timeZone":           "Asia/Bangkok",
		"token":              "",
	}
	got, err := marshalRaw(payload)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"carrierCountryCode": "510", "carrierName": "Indosat Ooredoo", "carrierNetworkCode": "01", "countryCode": "id", "deepLink": null, "deviceName": "SM-G977N", "deviceType": "Android", "email": null, "notificationToken": "", "oldToken": null, "peerKey": 1234567, "timeZone": "Asia/Bangkok", "token": ""}`
	if string(got) != want {
		t.Fatalf("marshalRaw = %q\n       want = %q", string(got), want)
	}
}

// TestRegisterPollsCheckUntilConfirmed proves Register retries /v2.0/check until
// the WhatsApp side is confirmed (mock returns no sessionId on the first call).
func TestRegisterPollsCheckUntilConfirmed(t *testing.T) {
	finalKey := ""
	checkCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2.8/register" {
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			raw, _ := marshalRaw(payload)
			checkSig(t, r, string(raw), hmacKey)
			peer, _ := payload["peerKey"].(float64)
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
		if strings.HasPrefix(r.URL.Path, "/v2.0/") {
			plain := decryptBody(t, r, vfkFinalKey)
			_ = plain
			switch r.URL.Path {
			case "/v2.0/check":
				checkCalls++
				result := map[string]any{}
				if checkCalls > 1 {
					result = map[string]any{"sessionId": "sess-1"}
				}
				writeEncrypted(t, w, result, vfkFinalKey)
				return
			case "/v2.0/start":
				result := map[string]any{"deeplink": "https://wa.me/628123456789?text=*ABC-123*", "reference": "ref-1"}
				writeEncrypted(t, w, result, vfkFinalKey)
				return
			default:
				writeEncrypted(t, w, map[string]any{}, vfkFinalKey)
				return
			}
		}
		plain := decryptBody(t, r, finalKey)
		checkSig(t, r, plain, hmacKey)
		status := http.StatusOK
		if r.URL.Path == "/v2.8/init-basic" || r.URL.Path == "/v2.8/init-intro" {
			status = http.StatusCreated
		}
		if r.URL.Path == "/v2.8/verifykit-result" {
			writeEncrypted(t, w, map[string]any{"validationDate": "2026-08-29T00:00:00Z"}, finalKey)
			return
		}
		w.WriteHeader(status)
		writeEncrypted(t, w, map[string]any{}, finalKey)
	}))
	defer srv.Close()

	c := newTestClient(srv, Credential{})
	cred, err := c.Register("628123456789", "test")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if cred.ValidationDate != "2026-08-29T00:00:00Z" {
		t.Errorf("validationDate = %q", cred.ValidationDate)
	}
	if checkCalls < 2 {
		t.Fatalf("/v2.0/check called %d times, want >= 2 (polling retry)", checkCalls)
	}
}
