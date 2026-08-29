// Package client implements the GetContact API protocol as a faithful port of
// gtc.py (github.com/xdreizein666/getcontact-cli). Constants, endpoints, headers
// and payloads mirror gtc.py exactly. Do not guess: any deviation from the
// Python reference breaks wire compatibility.
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/oyi77/gc-lookup/internal/crypto"
)

// Source-of-truth constants copied verbatim from gtc.py.
const (
	gtcBase = "https://pbssrv-centralevents.com"
	vfkBase = "https://api.verifykit.com"

	hmacKey      = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"
	vfkHMACKey   = "3452235d713252604a35562d325f765238695738485863672a705e6841544d3c7e6e45463028266f372b544e596f3829236b392825262e534a7e774f37653932"
	vfkClientKey = "bhvbd7ced119dc6ad6a0b35bd3cf836555d6f71930d9e5a405f32105c790d"
	vfkFinalKey  = "bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa"

	appVersion  = "8.4.0"
	androidOS   = "android 9"
	langCode    = "en_US"
	countryCode = "id"
	deviceName  = "SM-G977N"
	timeZone    = "Asia/Bangkok"
	bundleID    = "app.source.getcontact"

	carrierMCC  = "510"
	carrierName = "Indosat Ooredoo"
	carrierMNC  = "01"
)

// Credential is one GetContact account as stored in the credentials file.
type Credential struct {
	Description    string `json:"description"`
	PhoneNumber    string `json:"phoneNumber"`
	ClientDeviceID string `json:"clientDeviceId"`
	FinalKey       string `json:"finalKey"`
	Token          string `json:"token"`
	ValidationDate string `json:"validationDate,omitempty"`
}

// Store is the on-disk credential set.
type Store struct {
	Active      string                `json:"active"`
	Credentials map[string]Credential `json:"credentials"`
}

// Client performs GetContact API calls for a single credential. The HTTP
// transport is injectable so tests can use a fake instead of the network.
type Client struct {
	Cred Credential
	do   func(req *http.Request) (*http.Response, error)

	// gtcURL/vfkURL default to the protocol constants; tests override them to
	// point at an httptest server. Production behavior is unchanged.
	gtcURL string
	vfkURL string
}

// New returns a Client bound to cred using the default HTTP client.
func New(cred Credential) *Client {
	return &Client{Cred: cred, do: http.DefaultClient.Do, gtcURL: gtcBase, vfkURL: vfkBase}
}

// NewWithDo returns a Client with a custom transport (used by tests).
func NewWithDo(cred Credential, do func(req *http.Request) (*http.Response, error)) *Client {
	return &Client{Cred: cred, do: do, gtcURL: gtcBase, vfkURL: vfkBase}
}

// --- helpers ---------------------------------------------------------------

func nowTS() string { return strconv.FormatInt(time.Now().UnixMilli(), 10) }

func newDeviceID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// marshalRaw serializes a payload EXACTLY like Python json.dumps(payload,
// ensure_ascii=False): default separators (", " and ": "), no HTML escaping.
// Go's encoder emits compact JSON, so after encoding we insert the spaces
// outside string literals. Go sorts map keys alphabetically; for the reference
// payloads whose dict insertion order is alphabetical the output is
// byte-identical to gtc.py (JSON object order is semantically irrelevant).
func marshalRaw(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	compact := buf.Bytes()
	// Encoder appends a trailing newline; strip it to match json.dumps.
	if n := len(compact); n > 0 && compact[n-1] == '\n' {
		compact = compact[:n-1]
	}
	// Insert Python default separators (", " and ": ") outside string values.
	out := make([]byte, 0, len(compact)+64)
	inStr := false
	for i := 0; i < len(compact); i++ {
		c := compact[i]
		out = append(out, c)
		if inStr {
			switch c {
			case '\\':
				if i+1 < len(compact) {
					out = append(out, compact[i+1])
					i++
				}
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case ',', ':':
			out = append(out, ' ')
		}
	}
	return out, nil
}

// marshalCompact serializes compactly (separators (",",":")) for vfk calls.
func marshalCompact(v any) ([]byte, error) {
	return json.Marshal(v)
}

// dig walks a nested map[string]any by string keys and returns the terminal
// value, or nil if any segment is missing/wrong-typed.
func dig(obj any, keys ...string) any {
	cur := obj
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func digStr(obj any, keys ...string) string {
	if v, ok := dig(obj, keys...).(string); ok {
		return v
	}
	return ""
}

func digInt(obj any, keys ...string) int64 {
	switch v := dig(obj, keys...).(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case int:
		return int64(v)
	}
	return 0
}

// --- gtcCall ---------------------------------------------------------------

// gtcCall mirrors gtc.py gtcCall. It signs raw, then (if encrypted) encrypts
// the same raw into {"data": ...}. Returns the HTTP status and the parsed
// (decrypted) response body.
func (c *Client) gtcCall(endpoint string, payload map[string]any, token, finalKey, deviceID string, encrypted bool) (int, map[string]any, error) {
	raw, err := marshalRaw(payload)
	if err != nil {
		return 0, nil, err
	}
	ts := nowTS()
	sig, err := crypto.HMACSign(ts, string(raw), hmacKey)
	if err != nil {
		return 0, nil, err
	}

	var bodyBytes []byte
	if encrypted {
		enc, e := crypto.EncryptToB64(string(raw), finalKey)
		if e != nil {
			return 0, nil, e
		}
		bodyBytes, e = marshalRaw(map[string]any{"data": enc})
		if e != nil {
			return 0, nil, e
		}
	} else {
		bodyBytes = raw
	}

	req, err := http.NewRequest(http.MethodPost, c.gtcURL+endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-os", androidOS)
	req.Header.Set("x-app-version", appVersion)
	req.Header.Set("x-client-device-id", deviceID)
	req.Header.Set("x-lang", langCode)
	req.Header.Set("x-req-timestamp", ts)
	req.Header.Set("x-country-code", countryCode)
	req.Header.Set("x-encrypted", boolTo01(encrypted))
	req.Header.Set("x-req-signature", sig)
	if token != "" {
		req.Header.Set("x-token", token)
	}

	resp, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	var parsed map[string]any
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("parse response: %w (body=%s)", err, string(respBytes))
	}
	if encrypted {
		if ds, ok := parsed["data"].(string); ok {
			dec, e := crypto.DecryptFromB64(ds, finalKey)
			if e != nil {
				return resp.StatusCode, nil, e
			}
			var inner map[string]any
			if e := json.Unmarshal([]byte(dec), &inner); e != nil {
				return resp.StatusCode, nil, e
			}
			parsed = inner
		}
	}
	return resp.StatusCode, parsed, nil
}

// registerPost mirrors the registration call: x-encrypted "0", no x-token,
// body is the raw json, response is plain JSON (not wrapped in data).
func (c *Client) registerPost(endpoint string, payload map[string]any, deviceID string) (int, map[string]any, error) {
	raw, err := marshalRaw(payload)
	if err != nil {
		return 0, nil, err
	}
	ts := nowTS()
	sig, err := crypto.HMACSign(ts, string(raw), hmacKey)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.gtcURL+endpoint, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-os", androidOS)
	req.Header.Set("x-app-version", appVersion)
	req.Header.Set("x-client-device-id", deviceID)
	req.Header.Set("x-lang", langCode)
	req.Header.Set("x-req-timestamp", ts)
	req.Header.Set("x-country-code", countryCode)
	req.Header.Set("x-encrypted", "0")
	req.Header.Set("x-req-signature", sig)

	resp, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	var parsed map[string]any
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("parse response: %w (body=%s)", err, string(respBytes))
	}
	return resp.StatusCode, parsed, nil
}

// --- vfkCall ---------------------------------------------------------------

// vfkCall mirrors gtc.py vfkCall. Always encrypted with VFK_FINAL_KEY.
func (c *Client) vfkCall(endpoint string, payload map[string]any, deviceID string) (int, map[string]any, error) {
	raw, err := marshalCompact(payload)
	if err != nil {
		return 0, nil, err
	}
	ts := nowTS()
	sig, err := crypto.HMACSign(ts, string(raw), vfkHMACKey)
	if err != nil {
		return 0, nil, err
	}
	enc, err := crypto.EncryptToB64(string(raw), vfkFinalKey)
	if err != nil {
		return 0, nil, err
	}
	bodyBytes, err := json.Marshal(map[string]any{"data": enc})
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.vfkURL+endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-VFK-Client-Device-Id", deviceID)
	req.Header.Set("X-VFK-Client-Key", vfkClientKey)
	req.Header.Set("X-VFK-Sdk-Version", "0.11.4")
	req.Header.Set("X-VFK-Os", "android 9.0")
	req.Header.Set("X-VFK-App-Version", "8.16.0")
	req.Header.Set("X-VFK-Encrypted", "1")
	req.Header.Set("X-VFK-Lang", "in_ID")
	req.Header.Set("X-VFK-Req-Timestamp", ts)
	req.Header.Set("X-VFK-Req-Signature", sig)

	resp, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	var parsed map[string]any
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("parse response: %w (body=%s)", err, string(respBytes))
	}
	if ds, ok := parsed["data"].(string); ok {
		dec, e := crypto.DecryptFromB64(ds, vfkFinalKey)
		if e != nil {
			return resp.StatusCode, nil, e
		}
		var inner map[string]any
		if e := json.Unmarshal([]byte(dec), &inner); e != nil {
			return resp.StatusCode, nil, e
		}
		parsed = inner
	}
	return resp.StatusCode, parsed, nil
}

func boolTo01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// --- public result types ---------------------------------------------------

// SearchResult is the parsed response of Search.
type SearchResult struct {
	Profile any            `json:"profile"`
	Tags    any            `json:"tags"`
	Raw     map[string]any `json:"-"`
}

// Usage is the per-endpoint quota counters.
type Usage struct {
	RemainingCount int `json:"remainingCount"`
	Limit          int `json:"limit"`
}

// SubscriptionInfo is the parsed response of Subscription.
type SubscriptionInfo struct {
	Search       Usage          `json:"search"`
	NumberDetail Usage          `json:"numberDetail"`
	RenewDate    string         `json:"renewDate"`
	Raw          map[string]any `json:"-"`
}

// --- Search ----------------------------------------------------------------

// Search queries a phone number. source is "profile" or "tags". The endpoint
// mapping matches gtc.py: source "tags" -> /v2.8/number-detail (returns tags),
// any other -> /v2.8/search (returns profile).
func (c *Client) Search(phone, source string) (*SearchResult, error) {
	if c.Cred.Token == "" || c.Cred.FinalKey == "" {
		return nil, fmt.Errorf("credential %q missing token/finalKey", c.Cred.Description)
	}
	deviceID := c.Cred.ClientDeviceID
	if deviceID == "" {
		deviceID = newDeviceID()
	}
	endpoint := "/v2.8/search"
	payloadSource := "search"
	if source == "tags" {
		endpoint = "/v2.8/number-detail"
		payloadSource = "profile"
	}
	payload := map[string]any{
		"countryCode": "id",
		"phoneNumber": phone,
		"source":      payloadSource,
		"token":       c.Cred.Token,
	}
	status, parsed, err := c.gtcCall(endpoint, payload, c.Cred.Token, c.Cred.FinalKey, deviceID, true)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("search: http %d", status)
	}
	if code := digInt(parsed, "meta", "httpStatusCode"); code != 200 {
		return nil, fmt.Errorf("search: meta.httpStatusCode %d (msg=%s)", code, digStr(parsed, "meta", "message"))
	}
	return &SearchResult{
		Profile: dig(parsed, "result", "profile"),
		Tags:    dig(parsed, "result", "tags"),
		Raw:     parsed,
	}, nil
}

// --- Subscription (quota) --------------------------------------------------

// Subscription fetches quota/usage for the active credential.
func (c *Client) Subscription() (*SubscriptionInfo, error) {
	if c.Cred.Token == "" || c.Cred.FinalKey == "" {
		return nil, fmt.Errorf("credential %q missing token/finalKey", c.Cred.Description)
	}
	deviceID := c.Cred.ClientDeviceID
	if deviceID == "" {
		deviceID = newDeviceID()
	}
	payload := map[string]any{"token": c.Cred.Token}
	status, parsed, err := c.gtcCall("/v2.8/subscription", payload, c.Cred.Token, c.Cred.FinalKey, deviceID, true)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("subscription: http %d", status)
	}
	if code := digInt(parsed, "meta", "httpStatusCode"); code != 200 {
		return nil, fmt.Errorf("subscription: meta.httpStatusCode %d", code)
	}
	info := &SubscriptionInfo{Raw: parsed}
	si := dig(parsed, "result", "subscriptionInfo")
	if m, ok := si.(map[string]any); ok {
		if usage, ok := dig(m, "usage").(map[string]any); ok {
			info.Search = usageOf(dig(usage, "search"))
			info.NumberDetail = usageOf(dig(usage, "numberDetail"))
		}
		info.RenewDate = digStr(m, "renewDate")
	}
	return info, nil
}

func usageOf(v any) Usage {
	m, ok := v.(map[string]any)
	if !ok {
		return Usage{}
	}
	return Usage{
		RemainingCount: int(digInt(m, "remainingCount")),
		Limit:          int(digInt(m, "limit")),
	}
}

// --- Captcha ---------------------------------------------------------------

// RefreshCode requests a new validation code.
func (c *Client) RefreshCode() (map[string]any, error) {
	status, parsed, err := c.gtcCall("/v2.8/refresh-code", map[string]any{"token": c.Cred.Token}, c.Cred.Token, c.Cred.FinalKey, c.Cred.ClientDeviceID, true)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("refresh-code: http %d", status)
	}
	return parsed, nil
}

// VerifyCode submits the validation code.
func (c *Client) VerifyCode(answer string) error {
	status, parsed, err := c.gtcCall("/v2.8/verify-code", map[string]any{"validationCode": answer, "token": c.Cred.Token}, c.Cred.Token, c.Cred.FinalKey, c.Cred.ClientDeviceID, true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("verify-code: http %d", status)
	}
	if code := digInt(parsed, "meta", "httpStatusCode"); code != 200 {
		return fmt.Errorf("verify-code: meta.httpStatusCode %d", code)
	}
	return nil
}

// --- Register (generate) ---------------------------------------------------

// codeRe matches a VerifyKit code inside a deeplink.
var codeRe = regexp.MustCompile(`\*(.*?)\*`)
var codeValidRe = regexp.MustCompile(`^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+$`)

// Register performs the full account-generation handshake described in gtc.py.
// phone must be a phone number GetContact can verify via WhatsApp. The WhatsApp
// send step is interactive: the CLI prints the returned deeplink/code and the
// caller must send that WhatsApp message; verifykit-result only succeeds once
// the WhatsApp side is confirmed.
// vfkCheckAttempts/Interval bound how long Register polls /v2.0/check for the
// WhatsApp confirmation (gtc.py blocks on input(); we poll instead).
const (
	vfkCheckAttempts = 30
	vfkCheckInterval = 2 * time.Second
)

func (c *Client) Register(phone, description string) (Credential, error) {
	priv, pub, err := crypto.DHKeypair()
	if err != nil {
		return Credential{}, err
	}
	deviceID := newDeviceID()

	regPayload := map[string]any{
		"carrierCountryCode": carrierMCC,
		"carrierName":        carrierName,
		"carrierNetworkCode": carrierMNC,
		"countryCode":        "id",
		"deepLink":           nil,
		"deviceName":         deviceName,
		"deviceType":         "Android",
		"email":              nil,
		"notificationToken":  "",
		"oldToken":           nil,
		"peerKey":            pub,
		"timeZone":           timeZone,
		"token":              "",
	}
	status, parsed, err := c.registerPost("/v2.8/register", regPayload, deviceID)
	if err != nil {
		return Credential{}, err
	}
	if status != http.StatusCreated {
		return Credential{}, fmt.Errorf("register: expected http 201, got %d", status)
	}
	token := digStr(parsed, "result", "token")
	serverKey := digInt(parsed, "result", "serverKey")
	if token == "" || serverKey == 0 {
		return Credential{}, fmt.Errorf("register: missing token/serverKey in response")
	}
	finalKey := crypto.DHFinalKey(priv, serverKey)

	base := map[string]any{
		"carrierCountryCode": carrierMCC,
		"carrierName":        carrierName,
		"carrierNetworkCode": carrierMNC,
		"countryCode":        "id",
		"deviceName":         deviceName,
		"notificationToken":  "",
		"timeZone":           timeZone,
		"token":              token,
	}

	// Ordered init handshake exactly as gtc.py. Status codes are checked.
	type step struct {
		endpoint string
		payload  map[string]any
		want     int
	}
	steps := []step{
		{"/v2.8/init-basic", cloneMap(base), http.StatusCreated},
		{"/v2.8/ad-settings", map[string]any{"source": "init", "token": token}, http.StatusOK},
		{"/v2.8/init-intro", withMap(base, "hasRouting", false), http.StatusCreated},
		{"/v2.8/email-code-validate/start", map[string]any{
			"email":    fmt.Sprintf("user%d@gmail.com", randInt(10_000_000, 100_000_000)),
			"fullName": fmt.Sprintf("User%d", randInt(1000, 1_000_000)),
			"token":    token,
		}, http.StatusOK},
		{"/v2.8/country", map[string]any{"countryCode": "ID", "token": token}, http.StatusOK},
		{"/v2.8/validation-start", map[string]any{
			"app":               "verifykit",
			"countryCode":       "id",
			"notificationToken": "",
			"token":             token,
		}, http.StatusOK},
	}
	for _, s := range steps {
		st, _, err := c.gtcCall(s.endpoint, s.payload, token, finalKey, deviceID, true)
		if err != nil {
			return Credential{}, fmt.Errorf("%s: %w", s.endpoint, err)
		}
		if st != s.want {
			return Credential{}, fmt.Errorf("%s: expected http %d, got %d", s.endpoint, s.want, st)
		}
	}

	// VerifyKit handshake.
	vfkBasePayload := map[string]any{
		"countryCode": "ID",
		"deviceName":  deviceName,
		"bundleId":    bundleID,
		"timezone":    timeZone,
	}
	if st, _, err := c.vfkCall("/v2.0/init", withMap(vfkBasePayload,
		"isCallPermissionGranted", true,
		"outsideCountryCode", "ID",
		"outsidePhoneNumber", phone,
		"installedApps", `{"whatsapp":0,"telegram":0,"viber":0}`,
	), deviceID); err != nil {
		return Credential{}, fmt.Errorf("vfk init: %w", err)
	} else if st != http.StatusOK {
		return Credential{}, fmt.Errorf("vfk init: HTTP %d", st)
	}
	if st, _, err := c.vfkCall("/v2.0/country", map[string]any{"countryCode": "ID", "bundleId": bundleID}, deviceID); err != nil {
		return Credential{}, fmt.Errorf("vfk country: %w", err)
	} else if st != http.StatusOK {
		return Credential{}, fmt.Errorf("vfk country: HTTP %d", st)
	}
	_, startParsed, err := c.vfkCall("/v2.0/start", map[string]any{
		"countryCode": "ID",
		"mcc":         carrierMCC,
		"mnc":         carrierMNC,
		"phoneNumber": phone,
		"app":         "whatsapp",
		"bundleId":    bundleID,
	}, deviceID)
	if err != nil {
		return Credential{}, fmt.Errorf("vfk start: %w", err)
	}
	deeplink := digStr(startParsed, "result", "deeplink")
	reference := digStr(startParsed, "result", "reference")
	if deeplink == "" || reference == "" {
		return Credential{}, fmt.Errorf("vfk start: missing deeplink/reference")
	}
	// Second /v2.8/validation-start after the VerifyKit handshake, exactly as
	// gtc.py does (once in the init steps, once here before the WhatsApp step).
	if _, _, err := c.gtcCall("/v2.8/validation-start", map[string]any{
		"app":               "verifykit",
		"countryCode":       "id",
		"notificationToken": "",
		"token":             token,
	}, token, finalKey, deviceID, true); err != nil {
		return Credential{}, fmt.Errorf("validation-start (2nd): %w", err)
	}

	// Surface the code so the caller can complete the WhatsApp send.
	if code := extractCode(deeplink); code != "" {
		fmt.Printf("WhatsApp verification code: %s\nDeeplink: %s\nSend this code via WhatsApp, then the server will confirm.\n", code, deeplink)
	} else {
		fmt.Printf("WhatsApp deeplink: %s\n", deeplink)
	}

	// The VerifyKit check only succeeds once the WhatsApp side is confirmed.
	// gtc.py blocks on input(); we poll until confirmed so the CLI works
	// interactively without reading stdin.
	fmt.Println("Waiting for WhatsApp confirmation...")
	var sessionID string
	for attempt := 0; attempt < vfkCheckAttempts; attempt++ {
		_, checkParsed, err := c.vfkCall("/v2.0/check", map[string]any{"reference": reference, "bundleId": bundleID}, deviceID)
		if err != nil {
			return Credential{}, fmt.Errorf("vfk check: %w", err)
		}
		sessionID = digStr(checkParsed, "result", "sessionId")
		if sessionID != "" {
			break
		}
		time.Sleep(vfkCheckInterval)
	}
	if sessionID == "" {
		return Credential{}, fmt.Errorf("verification not completed within %s: send the WhatsApp code and retry",
			time.Duration(vfkCheckAttempts)*vfkCheckInterval)
	}

	_, vkParsed, err := c.gtcCall("/v2.8/verifykit-result", map[string]any{"sessionId": sessionID, "token": token}, token, finalKey, deviceID, true)
	if err != nil {
		return Credential{}, fmt.Errorf("verifykit-result: %w", err)
	}
	validationDate := digStr(vkParsed, "result", "validationDate")

	cred := Credential{
		Description:    description,
		PhoneNumber:    phone,
		ClientDeviceID: deviceID,
		FinalKey:       finalKey,
		Token:          token,
		ValidationDate: validationDate,
	}
	return cred, nil
}

func extractCode(deeplink string) string {
	for _, m := range codeRe.FindAllStringSubmatch(deeplink, -1) {
		if len(m) >= 2 && codeValidRe.MatchString(m[1]) {
			return m[1]
		}
	}
	return ""
}

// --- map helpers -----------------------------------------------------------

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func withMap(m map[string]any, kv ...any) map[string]any {
	out := cloneMap(m)
	for i := 0; i+1 < len(kv); i += 2 {
		out[fmt.Sprintf("%v", kv[i])] = kv[i+1]
	}
	return out
}

func randInt(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	if err != nil {
		return lo
	}
	return lo + int(n.Int64())
}
