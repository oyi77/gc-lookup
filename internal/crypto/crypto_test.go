package crypto

import (
	"crypto/aes"
	"testing"
)

func TestAESECBRoundTrip(t *testing.T) {
	// AES-256 keys are 32 bytes (64 hex chars). These mirror the canonical
	// protocol finalKey values (sha256(serverPub^priv).hexdigest()).
	for _, keyHex := range []string{
		"bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa",
		"31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b",
		"3452235d7132526052342d4b5a566a4f7a7333513a3073315234736e3141717a",
	} {
		p := "payload:" + keyHex[:8]
		ct, err := EncryptToB64(p, keyHex)
		if err != nil {
			t.Fatalf("encrypt(%q): %v", keyHex, err)
		}
		got, err := DecryptFromB64(ct, keyHex)
		if err != nil {
			t.Fatalf("decrypt(%q): %v", keyHex, err)
		}
		if got != p {
			t.Fatalf("round-trip mismatch: got %q want %q", got, p)
		}
	}
}

func TestAESECBNonDeterministicAcrossKeys(t *testing.T) {
	p := "same plaintext payload for both keys to ensure separation"
	// Both keys MUST be 32-byte AES-256 keys.
	k1 := "bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa"
	k2 := "3452235d7132526052342d4b5a566a4f7a7333513a3073315234736e3141717a"
	c1, err := EncryptToB64(p, k1)
	if err != nil {
		t.Fatalf("encrypt k1: %v", err)
	}
	c2, err := EncryptToB64(p, k2)
	if err != nil {
		t.Fatalf("encrypt k2: %v", err)
	}
	if c1 == c2 {
		t.Fatal("ciphertext should differ by key")
	}
}

func TestHMACSignMatchesReference(t *testing.T) {
	// Reference computed from the canonical gtc.py definition:
	//   base64(hmac_sha256(bytes.fromhex(HMAC_KEY), f"{ts}-{msg}"))
	// with HMAC_KEY below, ts="1700000000000", msg='{"a":1}'.
	keyHex := "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"
	ts := "1700000000000"
	msg := `{"a":1}`
	got, err := HMACSign(ts, msg, keyHex)
	if err != nil {
		t.Fatal(err)
	}
	// Golden value computed from the Python reference (gtc.py _sig):
	//   base64(hmac_sha256(bytes.fromhex(HMAC_KEY), f"1700000000000-{'{\"a\":1}}"))
	const want = "dmVB2fDXcuVnDwf4A26xxc3exNrmNvDABUmemQneqTw="
	// But also verify determinism as a second check.
	again, _ := HMACSign(ts, msg, keyHex)
	if got != again {
		t.Fatal("HMACSign not deterministic")
	}
	if got != want {
		t.Fatalf("HMACSign = %q, want %q (computed from reference gtc.py)", got, want)
	}
}

func TestDHFinalKeyDeterministicAndNonZero(t *testing.T) {
	priv, pub := int64(1234567), DHExp(DH_G, 1234567)
	serverPub := DHExp(DH_G, 9876543)
	// shared = g^(priv*serverPriv) mod p = same from both sides
	sharedPrivSide := DHFinalKey(priv, serverPub)
	sharedServerSide := DHFinalKey(9876543, pub)
	if sharedPrivSide != sharedServerSide {
		t.Fatalf("DH mismatch: %s vs %s", sharedPrivSide, sharedServerSide)
	}
	if len(sharedPrivSide) != 64 {
		t.Fatalf("final key should be 64 hex chars (sha256), got %d", len(sharedPrivSide))
	}
}

func TestDHKeypairRange(t *testing.T) {
	for i := 0; i < 50; i++ {
		priv, pub := mustKeypair(t)
		if priv < 1_000_000 || priv >= 100_000_000 {
			t.Fatalf("priv out of range: %d", priv)
		}
		if pub <= 0 {
			t.Fatalf("pub must be positive, got %d", pub)
		}
	}
}

func mustKeypair(t *testing.T) (int64, int64) {
	t.Helper()
	priv, pub, err := DHKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestPKCS7UnpadRejectsGarbage(t *testing.T) {
	if _, err := pkcs7Unpad([]byte("abc")); err == nil {
		t.Fatal("expected error for short input")
	}
	// valid pad
	good := pkcs7Pad([]byte("hi"), aes.BlockSize)
	if _, err := pkcs7Unpad(good); err != nil {
		t.Fatalf("valid pad rejected: %v", err)
	}
}

func TestEncryptToB64BadKeyHex(t *testing.T) {
	if _, err := EncryptToB64("data", "zzz"); err == nil {
		t.Fatal("expected error for non-hex key")
	}
	// Odd-length hex string also fails decode.
	if _, err := EncryptToB64("data", "abc"); err == nil {
		t.Fatal("expected error for odd-length key hex")
	}
	// 31-byte key fails AES-256 (needs exactly 32 bytes).
	if _, err := EncryptToB64("data", "00112233445566778899aabbccddeeff00112233445566778899aabbccddee"); err == nil {
		t.Fatal("expected error for 31-byte key")
	}
}

func TestDecryptFromB64Errors(t *testing.T) {
	// Bad key hex.
	if _, err := DecryptFromB64("AAAA", "zzz"); err == nil {
		t.Fatal("expected error for non-hex key")
	}
	// Bad base64 payload.
	if _, err := DecryptFromB64("!!!not-base64!!!", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("expected error for bad base64")
	}
	// Valid base64 but not block-aligned (15 bytes).
	if _, err := DecryptFromB64("AAAAAAAAAAAAAAAAAAAAAAA=", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("expected error for non-block-aligned ciphertext")
	}
}

func TestHMACSignBadKey(t *testing.T) {
	if _, err := HMACSign("1700000000000", `{"a":1}`, "nothex"); err == nil {
		t.Fatal("expected error for non-hex key")
	}
}

func TestAESECBWrongKeyLength(t *testing.T) {
	// 16-byte key must be rejected (AES-256 needs 32).
	if _, err := EncryptToB64("data", "00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestAESECBGoldenVector(t *testing.T) {
	// Encryption of known plaintext with TEST_KEY, computed from gtc.py's
	// encrypt() using the cryptography library:
	//   base64(AES-256-ECB(pad('{"hello":"world"}')))
	keyHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	ct, err := EncryptToB64(`{"hello":"world"}`, keyHex)
	if err != nil {
		t.Fatal(err)
	}
	const want = "bbVDjluZZi2/OQoP3uv7VsP2kz+b9OqUs3/Dh73Az5A="
	if ct != want {
		t.Fatalf("EncryptToB64 = %q, want %q", ct, want)
	}
	// Round-trip.
	got, err := DecryptFromB64(ct, keyHex)
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"hello":"world"}` {
		t.Fatalf("decrypt = %q", got)
	}
}

func TestDHGoldenValues(t *testing.T) {
	// DHExp(g^127 mod p) computed from Python: pow(7, 1234567, 900719898367).
	pub1 := DHExp(DH_G, 1234567)
	if pub1 != 325365675534 {
		t.Fatalf("DHExp(7,1234567) = %d, want 325365675534 (from gtc.py)", pub1)
	}
	// DHFinalKey(priv=1234567, serverPub = 7^9876543 mod p).
	serverPub := DHExp(DH_G, 9876543)
	final := DHFinalKey(1234567, serverPub)
	if final != "ade430f25aed6dba500d9caf324efb504b3699830587868ddbf1695bfafde484" {
		t.Fatalf("DHFinalKey = %q, want ade430...484 (from gtc.py)", final)
	}
	// Symmetry: other side derives the same key.
	sym := DHFinalKey(9876543, pub1)
	if sym != final {
		t.Fatalf("DH final key not symmetric: %q != %q", sym, final)
	}
}

func TestPKCS7UnpadInconsistentPadding(t *testing.T) {
	// Valid: 3 pad bytes of value 3.
	good := []byte{'a', 'b', 'c', 3, 3, 3}
	if _, err := pkcs7Unpad(good); err != nil {
		t.Fatalf("valid pad rejected: %v", err)
	}
	// Corrupt one pad byte: last byte claims 3 but middle pad byte is 2.
	bad := []byte{'a', 'b', 'c', 3, 2, 3}
	if _, err := pkcs7Unpad(bad); err == nil {
		t.Fatal("expected error for inconsistent padding")
	}
}
