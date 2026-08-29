package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// --- DH handshake constants (from gtc.py) ---
const (
	DH_P = 900719898367 // modulus
	DH_G = 7            // generator
)

// --- AES-256-ECB (Go has no ECB; encrypt each 16-byte block with same key) ---

func aes256ECBEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes for AES-256, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize() // 16
	if len(plaintext)%bs != 0 {
		return nil, fmt.Errorf("crypto: plaintext not block-aligned")
	}
	out := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += bs {
		block.Encrypt(out[i:i+bs], plaintext[i:i+bs])
	}
	return out, nil
}

func aes256ECBDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes for AES-256, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(ciphertext)%bs != 0 {
		return nil, fmt.Errorf("crypto: ciphertext not block-aligned")
	}
	out := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += bs {
		block.Decrypt(out[i:i+bs], ciphertext[i:i+bs])
	}
	return out, nil
}

// --- PKCS7 ---

func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - (len(data) % blockSize)
	pad := make([]byte, n)
	for i := range pad {
		pad[i] = byte(n)
	}
	return append(data, pad...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("crypto: empty data")
	}
	n := int(data[len(data)-1])
	if n <= 0 || n > len(data) {
		return nil, fmt.Errorf("crypto: invalid PKCS7 padding")
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, fmt.Errorf("crypto: inconsistent PKCS7 padding")
		}
	}
	return data[:len(data)-n], nil
}

// --- Public API used by client ---

// EncryptToB64 AES-256-ECB encrypts (PKCS7 padded) then base64-encodes.
func EncryptToB64(data, keyHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("crypto: bad key hex: %w", err)
	}
	padded := pkcs7Pad([]byte(data), aes.BlockSize)
	ct, err := aes256ECBEncrypt(key, padded)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// DecryptFromB64 base64-decodes then AES-256-ECB decrypts and strips PKCS7.
func DecryptFromB64(data, keyHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("crypto: bad key hex: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("crypto: bad base64: %w", err)
	}
	pt, err := aes256ECBDecrypt(key, ct)
	if err != nil {
		return "", err
	}
	unpadded, err := pkcs7Unpad(pt)
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

// HMACSign matches gtc.py _sig(ts, msg, keyHex):
//
//	base64(HMAC-SHA256(bytes.fromhex(keyHex), "{ts}-{msg}"))
//
// ts is the millisecond timestamp STRING; msg is the RAW json string (not encrypted).
func HMACSign(ts, msg, keyHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("crypto: bad key hex: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "-" + msg))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// --- DH ---

// DHKeypair returns (priv, pub) where pub = g^priv mod p, priv in [1e6, 1e8).
func DHKeypair() (priv, pub int64, err error) {
	const lo int64 = 1_000_000
	const span int64 = 99_000_000 // [1e6, 1e8)
	k, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, 0, err
	}
	priv = k.Int64() + lo
	pub = DHExp(DH_G, priv)
	return priv, pub, nil
}

// DHExp computes g^e mod DH_P using big.Int (deterministic, no side channel concern here).
func DHExp(g, e int64) int64 {
	p := big.NewInt(DH_P)
	res := new(big.Int).Exp(big.NewInt(g), big.NewInt(e), p)
	return res.Int64()
}

// DHFinalKey = sha256(str(serverPub^priv mod p)).hexdigest()
func DHFinalKey(priv, serverPub int64) string {
	shared := new(big.Int).Exp(big.NewInt(serverPub), big.NewInt(priv), big.NewInt(DH_P))
	return fmt.Sprintf("%x", sha256.Sum256([]byte(shared.String())))
}

// BlockCipherFor returns a no-op wrapper to satisfy interfaces; kept for clarity.
var _ cipher.Block = func() cipher.Block { b, _ := aes.NewCipher(make([]byte, 32)); return b }()
