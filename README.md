# gc-lookup — GetContact lookup CLI

Faithful Go port of [gtc.py](https://github.com/xdreizein666/getcontact-cli), the
GetContact API client. Constants, endpoints, headers, and payloads mirror the
Python reference exactly — any deviation breaks wire compatibility.

## Status

| Metric | Value |
|---|---|
| Build | green (`go build ./...`) |
| Tests | green (`go test ./...`) — 50 tests (24 client + 12 crypto + 14 cmd), no network (httptest) |
| Race | clean (`go test -race ./...`) |
| Coverage | 82.2% client / 90.0% crypto / 34.5% cmd |
| Cross-compile | green — linux/amd64, windows/amd64, darwin/arm64 |
| Upstream | [`xdreizein666/getcontact-cli`](https://github.com/xdreizein666/getcontact-cli) `gtc.py` |

## Protocol

The GetContact API uses a custom crypto layer:

1. **DH key exchange** — modulus P = 900719898367, generator G = 7. Both sides
   derive a shared secret `sha256(str(g^{ab} mod p)).hexdigest()`.
2. **AES-256-ECB** — each block encrypted independently with the shared secret.
   PKCS7 padding. No GCM/CBC — this is the protocol as defined.
3. **HMAC-SHA256** — every request signed with a fixed key:
   `base64(hmac_sha256(bytes.fromhex(key), "{ts}-{raw}"))`.

## Usage

```
gc-lookup search <phone> [--source profile|tags]
gc-lookup subscription
gc-lookup refresh-code
gc-lookup verify-code <code>
gc-lookup register <phone> [--name desc]
gc-lookup cred list|use <name>|remove <name>|path
gc-lookup help
```

### Credential store

Credentials are stored at `$GTC_CONFIG_DIR/credentials.json` (default
`~/.config/gtc/`). The `cred` subcommand manages them:

```
$ gc-lookup cred list
* acc-a  phone=628111 token=tok-aaa-… finalKey=f1f2f3f4…
  acc-b  phone=628222 token=tok-bbb… finalKey=aa…

$ gc-lookup cred use acc-b
active credential: acc-b
```

### Registration (interactive)

`gc-lookup register` performs the full handshake, but the WhatsApp verification
step is interactive:

1. Run `gc-lookup register 628123456789`
2. The CLI prints a verification code and deeplink.
3. Send that code to the phone number via WhatsApp.
4. The server confirms automatically; the account is saved to the store.

## Build

```
go build ./...
go test ./...
```

## Disclaimer

This is an **unofficial** client. It is not affiliated with GetContact. The
protocol constants are exact copies of the upstream Python reference. Use at
your own risk.

The canonical source of truth is `gtc.py` at
[github.com/xdreizein666/getcontact-cli](https://github.com/xdreizein666/getcontact-cli).
**Do not guess** — any deviation from the Python reference breaks wire
compatibility.