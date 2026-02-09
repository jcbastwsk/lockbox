# lockbox Wire Format

## Encrypted File Format

```
Offset  Size     Description
──────  ─────    ───────────
0       8        Magic: "LOCKBOX\x00"
8       1        Version (currently 0x01)
9       1        Type byte
10      32       Sender fingerprint (SHA-256 of Ed25519 public key)
42      32       Ephemeral X25519 public key
74      24       Nonce (XChaCha20-Poly1305)
98      var      Ciphertext + 16-byte Poly1305 tag
```

Total header: 98 bytes.

### Type Bytes

| Value  | Name             | Description                              |
|--------|------------------|------------------------------------------|
| `0x01` | Sealed           | Anonymous (no sender identity)           |
| `0x02` | Authenticated    | Sender identified by fingerprint         |
| `0x03` | Signed+Encrypted | Signed then encrypted                    |

### Encryption Scheme

1. Sender generates an ephemeral X25519 keypair
2. Recipient's Ed25519 public key is converted to X25519 via `crypto_sign_ed25519_pk_to_curve25519`
3. Shared secret computed: `crypto_box_beforenm(shared, recip_x25519, eph_sk)`
4. Random 24-byte nonce generated
5. Plaintext encrypted: `crypto_aead_xchacha20poly1305_ietf_encrypt(ct, pt, nonce, shared)`
6. Header + ciphertext written to output

### Decryption

1. Parse and validate header (magic, version)
2. Recipient's Ed25519 secret key converted to X25519 via `crypto_sign_ed25519_sk_to_curve25519`
3. Shared secret computed: `crypto_box_beforenm(shared, eph_pk, recip_x25519_sk)`
4. Ciphertext decrypted and authenticated: `crypto_aead_xchacha20poly1305_ietf_decrypt`

## Detached Signatures

Detached signatures are base64-encoded Ed25519 signatures (64 bytes raw).
Output as a single line of base64 text.

## Sigchain Format

JSON array where each element is a signed link:

```json
{
  "seqno": 1,
  "type": "key.create",
  "timestamp": 1707500000,
  "payload": { ... },
  "prev": null,
  "signature": "<base64>"
}
```

- `seqno`: Monotonically increasing, starting at 1
- `type`: One of `key.create`, `key.revoke`, `identity.prove.dns`, `identity.prove.https`, `identity.revoke`
- `timestamp`: Unix timestamp
- `payload`: Type-specific data
- `prev`: Base64-encoded SHA-256 hash of the previous link's canonical JSON (null for first link)
- `signature`: Base64-encoded Ed25519 detached signature of canonical JSON (all fields except `signature`, sorted keys, compact)

## Identity Proofs

### DNS Proof

TXT record at `_lockbox.<domain>`:
```
lockbox-proof=<base64>
```

The base64 decodes to: `<json-statement>.<ed25519-signature>`

Statement JSON: `{"domain":"...","fingerprint":"...","timestamp":...,"type":"dns"}`

### HTTPS Proof

File at `https://<domain>/.well-known/lockbox.json`:
```json
{
  "fingerprint": "<hex>",
  "public_key": "<base64>",
  "proofs": [
    {
      "type": "https",
      "domain": "<domain>",
      "statement": "<canonical-json>",
      "sig": "<base64>"
    }
  ]
}
```

## Key Fingerprint

SHA-256 hash of the raw 32-byte Ed25519 public key, displayed as 64 hex characters.
