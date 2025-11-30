# QuantShake

<img src="misc/quantshake.svg" align="right" width="100">

A Post-Quantum Cryptography (PQC) demonstration implementing a peer-to-peer handshake daemon with support for multiple KEM algorithms.

> [!WARNING]
> This code has NOT been audited and is intended for research and educational purposes only.
> - The AEAD encryption in the handshake uses **random nonces** instead of counter-based nonces
> - While ChaCha20-Poly1305 with random 96-bit nonces has negligible collision probability for reasonable message counts, this deviates from standard Noise protocol implementations
> - Do NOT use this in production systems without a thorough security audit
> - Consider this a proof-of-concept implementation for studying post-quantum key exchange patterns

## Features

### Supported KEM Algorithms
- **ML-KEM-768** (formerly Kyber768) - NIST standardized lattice-based KEM
- **X-Wing** - Hybrid KEM combining X25519 with ML-KEM-768
- **sntrup761** - Streamlined NTRU Prime

### Key Generation
Generate keypairs for any supported KEM algorithm:
```bash
./quantshake genkey --kem mlkem768 --name mykey
```

This creates:
- `mykey.pub` - Public key (JSON format with base64-encoded key)
- `mykey.sec` - Secret key (JSON format with base64-encoded key, mode 0600)

**Available algorithms:**
- `mlkem768` - ML-KEM-768 (NIST standard)
- `xwing` - X-Wing hybrid (X25519 + ML-KEM-768)
- `sntrup761` - Streamlined NTRU Prime

### 3-Message Handshake Protocol
Based on post-quantum IK pattern (pqIK) with KEMs for identity hiding and peer identification:

**Pre-conditions:**
- Responder's static public key is known to the initiator
- Initiator's identity is hidden until decrypted by responder

**Message 1** (Initiator → Responder)
```
-> skem, e, s
```
- `CT_ss`: SKEM - Initiator static encapsulates to responder's static key
- `EI`: Initiator's ephemeral public key
- `EncSI`: **Encrypted initiator's static public key** (identity hiding!)
- **Key schedule**: mixKey(ss_ss), mixHash(CT_ss), mixHash(EI), encryptAndHash(SI)
- **Identity hiding**: Passive observers cannot determine who is connecting

**Message 2** (Responder → Initiator)
```
<- ekem, skem
```
- `ER`: Responder's ephemeral public key
- `CT_ee`: EKEM - Responder ephemeral encapsulates to initiator's ephemeral key
- `CT_se`: SKEM - Responder static encapsulates to initiator's static key
- **Key schedule**: mixHash(ER), mixKey(ss_ee), mixHash(CT_ee), mixKey(ss_se), mixHash(CT_se)
- Both parties derive the **32-byte shared key** using HKDF-Expand(ck, "shared", 32)

**Message 3** (Initiator → Responder)
```
-> ack
```
- `EncryptedHash`: ChaCha20-Poly1305 encrypted hash of handshake transcript
- Provides explicit mutual authentication confirmation
- Encrypted with HKDF-Expand(handshakeHash, "ack", 32)

**Result:**
Both parties derive an identical **32-byte shared key** after Message 2, confirmed by Message 3.

### Daemon Mode

QuantShake supports two modes: **single-peer** (command-line flags) and **multi-peer** (TOML configuration).

#### Single-Peer Mode

Run as a daemon that maintains continuous key exchange with one peer:

```bash
./quantshake daemon \
  --listen 127.0.0.1:9001 \
  --endpoint 127.0.0.1:9002 \
  --private-key peer1.sec \
  --peer-public-key peer2.pub \
  --output alice.psk \
  --interval 120
```

Or using short flags (WireGuard-style):
```bash
./quantshake daemon --listen 127.0.0.1:9001 -e 127.0.0.1:9002 \
  -k peer1.sec -p peer2.pub -o alice.psk -i 120
```

**Parameters:**
- `--listen` - Local address to listen for incoming connections (default: `127.0.0.1:8000`)
- `--endpoint`, `-e` - Peer endpoint address to connect to (default: `127.0.0.1:8001`)
- `--private-key`, `-k` - Path to our private key file (required)
- `--peer-public-key`, `-p` - Path to peer's public key file (required)
- `--output`, `-o` - Output PSK file path (required)
- `--interval`, `-i` - Seconds between key exchanges (default: `120`)

#### Multi-Peer Mode

For managing multiple peers simultaneously, use a TOML configuration file:

```bash
./quantshake daemon --config peers.toml
```

**Example Configuration** (`peers.toml`):
```toml
[daemon]
listen_addr = "0.0.0.0:8000"  # Optional: omit for outgoing-only mode
private_key = "/etc/quantshake/mykey.sec"
interval = 120  # Default interval for all peers

# Bidirectional peer (we both connect to each other)
[[peers]]
name = "alice"
public_key = "/etc/quantshake/alice.pub"
endpoint = "alice.example.com:8000"
output_psk = "/var/lib/quantshake/alice.psk"

# Outgoing-only peer (we initiate, they don't connect to us)
[[peers]]
name = "bob"
public_key = "/etc/quantshake/bob.pub"
endpoint = "10.0.1.5:8000"
output_psk = "/var/lib/quantshake/bob.psk"
interval = 60  # Custom interval for this peer

# Incoming-only peer (they initiate, we accept)
[[peers]]
name = "charlie"
public_key = "/etc/quantshake/charlie.pub"
# No endpoint - charlie will connect to us
output_psk = "/var/lib/quantshake/charlie.psk"
```

Use `./quantshake daemon --help` for complete usage information.

**Behavior:**
- Both peers attempt to connect to each other periodically
- One becomes initiator, one becomes responder
- After successful handshake, both derive identical 32-byte shared key
- Key is saved as base64 in the specified output PSK file (mode 0600)
- **Timeout mechanism**:
  - If no exchange succeeds after `interval + 10` seconds, an immediate retry is attempted
  - If still no exchange after `interval + 30` seconds, a random fallback key is injected
  - This prevents mismatched intervals from causing premature timeouts

**PSK File Format:**
The shared key is stored as a simple base64-encoded string:
```
fRJwyfnGRI1+iObYEpSamMuAkWbiiq4ka+ZjoOyunrM=
```

This is a 32-byte (256-bit) key encoded in base64, suitable for direct use with symmetric encryption.

## Usage Examples

### 1. Generate Keys for Two Peers
```bash
./quantshake genkey --kem mlkem768 --name alice
./quantshake genkey --kem mlkem768 --name bob
```

### 2. Start Two Daemons
```bash
# Terminal 1 - Alice
./quantshake daemon --listen :9001 -e :9002 -k alice.sec -p bob.pub -o bob.psk

# Terminal 2 - Bob
./quantshake daemon --listen :9002 -e :9001 -k bob.sec -p alice.pub -o alice.psk
```

After successful exchange:
- Alice will have `bob.psk` containing the shared key
- Bob will have `alice.psk` containing the same shared key

### 3. Verify PSKs Match
```bash
# Compare the PSK files
diff bob.psk alice.psk && echo "PSKs match!" || echo "PSKs differ!"

# View the key
cat bob.psk
```

## Architecture

### Core Files
- **main.go** - CLI interface and command handling
- **daemon.go** - Single-peer daemon with retry logic and role negotiation
- **multipeer.go** - Multi-peer daemon with automatic peer identification
- **config.go** - TOML configuration parsing and validation
- **keygen.go** - Key generation utilities

### Handshake Package (`pkg/handshake/`)
- **noiseik.go** - Noise IK pattern implementation with PQC KEMs
- **noiseik_test.go** - Comprehensive handshake protocol tests

### KEM Package (`pkg/kem/`)
- **kem.go** - KEM interface and factory functions
- **mlkem.go** - ML-KEM-768 (NIST standardized) implementation
- **xwing.go** - X-Wing hybrid KEM (X25519 + ML-KEM-768)
- **sntrup761.go** - Streamlined NTRU Prime implementation

## Protocol Details

### Post-Quantum IK Pattern (pqIK)

QuantShake implements a post-quantum IK handshake pattern optimized for KEMs:

**Key Features:**
- **Identity hiding**: Initiator's static public key is encrypted in Message 1
- **Peer identification**: Responder can identify which peer is connecting after decrypting Message 1
- **Three KEM operations**: Optimized for post-quantum efficiency
  - skem (Msg1): Initiator static → responder static (authentication, starts encryption)
  - ekem (Msg2): Responder ephemeral → initiator ephemeral (forward secrecy)
  - skem (Msg2): Responder static → initiator static (authentication)
- **Key schedule**: HKDF-based (HMAC-SHA256) with chaining key and hash
- **AEAD encryption**: ChaCha20-Poly1305 for encrypting initiator's static key and Message 3
- **Three-message pattern**: Essential for full mutual authentication with PQC

### KEM Operations Breakdown

| Message | Direction | Operation | Purpose |
|---------|-----------|-----------|---------|
| Msg1 | I → R | skem | Initiator static → responder static (authentication, starts encryption) |
| Msg1 | I → R | e | Initiator ephemeral public key (in cleartext) |
| Msg1 | I → R | encrypt(SI) | Encrypted initiator static key (identity hiding) |
| Msg2 | R → I | e | Responder ephemeral public key (in cleartext) |
| Msg2 | R → I | ekem | Responder ephemeral → initiator ephemeral (forward secrecy) |
| Msg2 | R → I | skem | Responder static → initiator static (authentication) |

### Key Derivation

Both parties derive a **single symmetric 32-byte key** (not split send/recv keys):

```
shared_key = HKDF-Expand(chaining_key, "shared", 32)
```

## Examples

See the [`examples/`](examples/) directory for usage examples:

- **[simple_handshake.go](examples/simple_handshake.go)** - Minimal single-file example showing a complete 3-message handshake without network or file I/O

Run the example:
```bash
go run examples/simple_handshake.go
```

## License

MIT License - See [LICENSE](LICENSE) file for details.
