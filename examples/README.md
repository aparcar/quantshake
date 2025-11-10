# QuantShake Examples

This directory contains example programs demonstrating how to use the QuantShake library.

## Simple Handshake Example

**File:** `simple_handshake.go`

A minimal, single-file example demonstrating the complete 3-message Noise KK handshake pattern with post-quantum KEMs.

### What it demonstrates:

1. **Key Generation** - Creates keypairs for two parties (Alice and Bob)
2. **Message 1** - Initiator sends ephemeral key + 2 KEM ciphertexts
3. **Message 2** - Responder sends ephemeral key + 2 KEM ciphertexts
4. **Message 3** - Initiator sends encrypted acknowledgment
5. **Shared Key** - Both parties derive identical 32-byte keys

### Run the example:

```bash
go run examples/simple_handshake.go
```

### Expected output:

```
=== QuantShake Simple Handshake Example ===

Using KEM: ML-KEM-768

Generating keypairs...
✓ Alice and Bob have their keypairs

--- Message 1: Alice -> Bob ---
✓ Alice sends: ephemeral key + 2 KEM ciphertexts
  - Ephemeral key: 1184 bytes
  - CT_es: 1088 bytes
  - CT_ss: 1088 bytes

✓ Bob processed Message 1

--- Message 2: Bob -> Alice ---
✓ Bob sends: ephemeral key + 2 KEM ciphertexts
  - Ephemeral key: 1184 bytes
  - CT_se: 1088 bytes
  - CT_ss: 1088 bytes

✓ Alice processed Message 2
✓ Alice and Bob both derived shared keys

--- Message 3: Alice -> Bob (Acknowledgment) ---
✓ Alice sends: encrypted handshake hash (60 bytes)

✓ Bob verified Message 3 - handshake complete!

=== Handshake Complete ===
Alice's shared key: [32 bytes hex]
Bob's shared key:   [32 bytes hex]

✅ SUCCESS: Both parties derived the same 32-byte shared key!
```

### Key Concepts:

- **No network communication** - Pure in-memory handshake
- **No file I/O** - Keys generated and used in memory only
- **Complete handshake** - Shows all three messages
- **Verification** - Confirms both parties derive matching keys

### Customization:

You can easily modify the example to:
- Try different KEMs (`NewXWing()`, `NewSntrup761()`)
- Change the prologue for different contexts
- Add your own payload encryption after handshake
