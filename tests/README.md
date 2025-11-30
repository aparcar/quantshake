# Integration Tests

This directory contains end-to-end integration tests for QuantShake that verify the complete daemon functionality with real network communication and key exchange.

## Test Scripts

### `integration_two_peers.sh`

Tests the basic two-peer scenario using command-line flags:
- **Alice** and **Bob** both act as client and server
- Both daemons listen on different ports and connect to each other
- Verifies PSK files are created and match
- Validates 32-byte key format

**Run:**
```bash
cd test
./integration_two_peers.sh
```

**Duration:** ~15 seconds

### `integration_three_peers.sh`

Tests the multi-peer scenario with different peer roles using TOML configuration:
- **Alice**: Client only (no listener, only initiates connections)
- **Bob**: Client and Server (accepts from Alice, connects to Charlie)
- **Charlie**: Server only (only accepts incoming connections)

This test verifies:
- ✓ All 6 PSK files are created (2 per peer pair)
- ✓ PSK pairs match between peers
- ✓ All PSKs are different (due to ephemeral randomness)
- ✓ Role behavior is correct (client-only vs server-only vs both)
- ✓ Peer identification works correctly (IK pattern feature)

**Run:**
```bash
cd test
./integration_three_peers.sh
```

**Duration:** ~20 seconds

## CI Integration

These tests run automatically in GitHub Actions via `.github/workflows/integration.yml`:
- Runs on both Ubuntu and macOS
- Executes on every push and pull request to main
- Test logs are uploaded as artifacts on failure

## Requirements

- Go 1.24+
- Available ports: 19001-19003 (for tests)
- `base64` command (standard on Unix systems)

## Manual Testing

Clean up any leftover test directories before running:
```bash
cd test
rm -rf test_output test_output_3peer
./integration_two_peers.sh
./integration_three_peers.sh
```

## What Gets Tested

### Two-Peer Test
1. Binary builds successfully
2. Key generation works
3. Daemons start and maintain connections
4. PSK files are created
5. PSKs match between peers
6. Keys are valid 32-byte base64-encoded values

### Three-Peer Test
1. Multi-peer TOML configuration parsing
2. Client-only mode (no listener)
3. Server-only mode (no outgoing connections)
4. Mixed client+server mode
5. Peer identification via IK pattern
6. Independent PSK generation per peer pair
7. Correct role behavior verification

## Output

Both tests produce:
- ✓ Success indicators for each verification step
- Detailed logs in `test_output/` or `test_output_3peer/`
- PSK files for manual inspection
- Error messages with full logs on failure

Example successful output:
```
=== Three-Peer Multi-Role Integration Test PASSED ===
Summary:
  - Alice (client): Connected to Bob and Charlie ✓
  - Bob (client+server): Connected to Alice and Charlie ✓
  - Charlie (server): Accepted from Alice and Bob ✓
  - All PSK pairs verified and match ✓
```
