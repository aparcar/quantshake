#!/bin/bash
set -e

# Integration test: Two peers with command-line flags
# Alice and Bob exchange keys using the daemon mode

echo "=== Two-Peer Integration Test ==="
echo "Testing command-line daemon mode with two peers"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    kill $ALICE_PID $BOB_PID 2>/dev/null || true
    rm -rf test_output
}
trap cleanup EXIT

# Create test directory
mkdir -p test_output
cd test_output

# Build the binary
echo "Building quantshake..."
go build -o quantshake ../..

# Generate keypairs
echo "Generating keypairs..."
./quantshake genkey --kem mlkem768 --name alice
./quantshake genkey --kem mlkem768 --name bob

# Start Alice daemon
echo "Starting Alice daemon on :19001..."
./quantshake daemon \
    --listen 127.0.0.1:19001 \
    --endpoint 127.0.0.1:19002 \
    --private-key alice.sec \
    --peer-public-key bob.pub \
    --output alice_bob.psk \
    --interval 5 > alice.log 2>&1 &
ALICE_PID=$!
echo "Alice PID: $ALICE_PID"

# Start Bob daemon
echo "Starting Bob daemon on :19002..."
./quantshake daemon \
    --listen 127.0.0.1:19002 \
    --endpoint 127.0.0.1:19001 \
    --private-key bob.sec \
    --peer-public-key alice.pub \
    --output bob_alice.psk \
    --interval 5 > bob.log 2>&1 &
BOB_PID=$!
echo "Bob PID: $BOB_PID"

# Wait for handshake to complete
echo "Waiting for handshake to complete (15 seconds)..."
sleep 15

# Check if processes are still running
if ! kill -0 $ALICE_PID 2>/dev/null; then
    echo "ERROR: Alice daemon died unexpectedly"
    cat alice.log
    exit 1
fi

if ! kill -0 $BOB_PID 2>/dev/null; then
    echo "ERROR: Bob daemon died unexpectedly"
    cat bob.log
    exit 1
fi

# Check if PSK files were created
if [ ! -f alice_bob.psk ]; then
    echo "ERROR: Alice's PSK file not created"
    echo "Alice log:"
    cat alice.log
    exit 1
fi

if [ ! -f bob_alice.psk ]; then
    echo "ERROR: Bob's PSK file not created"
    echo "Bob log:"
    cat bob.log
    exit 1
fi

# Verify PSKs match
echo "Verifying PSKs match..."
ALICE_PSK=$(cat alice_bob.psk)
BOB_PSK=$(cat bob_alice.psk)

if [ "$ALICE_PSK" != "$BOB_PSK" ]; then
    echo "ERROR: PSKs do not match!"
    echo "Alice PSK: $ALICE_PSK"
    echo "Bob PSK: $BOB_PSK"
    exit 1
fi

echo "✓ PSKs match: $ALICE_PSK"

# Verify PSK is valid base64 and 32 bytes when decoded
PSK_DECODED=$(echo "$ALICE_PSK" | base64 -d | wc -c | tr -d ' ')
if [ "$PSK_DECODED" != "32" ]; then
    echo "ERROR: PSK is not 32 bytes when decoded (got $PSK_DECODED bytes)"
    exit 1
fi

echo "✓ PSK is valid 32-byte key"

# Check logs for successful handshake
if grep -q "Handshake successful" alice.log && grep -q "Handshake successful" bob.log; then
    echo "✓ Both peers report successful handshake"
else
    echo "WARNING: Handshake success message not found in logs"
    echo "Alice log:"
    cat alice.log
    echo ""
    echo "Bob log:"
    cat bob.log
fi

echo ""
echo "=== Two-Peer Integration Test PASSED ==="
exit 0
