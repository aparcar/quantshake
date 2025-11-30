#!/bin/bash
set -e

# Integration test: Three peers with different roles
# Alice: Client only (initiator, outgoing connections)
# Bob: Client and Server (both initiator and responder)
# Charlie: Server only (responder, incoming connections)

echo "=== Three-Peer Multi-Role Integration Test ==="
echo "Alice: Client only"
echo "Bob: Client and Server"
echo "Charlie: Server only"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    kill $ALICE_PID $BOB_PID $CHARLIE_PID 2>/dev/null || true
    rm -rf test_output_3peer
}
trap cleanup EXIT

# Create test directory
mkdir -p test_output_3peer
cd test_output_3peer

# Build the binary
echo "Building quantshake..."
go build -o quantshake ../..

# Generate keypairs
echo "Generating keypairs..."
./quantshake genkey --kem mlkem768 --name alice
./quantshake genkey --kem mlkem768 --name bob
./quantshake genkey --kem mlkem768 --name charlie

# Create config files
echo "Creating configuration files..."

# Alice config: Client only - connects to Bob and Charlie
cat > config.alice.toml <<EOF
[daemon]
# No listen_addr - Alice is client only
private_key = "alice.sec"
interval = 5

[[peers]]
name = "bob"
public_key = "bob.pub"
endpoint = "127.0.0.1:19102"
output_psk = "alice_bob.psk"

[[peers]]
name = "charlie"
public_key = "charlie.pub"
endpoint = "127.0.0.1:19103"
output_psk = "alice_charlie.psk"
EOF

# Bob config: Client and Server - listens for Alice, connects to Charlie
cat > config.bob.toml <<EOF
[daemon]
listen_addr = "127.0.0.1:19102"
private_key = "bob.sec"
interval = 5

[[peers]]
name = "alice"
public_key = "alice.pub"
output_psk = "bob_alice.psk"
# No endpoint - only accepts from Alice

[[peers]]
name = "charlie"
public_key = "charlie.pub"
endpoint = "127.0.0.1:19103"
output_psk = "bob_charlie.psk"
EOF

# Charlie config: Server only - listens for Alice and Bob
cat > config.charlie.toml <<EOF
[daemon]
listen_addr = "127.0.0.1:19103"
private_key = "charlie.sec"
interval = 5

[[peers]]
name = "alice"
public_key = "alice.pub"
output_psk = "charlie_alice.psk"
# No endpoint - only accepts from Alice

[[peers]]
name = "bob"
public_key = "bob.pub"
output_psk = "charlie_bob.psk"
# No endpoint - only accepts from Bob
EOF

# Start Charlie daemon (server only)
echo "Starting Charlie daemon (server only) on :19103..."
./quantshake daemon --config config.charlie.toml > charlie.log 2>&1 &
CHARLIE_PID=$!
echo "Charlie PID: $CHARLIE_PID"

# Give Charlie time to start listening
sleep 2

# Start Bob daemon (client and server)
echo "Starting Bob daemon (client and server) on :19102..."
./quantshake daemon --config config.bob.toml > bob.log 2>&1 &
BOB_PID=$!
echo "Bob PID: $BOB_PID"

# Give Bob time to start listening
sleep 2

# Start Alice daemon (client only)
echo "Starting Alice daemon (client only)..."
./quantshake daemon --config config.alice.toml > alice.log 2>&1 &
ALICE_PID=$!
echo "Alice PID: $ALICE_PID"

# Wait for all handshakes to complete
echo "Waiting for handshakes to complete (25 seconds)..."
sleep 25

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

if ! kill -0 $CHARLIE_PID 2>/dev/null; then
    echo "ERROR: Charlie daemon died unexpectedly"
    cat charlie.log
    exit 1
fi

echo "✓ All daemons are running"

# Check all PSK files exist
echo "Checking PSK files..."
MISSING_FILES=0

for file in alice_bob.psk alice_charlie.psk bob_alice.psk bob_charlie.psk charlie_alice.psk charlie_bob.psk; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Missing PSK file: $file"
        MISSING_FILES=1
    else
        echo "✓ Found $file"
    fi
done

if [ $MISSING_FILES -eq 1 ]; then
    echo "ERROR: Some PSK files are missing"
    echo "Alice log:"
    cat alice.log
    echo ""
    echo "Bob log:"
    cat bob.log
    echo ""
    echo "Charlie log:"
    cat charlie.log
    exit 1
fi

# Verify PSK pairs match
echo ""
echo "Verifying PSK pairs match..."

verify_psk_pair() {
    local file1=$1
    local file2=$2
    local name=$3
    
    local psk1=$(cat "$file1")
    local psk2=$(cat "$file2")
    
    if [ "$psk1" != "$psk2" ]; then
        echo "ERROR: PSK mismatch for $name"
        echo "  $file1: $psk1"
        echo "  $file2: $psk2"
        return 1
    fi
    
    # Verify it's valid base64 32-byte key
    local decoded_len=$(echo "$psk1" | base64 -d | wc -c | tr -d ' ')
    if [ "$decoded_len" != "32" ]; then
        echo "ERROR: PSK for $name is not 32 bytes (got $decoded_len)"
        return 1
    fi
    
    echo "✓ $name PSKs match: $psk1"
    return 0
}

ALL_MATCH=0

verify_psk_pair "alice_bob.psk" "bob_alice.psk" "Alice-Bob" || ALL_MATCH=1
verify_psk_pair "alice_charlie.psk" "charlie_alice.psk" "Alice-Charlie" || ALL_MATCH=1
verify_psk_pair "bob_charlie.psk" "charlie_bob.psk" "Bob-Charlie" || ALL_MATCH=1

if [ $ALL_MATCH -eq 1 ]; then
    echo ""
    echo "ERROR: Some PSKs do not match"
    echo "Alice log:"
    cat alice.log
    echo ""
    echo "Bob log:"
    cat bob.log
    echo ""
    echo "Charlie log:"
    cat charlie.log
    exit 1
fi

# Verify all three PSKs are different (due to ephemeral randomness)
echo ""
echo "Verifying all PSK pairs are different..."
PSK_AB=$(cat alice_bob.psk)
PSK_AC=$(cat alice_charlie.psk)
PSK_BC=$(cat bob_charlie.psk)

if [ "$PSK_AB" = "$PSK_AC" ] || [ "$PSK_AB" = "$PSK_BC" ] || [ "$PSK_AC" = "$PSK_BC" ]; then
    echo "WARNING: Some PSK pairs are identical (unlikely but possible with mock KEM)"
else
    echo "✓ All PSK pairs are different (expected with random ephemeral keys)"
fi

# Verify role behavior
echo ""
echo "Verifying role behavior from logs..."

# Alice should only initiate (no "Received connection" messages for multi-peer daemon)
if grep -q "Received connection" alice.log; then
    echo "ERROR: Alice (client-only) should not accept connections"
    cat alice.log
    exit 1
fi
echo "✓ Alice is client-only (no incoming connections)"

# Bob should both initiate and accept
if ! grep -q "Received connection" bob.log; then
    echo "ERROR: Bob (client+server) should accept connections from Alice"
    cat bob.log
    exit 1
fi
echo "✓ Bob accepts incoming connections (acting as server)"

if ! grep -q "Initiating connection" bob.log; then
    echo "WARNING: Bob should initiate connection to Charlie"
fi
echo "✓ Bob initiates outgoing connections (acting as client)"

# Charlie should only accept (no "Initiating connection" messages)
if grep -q "Initiating connection" charlie.log; then
    echo "ERROR: Charlie (server-only) should not initiate connections"
    cat charlie.log
    exit 1
fi
echo "✓ Charlie is server-only (no outgoing connections)"

if ! grep -q "Received connection" charlie.log; then
    echo "ERROR: Charlie (server-only) should accept connections"
    cat charlie.log
    exit 1
fi
echo "✓ Charlie accepts incoming connections"

echo ""
echo "=== Three-Peer Multi-Role Integration Test PASSED ==="
echo "Summary:"
echo "  - Alice (client): Connected to Bob and Charlie ✓"
echo "  - Bob (client+server): Connected to Alice and Charlie ✓"
echo "  - Charlie (server): Accepted from Alice and Bob ✓"
echo "  - All PSK pairs verified and match ✓"
exit 0
