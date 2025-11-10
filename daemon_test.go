package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"quantshake/pkg/kem"
)

// getFreePort asks the kernel for a free open port that is ready to use
func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }() // Best effort close
	return l.Addr().(*net.TCPAddr).Port, nil
}

// testSimultaneousStartWithPorts is the core test function that accepts custom ports
func testSimultaneousStartWithPorts(t *testing.T, alicePort, bobPort string) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()

	// Generate test keys
	k := kem.Get("mlkem768")
	if k == nil {
		t.Fatal("Failed to get mlkem768 implementation")
	}

	// Generate Alice's keys
	alicePub, aliceSec, err := k.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Alice's keys: %v", err)
	}
	aliceKeyFile := tmpDir + "/alice.sec"
	if err := SaveSecretKey(aliceKeyFile, k.Name(), aliceSec); err != nil {
		t.Fatalf("Failed to save Alice's secret key: %v", err)
	}
	if err := SavePublicKey(tmpDir+"/alice.pub", k.Name(), alicePub); err != nil {
		t.Fatalf("Failed to save Alice's public key: %v", err)
	}

	// Generate Bob's keys
	bobPub, bobSec, err := k.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Bob's keys: %v", err)
	}
	bobKeyFile := tmpDir + "/bob.sec"
	if err := SaveSecretKey(bobKeyFile, k.Name(), bobSec); err != nil {
		t.Fatalf("Failed to save Bob's secret key: %v", err)
	}
	if err := SavePublicKey(tmpDir+"/bob.pub", k.Name(), bobPub); err != nil {
		t.Fatalf("Failed to save Bob's public key: %v", err)
	}

	// Create daemon configs
	aliceConfig := DaemonConfig{
		ListenAddr:  "127.0.0.1:" + alicePort,
		ConnectAddr: "127.0.0.1:" + bobPort,
		PeerKeyFile: tmpDir + "/bob.pub",
		KeyFile:     aliceKeyFile,
		Interval:    5,
		PeerName:    tmpDir + "/alice.psk",
	}

	bobConfig := DaemonConfig{
		ListenAddr:  "127.0.0.1:" + bobPort,
		ConnectAddr: "127.0.0.1:" + alicePort,
		PeerKeyFile: tmpDir + "/alice.pub",
		KeyFile:     bobKeyFile,
		Interval:    5,
		PeerName:    tmpDir + "/bob.psk",
	}

	// Create daemons
	alice, err := NewDaemon(aliceConfig)
	if err != nil {
		t.Fatalf("Failed to create Alice daemon: %v", err)
	}

	bob, err := NewDaemon(bobConfig)
	if err != nil {
		t.Fatalf("Failed to create Bob daemon: %v", err)
	}

	// Start listeners
	alice.listener, err = net.Listen("tcp", aliceConfig.ListenAddr)
	if err != nil {
		t.Fatalf("Failed to start Alice listener: %v", err)
	}
	defer func() { _ = alice.listener.Close() }() // Best effort close

	bob.listener, err = net.Listen("tcp", bobConfig.ListenAddr)
	if err != nil {
		t.Fatalf("Failed to start Bob listener: %v", err)
	}
	defer func() { _ = bob.listener.Close() }() // Best effort close

	// Start accept loops in separate goroutines
	go func() {
		for {
			conn, err := alice.listener.Accept()
			if err != nil {
				return // Listener closed
			}
			go alice.handleResponderRole(conn)
		}
	}()
	go func() {
		for {
			conn, err := bob.listener.Accept()
			if err != nil {
				return // Listener closed
			}
			go bob.handleResponderRole(conn)
		}
	}()

	// Use WaitGroup to start both connection attempts simultaneously
	var wg sync.WaitGroup
	wg.Add(2)

	// Channels to signal completion
	aliceDone := make(chan bool, 1)
	bobDone := make(chan bool, 1)

	// Start Alice's connection attempt
	go func() {
		defer wg.Done()
		// Call initiateConnection which will retry until success
		// We'll monitor the shared key to know when it's done
		for {
			alice.keysMu.RLock()
			hasKey := len(alice.sharedKey) > 0
			alice.keysMu.RUnlock()

			if hasKey {
				select {
				case aliceDone <- true:
				default:
				}
				return
			}

			alice.exchangeMu.Lock()
			if !alice.inExchange {
				alice.exchangeMu.Unlock()
				alice.initiateConnection()
			} else {
				alice.exchangeMu.Unlock()
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Start Bob's connection attempt simultaneously
	go func() {
		defer wg.Done()
		for {
			bob.keysMu.RLock()
			hasKey := len(bob.sharedKey) > 0
			bob.keysMu.RUnlock()

			if hasKey {
				select {
				case bobDone <- true:
				default:
				}
				return
			}

			bob.exchangeMu.Lock()
			if !bob.inExchange {
				bob.exchangeMu.Unlock()
				bob.initiateConnection()
			} else {
				bob.exchangeMu.Unlock()
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Wait for both to have keys with timeout
	timeout := time.After(10 * time.Second)
	aliceReady := false
	bobReady := false

	for !aliceReady || !bobReady {
		select {
		case <-aliceDone:
			aliceReady = true
		case <-bobDone:
			bobReady = true
		case <-timeout:
			t.Fatal("Test timeout: daemons did not complete handshake within 10 seconds")
		}
	}

	// Give a small grace period for any in-flight exchanges to complete
	time.Sleep(200 * time.Millisecond)

	// Wait for goroutines to finish
	wg.Wait()

	// Verify both have shared keys
	alice.keysMu.RLock()
	aliceHasKey := len(alice.sharedKey) > 0
	aliceKey := make([]byte, len(alice.sharedKey))
	copy(aliceKey, alice.sharedKey)
	alice.keysMu.RUnlock()

	bob.keysMu.RLock()
	bobHasKey := len(bob.sharedKey) > 0
	bobKey := make([]byte, len(bob.sharedKey))
	copy(bobKey, bob.sharedKey)
	bob.keysMu.RUnlock()

	if !aliceHasKey {
		t.Error("Alice did not generate a shared key")
	}
	if !bobHasKey {
		t.Error("Bob did not generate a shared key")
	}

	// Verify keys match
	if !bytes.Equal(aliceKey, bobKey) {
		t.Error("Shared keys do not match between Alice and Bob")
	}

	// Verify PSK files were created and match
	alicePSK, err := LoadSharedKeyPSK(aliceConfig.PeerName)
	if err != nil {
		t.Errorf("Failed to load Alice's PSK: %v", err)
	}

	bobPSK, err := LoadSharedKeyPSK(bobConfig.PeerName)
	if err != nil {
		t.Errorf("Failed to load Bob's PSK: %v", err)
	}

	if !bytes.Equal(alicePSK, bobPSK) {
		t.Error("PSK files do not match between Alice and Bob")
	}

	if !bytes.Equal(alicePSK, aliceKey) {
		t.Error("Alice's PSK file does not match her in-memory key")
	}

	t.Logf("Successfully completed simultaneous start test")
	t.Logf("Alice's turn next: %v", alice.myTurn)
	t.Logf("Bob's turn next: %v", bob.myTurn)

	// Verify that exactly one has myTurn set (they should alternate)
	alice.exchangeMu.Lock()
	aliceTurn := alice.myTurn
	alice.exchangeMu.Unlock()

	bob.exchangeMu.Lock()
	bobTurn := bob.myTurn
	bob.exchangeMu.Unlock()

	if aliceTurn == bobTurn {
		t.Error("Both daemons have the same myTurn value - they should alternate")
	}
}

// TestSimultaneousStart tests that two daemons can start simultaneously without race conditions
func TestSimultaneousStart(t *testing.T) {
	// Get two free ports
	alicePort, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port for Alice: %v", err)
	}
	bobPort, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port for Bob: %v", err)
	}

	testSimultaneousStartWithPorts(t, fmt.Sprintf("%d", alicePort), fmt.Sprintf("%d", bobPort))
}

// TestMultipleSimultaneousStarts runs the simultaneous start test 5 times sequentially
// to catch race conditions that might not appear every time
func TestMultipleSimultaneousStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multiple simultaneous starts test in short mode")
	}

	for i := 1; i <= 5; i++ {
		t.Run(fmt.Sprintf("Attempt%d", i), func(t *testing.T) {
			// Get two free ports for this iteration
			alicePort, err := getFreePort()
			if err != nil {
				t.Fatalf("Failed to get free port for Alice: %v", err)
			}
			bobPort, err := getFreePort()
			if err != nil {
				t.Fatalf("Failed to get free port for Bob: %v", err)
			}

			testSimultaneousStartWithPorts(t, fmt.Sprintf("%d", alicePort), fmt.Sprintf("%d", bobPort))
		})
	}
}

// TestComparePubKeys tests the public key comparison function
func TestComparePubKeys(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected int
	}{
		{
			name:     "Equal keys",
			a:        []byte{1, 2, 3, 4},
			b:        []byte{1, 2, 3, 4},
			expected: 0,
		},
		{
			name:     "First key less than second",
			a:        []byte{1, 2, 3, 4},
			b:        []byte{1, 2, 3, 5},
			expected: -1,
		},
		{
			name:     "First key greater than second",
			a:        []byte{1, 2, 3, 5},
			b:        []byte{1, 2, 3, 4},
			expected: 1,
		},
		{
			name:     "Different length - shorter is less",
			a:        []byte{1, 2, 3},
			b:        []byte{1, 2, 3, 4},
			expected: -1,
		},
		{
			name:     "Different length - longer is greater",
			a:        []byte{1, 2, 3, 4},
			b:        []byte{1, 2, 3},
			expected: 1,
		},
		{
			name:     "Empty keys",
			a:        []byte{},
			b:        []byte{},
			expected: 0,
		},
		{
			name:     "First key empty",
			a:        []byte{},
			b:        []byte{1, 2, 3},
			expected: -1,
		},
		{
			name:     "Second key empty",
			a:        []byte{1, 2, 3},
			b:        []byte{},
			expected: 1,
		},
		{
			name:     "Difference at first byte",
			a:        []byte{0, 2, 3},
			b:        []byte{1, 2, 3},
			expected: -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := comparePubKeys(tc.a, tc.b)
			if result != tc.expected {
				t.Errorf("comparePubKeys(%v, %v) = %d, expected %d", tc.a, tc.b, result, tc.expected)
			}
		})
	}
}

// TestSetRandomKey tests the random key fallback functionality
func TestSetRandomKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal daemon config
	k := kem.Get("mlkem768")
	if k == nil {
		t.Fatal("Failed to get mlkem768 implementation")
	}

	alicePub, aliceSec, err := k.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	keyFile := tmpDir + "/alice.sec"
	if err := SaveSecretKey(keyFile, k.Name(), aliceSec); err != nil {
		t.Fatalf("Failed to save secret key: %v", err)
	}
	if err := SavePublicKey(tmpDir+"/alice.pub", k.Name(), alicePub); err != nil {
		t.Fatalf("Failed to save public key: %v", err)
	}

	config := DaemonConfig{
		ListenAddr:  "127.0.0.1:0",
		ConnectAddr: "127.0.0.1:0",
		PeerKeyFile: tmpDir + "/alice.pub",
		KeyFile:     keyFile,
		Interval:    5,
		PeerName:    tmpDir + "/test.psk",
	}

	daemon, err := NewDaemon(config)
	if err != nil {
		t.Fatalf("Failed to create daemon: %v", err)
	}

	// Call setRandomKey
	daemon.setRandomKey()

	// Verify a random key was set
	daemon.keysMu.RLock()
	hasKey := len(daemon.sharedKey) > 0
	keyLen := len(daemon.sharedKey)
	daemon.keysMu.RUnlock()

	if !hasKey {
		t.Error("setRandomKey did not set a shared key")
	}

	if keyLen != 32 {
		t.Errorf("Expected random key length of 32 bytes, got %d", keyLen)
	}

	// Verify PSK file was created
	pskData, err := LoadSharedKeyPSK(config.PeerName)
	if err != nil {
		t.Errorf("Failed to load PSK file: %v", err)
	}

	if len(pskData) != 32 {
		t.Errorf("Expected PSK file to contain 32 bytes, got %d", len(pskData))
	}
}

// TestUpdateKey tests the updateKey function
func TestUpdateKey(t *testing.T) {
	tmpDir := t.TempDir()

	k := kem.Get("mlkem768")
	if k == nil {
		t.Fatal("Failed to get mlkem768 implementation")
	}

	alicePub, aliceSec, err := k.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	keyFile := tmpDir + "/alice.sec"
	if err := SaveSecretKey(keyFile, k.Name(), aliceSec); err != nil {
		t.Fatalf("Failed to save secret key: %v", err)
	}
	if err := SavePublicKey(tmpDir+"/alice.pub", k.Name(), alicePub); err != nil {
		t.Fatalf("Failed to save public key: %v", err)
	}

	config := DaemonConfig{
		ListenAddr:  "127.0.0.1:0",
		ConnectAddr: "127.0.0.1:0",
		PeerKeyFile: tmpDir + "/alice.pub",
		KeyFile:     keyFile,
		Interval:    5,
		PeerName:    tmpDir + "/test.psk",
	}

	daemon, err := NewDaemon(config)
	if err != nil {
		t.Fatalf("Failed to create daemon: %v", err)
	}

	// Test updateKey with normal key
	testKey := []byte("this is a test shared key 123")
	daemon.updateKey(testKey, false)

	daemon.keysMu.RLock()
	storedKey := make([]byte, len(daemon.sharedKey))
	copy(storedKey, daemon.sharedKey)
	daemon.keysMu.RUnlock()

	if !bytes.Equal(storedKey, testKey) {
		t.Error("updateKey did not store the key correctly")
	}

	// Verify PSK file was created
	pskData, err := LoadSharedKeyPSK(config.PeerName)
	if err != nil {
		t.Errorf("Failed to load PSK file: %v", err)
	}

	if !bytes.Equal(pskData, testKey) {
		t.Error("PSK file does not match the key")
	}

	// Test updateKey with random flag
	randomKey := []byte("random fallback key 1234567890")
	daemon.updateKey(randomKey, true)

	daemon.keysMu.RLock()
	storedKey2 := make([]byte, len(daemon.sharedKey))
	copy(storedKey2, daemon.sharedKey)
	daemon.keysMu.RUnlock()

	if !bytes.Equal(storedKey2, randomKey) {
		t.Error("updateKey with random flag did not store the key correctly")
	}
}

// TestSendMessageSizeLimit tests that sendMessage works for normal messages
func TestSendMessageSizeLimit(t *testing.T) {
	// Create a mock connection using a pipe
	reader, writer := net.Pipe()
	defer func() { _ = reader.Close() }() // Best effort close
	defer func() { _ = writer.Close() }() // Best effort close

	// Create a message that's within limits (small)
	smallMsg := make([]byte, 1000)

	// Send in goroutine and receive in main thread
	done := make(chan error, 1)
	go func() {
		done <- sendMessage(writer, smallMsg)
	}()

	// Read the message
	receivedMsg, err := receiveMessage(reader)
	if err != nil {
		t.Errorf("receiveMessage failed: %v", err)
	}

	if !bytes.Equal(receivedMsg, smallMsg) {
		t.Error("Received message does not match sent message")
	}

	// Check send result
	if sendErr := <-done; sendErr != nil {
		t.Errorf("sendMessage failed: %v", sendErr)
	}
}

// TestReceiveMessageSizeLimit tests that receiveMessage rejects oversized messages
func TestReceiveMessageSizeLimit(t *testing.T) {
	// Create a mock connection using a pipe
	reader, writer := net.Pipe()
	defer func() { _ = reader.Close() }() // Best effort close
	defer func() { _ = writer.Close() }() // Best effort close

	// Send a message that claims to be too large (over 10MB limit)
	go func() {
		// Send length prefix indicating 11MB
		largeSizeBytes := []byte{0x00, 0xA8, 0xC0, 0x00} // 11,059,200 bytes
		_, _ = writer.Write(largeSizeBytes)              // Best effort write
	}()

	// Try to receive - should fail with size error
	_, err := receiveMessage(reader)
	if err == nil {
		t.Error("Expected error for oversized message, got nil")
	}
	if err != nil && err.Error() != "message too large: 11059200 bytes" {
		t.Logf("Got expected error type: %v", err)
	}
}

// TestDeserializeNetworkMsgError tests error handling in message deserialization
func TestDeserializeNetworkMsgError(t *testing.T) {
	// Test with invalid JSON
	_, err := DeserializeNetworkMsg([]byte("not valid json"))
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}

	// Test with empty data
	_, err = DeserializeNetworkMsg([]byte{})
	if err == nil {
		t.Error("Expected error for empty data, got nil")
	}
}

// TestLoadSharedKeyPSKError tests error handling in LoadSharedKeyPSK
func TestLoadSharedKeyPSKError(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("FileNotExist", func(t *testing.T) {
		_, err := LoadSharedKeyPSK(tmpDir + "/nonexistent.psk")
		if err == nil {
			t.Error("Expected error for non-existent file, got nil")
		}
	})

	t.Run("InvalidBase64", func(t *testing.T) {
		invalidFile := tmpDir + "/invalid.psk"
		_ = os.WriteFile(invalidFile, []byte("not-valid-base64!!!"), 0600)
		_, err := LoadSharedKeyPSK(invalidFile)
		if err == nil {
			t.Error("Expected error for invalid base64, got nil")
		}
	})
}

// TestNewDaemonErrors tests error handling in NewDaemon
func TestNewDaemonErrors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("MissingSecretKey", func(t *testing.T) {
		config := DaemonConfig{
			ListenAddr:  "127.0.0.1:0",
			ConnectAddr: "127.0.0.1:0",
			PeerKeyFile: tmpDir + "/peer.pub",
			KeyFile:     tmpDir + "/nonexistent.sec",
			Interval:    5,
			PeerName:    tmpDir + "/test.psk",
		}

		_, err := NewDaemon(config)
		if err == nil {
			t.Error("Expected error for missing secret key, got nil")
		}
	})

	t.Run("MissingPublicKey", func(t *testing.T) {
		// Create a valid secret key first
		k := kem.Get("mlkem768")
		_, sec, _ := k.GenerateKey(rand.Reader)
		secFile := tmpDir + "/valid.sec"
		_ = SaveSecretKey(secFile, k.Name(), sec)
		pubFile := tmpDir + "/valid.pub"
		pub, _, _ := k.GenerateKey(rand.Reader)
		_ = SavePublicKey(pubFile, k.Name(), pub)

		config := DaemonConfig{
			ListenAddr:  "127.0.0.1:0",
			ConnectAddr: "127.0.0.1:0",
			PeerKeyFile: tmpDir + "/nonexistent_peer.pub",
			KeyFile:     secFile,
			Interval:    5,
			PeerName:    tmpDir + "/test.psk",
		}

		_, err := NewDaemon(config)
		if err == nil {
			t.Error("Expected error for missing peer public key, got nil")
		}
	})
}
