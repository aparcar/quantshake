package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"fmt"
	"io"
	"log"
	mathRand "math/rand"
	"net"
	"os"
	"sync"
	"time"

	"quantshake/pkg/handshake"
	"quantshake/pkg/kem"
)

// ------------------------ Message Serialization ------------------------

// NetworkMsg wraps all message types for network transmission
type NetworkMsg struct {
	Type    string          `json:"type"` // "msg1", "msg2", "msg3"
	Payload json.RawMessage `json:"payload"`
}

// SerializeMsg1 serializes Message 1 for network transmission
func SerializeMsg1(m *handshake.Msg1) ([]byte, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	msg := NetworkMsg{Type: "msg1", Payload: payload}
	return json.Marshal(msg)
}

// SerializeMsg2 serializes Message 2 for network transmission
func SerializeMsg2(m *handshake.Msg2) ([]byte, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	msg := NetworkMsg{Type: "msg2", Payload: payload}
	return json.Marshal(msg)
}

// SerializeMsg3 serializes Message 3 for network transmission
func SerializeMsg3(m *handshake.Msg3) ([]byte, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	msg := NetworkMsg{Type: "msg3", Payload: payload}
	return json.Marshal(msg)
}

// DeserializeNetworkMsg deserializes a network message
func DeserializeNetworkMsg(data []byte) (*NetworkMsg, error) {
	var msg NetworkMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// ------------------------ Shared Key Storage ------------------------

// SaveSharedKeyPSK saves the shared key as base64 to a .psk file
func SaveSharedKeyPSK(filename string, sharedKey []byte) error {
	encoded := base64.StdEncoding.EncodeToString(sharedKey)
	if err := os.WriteFile(filename, []byte(encoded), 0600); err != nil {
		return fmt.Errorf("failed to write PSK file: %w", err)
	}
	return nil
}

// LoadSharedKeyPSK loads a shared key from a .psk file
func LoadSharedKeyPSK(filename string) ([]byte, error) {
	// #nosec G304 - filename comes from config, validated by caller
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read PSK file: %w", err)
	}

	key, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode PSK: %w", err)
	}

	return key, nil
}

// ------------------------ Daemon State ------------------------

// DaemonConfig holds daemon configuration
type DaemonConfig struct {
	ListenAddr  string
	ConnectAddr string
	PeerKeyFile string
	KeyFile     string
	Interval    int    // seconds between exchanges
	PeerName    string // output PSK file path
}

// Daemon represents the running daemon
type Daemon struct {
	config        DaemonConfig
	myPublicKey   []byte
	mySecretKey   []byte
	peerPublicKey []byte
	algorithm     string
	kem           kem.KEM // KEM algorithm instance

	lastExchange time.Time
	myTurn       bool // true if it's our turn to initiate next
	exchangeMu   sync.Mutex

	listener net.Listener

	// Current shared key
	sharedKey []byte
	keysMu    sync.RWMutex

	// Connection state
	inExchange bool      // true if currently in an exchange
	resetTimer chan bool // signal to reset the connection timer
}

// NewDaemon creates a new daemon instance
func NewDaemon(config DaemonConfig) (*Daemon, error) {
	d := &Daemon{
		config:       config,
		lastExchange: time.Now(),
		resetTimer:   make(chan bool, 10),
		myTurn:       true, // Initially both try, one will win
	}

	// Load our keys
	algo, sk, err := LoadSecretKey(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load secret key: %w", err)
	}
	d.algorithm = algo
	d.mySecretKey = sk

	// Extract public key from key file
	pubKeyFile := config.KeyFile[:len(config.KeyFile)-4] + ".pub"
	_, pk, err := LoadPublicKey(pubKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}
	d.myPublicKey = pk

	// Load peer's public key
	_, peerPK, err := LoadPublicKey(config.PeerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load peer public key: %w", err)
	}
	d.peerPublicKey = peerPK

	// Initialize KEM based on algorithm
	d.kem = kem.Get(algo)
	if d.kem == nil {
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", algo)
	}

	return d, nil
}

// Start starts the daemon
func (d *Daemon) Start() error {
	log.Printf("Starting daemon...")
	log.Printf("  Listen: %s", d.config.ListenAddr)
	log.Printf("  Connect: %s", d.config.ConnectAddr)
	log.Printf("  Interval: %ds", d.config.Interval)
	log.Printf("  Algorithm: %s", d.algorithm)

	// Start listener
	var err error
	d.listener, err = net.Listen("tcp", d.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	log.Printf("Listening on %s", d.config.ListenAddr)

	// Start accepting connections
	go d.acceptLoop()

	// Start periodic connection attempts
	go d.connectLoop()

	// Start watchdog for timeout
	go d.watchdogLoop()

	// Block forever
	select {}
}

// acceptLoop accepts incoming connections
func (d *Daemon) acceptLoop() {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		log.Printf("Accepted connection from %s", conn.RemoteAddr())
		go d.handleResponderRole(conn)
	}
}

// connectLoop periodically connects to peer with role-based timing
func (d *Daemon) connectLoop() {
	// Initial random delay to avoid race conditions
	// #nosec G404 - Non-cryptographic randomness acceptable for timing jitter
	time.Sleep(time.Duration(mathRand.Int63n(2000)) * time.Millisecond)
	d.initiateConnection()

	// Dynamic interval based on whose turn it is
	for {
		d.exchangeMu.Lock()
		isMyTurn := d.myTurn
		d.exchangeMu.Unlock()

		if !isMyTurn {
			// Not our turn, wait for peer to initiate
			log.Printf("Waiting for peer to initiate next exchange...")
			<-d.resetTimer
			log.Printf("Peer initiated exchange, checking if our turn next")
			// Loop will check myTurn again
		} else {
			// Our turn to initiate
			waitTime := time.Duration(d.config.Interval) * time.Second

			// Drain any pending reset signals first
			drained := 0
			for {
				select {
				case <-d.resetTimer:
					drained++
				default:
					goto drained
				}
			}
		drained:
			if drained > 0 {
				log.Printf("Drained %d stale reset signals", drained)
			}

			log.Printf("Scheduling next attempt in %d seconds (our turn)", d.config.Interval)

			// Wait with ability to reset timer
			timer := time.NewTimer(waitTime)
			select {
			case <-timer.C:
				// Timer expired normally, try to connect
				d.initiateConnection()
			case <-d.resetTimer:
				// Timer reset - peer initiated before we did
				timer.Stop()
				log.Printf("Peer initiated before our timer, canceling our attempt")
				// Loop will check myTurn and wait appropriately
			}
		}
	}
}

// watchdogLoop monitors for extended connection failures and sets fallback key
func (d *Daemon) watchdogLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		d.exchangeMu.Lock()
		elapsed := time.Since(d.lastExchange)
		interval := time.Duration(d.config.Interval) * time.Second

		// Set random key if no exchange for interval + 30 seconds
		finalTimeout := interval + 30*time.Second

		// Check if final timeout has been reached
		if elapsed > finalTimeout {
			log.Printf("WARNING: No key exchange for %.0fs (final timeout: %.0fs), setting random fallback key", elapsed.Seconds(), finalTimeout.Seconds())
			d.setRandomKey()
			d.lastExchange = time.Now()
			d.exchangeMu.Unlock()
			continue
		}

		d.exchangeMu.Unlock()
	}
}

// comparePubKeys compares two public keys lexicographically
// Returns -1 if a < b, 0 if a == b, 1 if a > b
func comparePubKeys(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// initiateConnection connects to peer as initiator with simple retry
func (d *Daemon) initiateConnection() {
	// Check if already in exchange
	d.exchangeMu.Lock()
	if d.inExchange {
		log.Printf("Skipping connection attempt - peer already initiated")
		d.exchangeMu.Unlock()
		return
	}
	d.inExchange = true
	d.exchangeMu.Unlock()

	defer func() {
		d.exchangeMu.Lock()
		d.inExchange = false
		d.exchangeMu.Unlock()
	}()

	attemptNum := 0
	for {
		// Simple backoff: 1 second with up to 100ms jitter
		if attemptNum > 0 {
			// #nosec G404 - Non-cryptographic randomness acceptable for timing jitter
			jitter := time.Duration(mathRand.Int63n(100)) * time.Millisecond
			waitTime := time.Second + jitter

			log.Printf("Retry attempt %d after %.3fs...", attemptNum, waitTime.Seconds())
			time.Sleep(waitTime)
		}

		attemptNum++
		log.Printf("Initiating connection to %s (attempt %d)...", d.config.ConnectAddr, attemptNum)

		conn, err := net.DialTimeout("tcp", d.config.ConnectAddr, 10*time.Second)
		if err != nil {
			log.Printf("Failed to connect to peer: %v", err)
			// Continue to next retry
			continue
		}

		log.Printf("Connected to %s", conn.RemoteAddr())
		err = d.performInitiatorHandshake(conn)
		_ = conn.Close() // Best effort close

		if err != nil {
			log.Printf("Initiator handshake failed: %v", err)
			// Continue to next retry
			continue
		}

		// Success! Update state
		d.exchangeMu.Lock()
		d.lastExchange = time.Now()
		// After completing as initiator, it's the peer's turn (responder goes next)
		d.myTurn = false
		d.exchangeMu.Unlock()

		// NOTE: Do NOT send reset signal from initiator role
		// Only the responder sends reset signals to prevent duplicate scheduling

		log.Printf("Key exchange complete as initiator (peer's turn next)")
		return
	}
}

// performInitiatorHandshake performs the 3-message handshake as initiator
func (d *Daemon) performInitiatorHandshake(conn net.Conn) error {
	// Set timeouts
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second)) // Best effort

	// Create initiator with prologue
	prologue := []byte("pqc-key-exchange-v2")
	init, err := handshake.NewInitiator(handshake.KeyPair{Sk: d.mySecretKey, Pk: d.myPublicKey}, d.peerPublicKey, d.kem, prologue)
	if err != nil {
		return fmt.Errorf("failed to create initiator: %w", err)
	}

	// Build and send Message 1
	m1, err := init.BuildMsg1()
	if err != nil {
		return fmt.Errorf("failed to build msg1: %w", err)
	}

	msg1Data, err := SerializeMsg1(m1)
	if err != nil {
		return fmt.Errorf("failed to serialize msg1: %w", err)
	}

	if err := sendMessage(conn, msg1Data); err != nil {
		return fmt.Errorf("failed to send msg1: %w", err)
	}

	// Receive Message 2
	msg2Data, err := receiveMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive msg2: %w", err)
	}

	netMsg, err := DeserializeNetworkMsg(msg2Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize msg2: %w", err)
	}

	if netMsg.Type != "msg2" {
		return fmt.Errorf("expected msg2, got %s", netMsg.Type)
	}

	var m2 handshake.Msg2
	if err := json.Unmarshal(netMsg.Payload, &m2); err != nil {
		return fmt.Errorf("failed to unmarshal msg2: %w", err)
	}

	// Process Message 2
	err = init.ProcessMsg2(&m2)
	if err != nil {
		return fmt.Errorf("failed to process msg2: %w", err)
	}

	// Build and send Message 3
	m3, err := init.BuildMsg3()
	if err != nil {
		return fmt.Errorf("failed to build msg3: %w", err)
	}

	msg3Data, err := SerializeMsg3(m3)
	if err != nil {
		return fmt.Errorf("failed to serialize msg3: %w", err)
	}

	if err := sendMessage(conn, msg3Data); err != nil {
		return fmt.Errorf("failed to send msg3: %w", err)
	}

	// Get and store key
	sharedKey := init.GetSharedKey()
	d.updateKey(sharedKey, false)

	return nil
}

// handleResponderRole handles incoming connection as responder
func (d *Daemon) handleResponderRole(conn net.Conn) {
	defer func() { _ = conn.Close() }() // Best effort close

	// Try to acquire exchange lock
	d.exchangeMu.Lock()
	if d.inExchange {
		// Race condition: both are trying to initiate
		// Tiebreaker: compare public keys lexicographically
		// Lower key wins and continues as initiator, higher key backs off and becomes responder
		shouldBackoff := comparePubKeys(d.myPublicKey, d.peerPublicKey) > 0

		if !shouldBackoff {
			// We have lower key, continue as initiator - reject this incoming connection
			d.exchangeMu.Unlock()
			log.Printf("Simultaneous connection attempt - continuing as initiator (lower pubkey)")
			return
		}

		// We have higher key, back off - accept this connection as responder
		log.Printf("Simultaneous connection attempt - backing off to become responder (higher pubkey)")
		// inExchange stays true, we'll handle this connection
	} else {
		d.inExchange = true
	}
	d.exchangeMu.Unlock()

	defer func() {
		d.exchangeMu.Lock()
		d.inExchange = false
		d.exchangeMu.Unlock()
	}()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second)) // Best effort deadline

	if err := d.performResponderHandshake(conn); err != nil {
		log.Printf("Responder handshake failed: %v", err)
		return
	}

	d.exchangeMu.Lock()
	d.lastExchange = time.Now()
	// After completing as responder, it's our turn to initiate next
	d.myTurn = true
	d.exchangeMu.Unlock()

	// Signal timer reset (non-blocking)
	select {
	case d.resetTimer <- true:
	default:
	}

	log.Printf("✓ Key exchange complete as responder (our turn in %ds)", d.config.Interval)
}

// performResponderHandshake performs the 3-message handshake as responder
func (d *Daemon) performResponderHandshake(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second)) // Best effort deadline

	// Create responder with prologue
	prologue := []byte("pqc-key-exchange-v2")
	resp, err := handshake.NewResponder(handshake.KeyPair{Sk: d.mySecretKey, Pk: d.myPublicKey}, d.peerPublicKey, d.kem, prologue)
	if err != nil {
		return fmt.Errorf("failed to create responder: %w", err)
	}

	// Receive Message 1
	msg1Data, err := receiveMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive msg1: %w", err)
	}

	netMsg, err := DeserializeNetworkMsg(msg1Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize msg1: %w", err)
	}

	if netMsg.Type != "msg1" {
		return fmt.Errorf("expected msg1, got %s", netMsg.Type)
	}

	var m1 handshake.Msg1
	if err := json.Unmarshal(netMsg.Payload, &m1); err != nil {
		return fmt.Errorf("failed to unmarshal msg1: %w", err)
	}

	// Process Message 1
	err = resp.ProcessMsg1(&m1)
	if err != nil {
		return fmt.Errorf("failed to process msg1: %w", err)
	}

	// Build and send Message 2
	m2, err := resp.BuildMsg2()
	if err != nil {
		return fmt.Errorf("failed to build msg2: %w", err)
	}

	msg2Data, err := SerializeMsg2(m2)
	if err != nil {
		return fmt.Errorf("failed to serialize msg2: %w", err)
	}

	if err := sendMessage(conn, msg2Data); err != nil {
		return fmt.Errorf("failed to send msg2: %w", err)
	}

	// Receive Message 3
	msg3Data, err := receiveMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive msg3: %w", err)
	}

	netMsg, err = DeserializeNetworkMsg(msg3Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize msg3: %w", err)
	}

	if netMsg.Type != "msg3" {
		return fmt.Errorf("expected msg3, got %s", netMsg.Type)
	}

	var m3 handshake.Msg3
	if err := json.Unmarshal(netMsg.Payload, &m3); err != nil {
		return fmt.Errorf("failed to unmarshal msg3: %w", err)
	}

	// Process Message 3
	if err := resp.ProcessMsg3(&m3); err != nil {
		return fmt.Errorf("failed to verify msg3: %w", err)
	}

	// Get and store key
	sharedKey := resp.GetSharedKey()
	d.updateKey(sharedKey, false)

	return nil
}

// updateKey updates the daemon's shared key and saves to disk
func (d *Daemon) updateKey(sharedKey []byte, isRandom bool) {
	d.keysMu.Lock()
	d.sharedKey = sharedKey
	d.keysMu.Unlock()

	// Save to disk at specified output path
	pskFile := d.config.PeerName
	if err := SaveSharedKeyPSK(pskFile, sharedKey); err != nil {
		log.Printf("Failed to save PSK: %v", err)
	} else {
		if isRandom {
			log.Printf("Saved random fallback PSK to %s", pskFile)
		} else {
			log.Printf("Saved shared PSK to %s", pskFile)
		}
	}
}

// setRandomKey sets a random fallback key
func (d *Daemon) setRandomKey() {
	randomKey := make([]byte, 32)
	if _, err := rand.Read(randomKey); err != nil {
		panic(err)
	}
	d.updateKey(randomKey, true)
}

// sendMessage sends a length-prefixed message
func sendMessage(conn net.Conn, data []byte) error {
	// Send length (4 bytes big-endian)
	dataLen := len(data)
	if dataLen > 10*1024*1024 { // 10MB max
		return fmt.Errorf("message too large: %d bytes", dataLen)
	}
	length := uint32(dataLen) // #nosec G115 - validated above
	lengthBuf := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	if _, err := conn.Write(lengthBuf); err != nil {
		return err
	}

	// Send data
	if _, err := conn.Write(data); err != nil {
		return err
	}

	return nil
}

// receiveMessage receives a length-prefixed message
func receiveMessage(conn net.Conn) ([]byte, error) {
	// Read length (4 bytes)
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, err
	}

	length := uint32(lengthBuf[0])<<24 | uint32(lengthBuf[1])<<16 | uint32(lengthBuf[2])<<8 | uint32(lengthBuf[3])

	// Sanity check
	if length > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	return data, nil
}
