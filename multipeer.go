package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	mathRand "math/rand"
	"net"
	"sync"
	"time"

	"quantshake/pkg/handshake"
	"quantshake/pkg/kem"
)

// PeerHandler manages a single peer's connection and key exchanges
type PeerHandler struct {
	name          string
	config        PeerConfig
	myPublicKey   []byte
	mySecretKey   []byte
	peerPublicKey []byte
	algorithm     string
	kem           kem.KEM

	lastExchange time.Time
	myTurn       bool
	exchangeMu   sync.Mutex

	sharedKey []byte
	keysMu    sync.RWMutex
}

// MultiPeerDaemon manages connections to multiple peers
type MultiPeerDaemon struct {
	config      *Config
	myPublicKey []byte
	mySecretKey []byte
	algorithm   string
	kem         kem.KEM

	// Per-peer handlers
	peers map[string]*PeerHandler
	// Map from public key to peer name for incoming connection routing
	pubKeyToPeer map[string]string
	mu           sync.RWMutex

	listener net.Listener
}

// NewMultiPeerDaemon creates a new multi-peer daemon
func NewMultiPeerDaemon(config *Config) (*MultiPeerDaemon, error) {
	mpd := &MultiPeerDaemon{
		config:       config,
		peers:        make(map[string]*PeerHandler),
		pubKeyToPeer: make(map[string]string),
	}

	// Load our keys
	algo, sk, err := LoadSecretKey(config.Daemon.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load secret key: %w", err)
	}
	mpd.algorithm = algo
	mpd.mySecretKey = sk

	// Extract public key from key file
	pubKeyFile := config.Daemon.PrivateKey[:len(config.Daemon.PrivateKey)-4] + ".pub"
	_, pk, err := LoadPublicKey(pubKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}
	mpd.myPublicKey = pk

	// Get KEM implementation
	mpd.kem = kem.Get(mpd.algorithm)
	if mpd.kem == nil {
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", mpd.algorithm)
	}

	// Create handler for each peer
	for _, peerCfg := range config.Peers {
		handler, err := mpd.createPeerHandler(peerCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create handler for peer '%s': %w", peerCfg.Name, err)
		}
		mpd.peers[peerCfg.Name] = handler

		// Map public key to peer name for routing incoming connections
		mpd.pubKeyToPeer[string(handler.peerPublicKey)] = peerCfg.Name
	}

	return mpd, nil
}

// createPeerHandler creates a PeerHandler instance for a specific peer
func (mpd *MultiPeerDaemon) createPeerHandler(peerCfg PeerConfig) (*PeerHandler, error) {
	// Load peer's public key
	_, peerPk, err := LoadPublicKey(peerCfg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load peer public key: %w", err)
	}

	handler := &PeerHandler{
		name:          peerCfg.Name,
		config:        peerCfg,
		myPublicKey:   mpd.myPublicKey,
		mySecretKey:   mpd.mySecretKey,
		peerPublicKey: peerPk,
		algorithm:     mpd.algorithm,
		kem:           mpd.kem,
		lastExchange:  time.Now(),
		myTurn:        true, // Initially both might try
	}

	return handler, nil
}

// Start starts the multi-peer daemon
func (mpd *MultiPeerDaemon) Start() error {
	// Start listener if configured
	if mpd.config.Daemon.ListenAddr != "" {
		var err error
		mpd.listener, err = net.Listen("tcp", mpd.config.Daemon.ListenAddr)
		if err != nil {
			return fmt.Errorf("failed to start listener: %w", err)
		}
		defer func() {
			if err := mpd.listener.Close(); err != nil {
				log.Printf("Error closing listener: %v", err)
			}
		}()
		log.Printf("Multi-peer daemon listening on %s", mpd.config.Daemon.ListenAddr)

		// Handle incoming connections
		go mpd.handleIncomingConnections()
	} else {
		log.Printf("Multi-peer daemon running in outgoing-only mode (no listener)")
	}

	log.Printf("Managing %d peer(s):", len(mpd.peers))
	for _, peerCfg := range mpd.config.Peers {
		endpoint := peerCfg.Endpoint
		if endpoint == "" {
			endpoint = "incoming-only"
		}
		log.Printf("  - %s: %s", peerCfg.Name, endpoint)
	}

	// Start watchdog for all peers
	go mpd.watchdogLoop()

	// Start goroutine for each peer with an endpoint (outgoing)
	var wg sync.WaitGroup
	for _, peerCfg := range mpd.config.Peers {
		if peerCfg.Endpoint != "" {
			handler := mpd.peers[peerCfg.Name]
			wg.Add(1)
			go func(h *PeerHandler) {
				defer wg.Done()
				log.Printf("[%s] Starting outgoing connection handler", h.name)
				mpd.runOutgoingPeer(h)
			}(handler)
		}
	}

	// If we have a listener, keep the process running
	if mpd.listener != nil {
		// Block indefinitely - the peer handlers will run in background
		select {}
	}

	// If no listener, wait for all peer handlers
	wg.Wait()

	return nil
}

// runOutgoingPeer runs the connection loop for a peer we connect to
func (mpd *MultiPeerDaemon) runOutgoingPeer(ph *PeerHandler) {
	interval := time.Duration(ph.config.Interval) * time.Second

	for {
		// Determine if it's our turn
		ph.exchangeMu.Lock()
		shouldInitiate := ph.myTurn || time.Since(ph.lastExchange) > interval*2
		ph.exchangeMu.Unlock()

		if shouldInitiate {
			if err := mpd.initiateHandshake(ph); err != nil {
				log.Printf("[%s] Handshake failed: %v", ph.name, err)
			}
		}

		// Wait for next interval
		time.Sleep(interval)
	}
}

// initiateHandshake initiates a handshake with a peer with retry logic
func (mpd *MultiPeerDaemon) initiateHandshake(ph *PeerHandler) error {
	attemptNum := 0
	maxAttempts := 5 // Maximum attempts before giving up for this round

	for attemptNum < maxAttempts {
		// Backoff: 1 second with jitter on retries
		if attemptNum > 0 {
			// #nosec G404 - Non-cryptographic randomness acceptable for timing jitter
			jitter := time.Duration(mathRand.Int63n(100)) * time.Millisecond
			waitTime := time.Second + jitter
			log.Printf("[%s] Retry attempt %d after %.3fs...", ph.name, attemptNum, waitTime.Seconds())
			time.Sleep(waitTime)
		}

		attemptNum++
		log.Printf("[%s] Initiating connection to %s (attempt %d/%d)...", ph.name, ph.config.Endpoint, attemptNum, maxAttempts)

		// Connect to peer with timeout
		conn, err := net.DialTimeout("tcp", ph.config.Endpoint, 10*time.Second)
		if err != nil {
			log.Printf("[%s] Failed to connect: %v", ph.name, err)
			continue // Retry
		}

		log.Printf("[%s] Connected to %s, starting handshake", ph.name, conn.RemoteAddr())

		// Perform handshake as initiator
		err = mpd.runHandshakeAsInitiator(conn, ph)
		_ = conn.Close() // Best effort close

		if err != nil {
			log.Printf("[%s] Handshake failed: %v", ph.name, err)
			continue // Retry
		}

		// Success!
		ph.exchangeMu.Lock()
		ph.lastExchange = time.Now()
		ph.myTurn = false // Next time, they should initiate
		ph.exchangeMu.Unlock()

		log.Printf("[%s] Handshake complete, saved PSK to %s", ph.name, ph.config.OutputPSK)
		return nil
	}

	return fmt.Errorf("failed after %d attempts", maxAttempts)
}

// handleIncomingConnections accepts and routes incoming connections to the appropriate peer daemon
func (mpd *MultiPeerDaemon) handleIncomingConnections() {
	for {
		conn, err := mpd.listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go mpd.routeConnection(conn)
	}
}

// routeConnection identifies which peer is connecting and handles the connection
func (mpd *MultiPeerDaemon) routeConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("Error closing connection: %v", err)
		}
	}()

	log.Printf("Received connection from %s, attempting to identify peer", conn.RemoteAddr())

	// Perform handshake and identify peer by their static key
	if err := mpd.handleIncomingHandshake(conn); err != nil {
		log.Printf("Failed to handle incoming handshake from %s: %v", conn.RemoteAddr(), err)
	}
}

// handleIncomingHandshake performs the responder handshake and identifies the peer
func (mpd *MultiPeerDaemon) handleIncomingHandshake(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Create responder (IK pattern - we don't know initiator's key yet)
	prologue := []byte("pqc-key-exchange-v2")
	resp, err := handshake.NewResponder(
		handshake.KeyPair{Sk: mpd.mySecretKey, Pk: mpd.myPublicKey},
		mpd.kem,
		prologue,
	)
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

	// Process Message 1 (this decrypts the initiator's static key)
	err = resp.ProcessMsg1(&m1)
	if err != nil {
		return fmt.Errorf("failed to process msg1: %w", err)
	}

	// Get initiator's static key and identify peer
	initiatorStaticKey := resp.GetInitiatorStaticKey()
	peerName, exists := mpd.pubKeyToPeer[string(initiatorStaticKey)]
	if !exists {
		return fmt.Errorf("unknown initiator static key")
	}

	ph := mpd.peers[peerName]
	log.Printf("[%s] Identified peer from %s", ph.name, conn.RemoteAddr())

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

	// Get and save shared key
	sharedKey := resp.GetSharedKey()
	if err := mpd.saveSharedKey(ph, sharedKey); err != nil {
		return fmt.Errorf("failed to save shared key: %w", err)
	}

	ph.exchangeMu.Lock()
	ph.lastExchange = time.Now()
	ph.myTurn = true // Next time, we should initiate
	ph.exchangeMu.Unlock()

	log.Printf("[%s] Incoming handshake complete from %s", ph.name, conn.RemoteAddr())
	return nil
}

// runHandshakeAsInitiator performs the handshake as initiator with a specific peer
func (mpd *MultiPeerDaemon) runHandshakeAsInitiator(conn net.Conn, ph *PeerHandler) error {
	// Set timeout for handshake
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Create initiator with prologue
	prologue := []byte("pqc-key-exchange-v2")
	init, err := handshake.NewInitiator(
		handshake.KeyPair{Sk: ph.mySecretKey, Pk: ph.myPublicKey},
		ph.peerPublicKey,
		ph.kem,
		prologue,
	)
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

	// Get and save shared key
	sharedKey := init.GetSharedKey()
	if err := mpd.saveSharedKey(ph, sharedKey); err != nil {
		return fmt.Errorf("failed to save shared key: %w", err)
	}

	return nil
}

// saveSharedKey saves the shared key for a peer
func (mpd *MultiPeerDaemon) saveSharedKey(ph *PeerHandler, sharedKey []byte) error {
	ph.keysMu.Lock()
	ph.sharedKey = sharedKey
	ph.keysMu.Unlock()

	// Save to disk at specified output path
	if err := SaveSharedKeyPSK(ph.config.OutputPSK, sharedKey); err != nil {
		return err
	}

	return nil
}

// setRandomKey sets a random fallback key for a peer
func (mpd *MultiPeerDaemon) setRandomKey(ph *PeerHandler) {
	randomKey := make([]byte, 32)
	if _, err := rand.Read(randomKey); err != nil {
		log.Printf("[%s] Failed to generate random key: %v", ph.name, err)
		return
	}

	ph.keysMu.Lock()
	ph.sharedKey = randomKey
	ph.keysMu.Unlock()

	// Save to disk
	if err := SaveSharedKeyPSK(ph.config.OutputPSK, randomKey); err != nil {
		log.Printf("[%s] Failed to save random fallback PSK: %v", ph.name, err)
	} else {
		log.Printf("[%s] Saved random fallback PSK to %s", ph.name, ph.config.OutputPSK)
	}
}

// watchdogLoop monitors all peers for extended connection failures and sets fallback keys
func (mpd *MultiPeerDaemon) watchdogLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		for _, ph := range mpd.peers {
			ph.exchangeMu.Lock()
			elapsed := time.Since(ph.lastExchange)
			interval := time.Duration(ph.config.Interval) * time.Second
			if interval == 0 {
				interval = time.Duration(mpd.config.Daemon.Interval) * time.Second
			}

			// Set random key if no exchange for interval + 30 seconds
			finalTimeout := interval + 30*time.Second

			if elapsed > finalTimeout {
				log.Printf("[%s] WARNING: No key exchange for %.0fs (final timeout: %.0fs), setting random fallback key",
					ph.name, elapsed.Seconds(), finalTimeout.Seconds())
				ph.exchangeMu.Unlock()
				mpd.setRandomKey(ph)
				ph.exchangeMu.Lock()
				ph.lastExchange = time.Now()
			}
			ph.exchangeMu.Unlock()
		}
	}
}

// Stop stops all peer daemons gracefully
func (mpd *MultiPeerDaemon) Stop() error {
	mpd.mu.Lock()
	defer mpd.mu.Unlock()

	log.Printf("Stopping multi-peer daemon...")

	if mpd.listener != nil {
		if err := mpd.listener.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}

	// In a full implementation, you'd signal each daemon to stop gracefully
	for name := range mpd.peers {
		log.Printf("[%s] Stopped", name)
	}

	return nil
}
