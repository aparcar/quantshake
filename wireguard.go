package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// InjectWireGuardPSK injects a PSK into a WireGuard interface for a specific peer using netlink
// wgInterface: the WireGuard interface name (e.g., "wg0")
// peerPublicKey: the peer's WireGuard public key (base64 encoded)
// psk: the pre-shared key to inject (32 bytes)
func InjectWireGuardPSK(wgInterface, peerPublicKey string, psk []byte) error {
	if wgInterface == "" || peerPublicKey == "" {
		// If either parameter is empty, skip injection
		return nil
	}

	if len(psk) != 32 {
		return fmt.Errorf("PSK must be exactly 32 bytes, got %d", len(psk))
	}

	// Create WireGuard client
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create WireGuard client: %w", err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			log.Printf("warning: failed to close WireGuard client: %v", closeErr)
		}
	}()

	// Decode peer public key from base64
	peerPubKeyBytes, err := base64.StdEncoding.DecodeString(peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode peer public key: %w", err)
	}

	// Parse peer public key
	peerKey, err := wgtypes.ParseKey(string(peerPubKeyBytes))
	if err != nil {
		// Try parsing as base64 directly
		if len(peerPubKeyBytes) != 32 {
			return fmt.Errorf("invalid peer public key length: expected 32 bytes, got %d", len(peerPubKeyBytes))
		}
		peerKey, err = wgtypes.NewKey(peerPubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse peer public key: %w", err)
		}
	}

	// Create PSK key
	pskKey, err := wgtypes.NewKey(psk)
	if err != nil {
		return fmt.Errorf("failed to create PSK key: %w", err)
	}

	// Configure peer with new PSK
	peerConfig := wgtypes.PeerConfig{
		PublicKey:         peerKey,
		PresharedKey:      &pskKey,
		UpdateOnly:        true, // Only update existing peer, don't create new one
		ReplaceAllowedIPs: false,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	// Apply configuration
	if err := client.ConfigureDevice(wgInterface, config); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %w", err)
	}

	log.Printf("✓ Injected PSK into WireGuard interface %s for peer %s", wgInterface, truncatePubKey(peerPublicKey))
	return nil
}

// ValidateWireGuardConfig checks if WireGuard interface and peer exist
func ValidateWireGuardConfig(wgInterface, peerPublicKey string) error {
	if wgInterface == "" || peerPublicKey == "" {
		// Skip validation if not configured
		return nil
	}

	// Create WireGuard client
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create WireGuard client: %w", err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			log.Printf("warning: failed to close WireGuard client: %v", closeErr)
		}
	}()

	// Get device info
	device, err := client.Device(wgInterface)
	if err != nil {
		return fmt.Errorf("WireGuard interface '%s' not found or not accessible: %w", wgInterface, err)
	}

	// Decode peer public key from base64
	peerPubKeyBytes, err := base64.StdEncoding.DecodeString(peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode peer public key: %w", err)
	}

	// Parse peer public key
	peerKey, err := wgtypes.ParseKey(string(peerPubKeyBytes))
	if err != nil {
		// Try parsing as raw bytes
		if len(peerPubKeyBytes) != 32 {
			return fmt.Errorf("invalid peer public key length: expected 32 bytes, got %d", len(peerPubKeyBytes))
		}
		peerKey, err = wgtypes.NewKey(peerPubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse peer public key: %w", err)
		}
	}

	// Check if peer exists
	peerFound := false
	for _, peer := range device.Peers {
		if peer.PublicKey == peerKey {
			peerFound = true
			break
		}
	}

	if !peerFound {
		return fmt.Errorf("peer %s not found in WireGuard interface %s", truncatePubKey(peerPublicKey), wgInterface)
	}

	log.Printf("✓ Validated WireGuard interface %s with peer %s", wgInterface, truncatePubKey(peerPublicKey))
	return nil
}

// truncatePubKey truncates a public key for logging purposes
func truncatePubKey(pubKey string) string {
	if len(pubKey) > 12 {
		return pubKey[:8] + "..." + pubKey[len(pubKey)-4:]
	}
	return pubKey
}
