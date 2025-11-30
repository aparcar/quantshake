package main

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

// Config represents the main configuration structure
type Config struct {
	Daemon DaemonGlobalConfig `toml:"daemon"`
	Peers  []PeerConfig       `toml:"peers"`
}

// DaemonGlobalConfig contains global daemon settings
type DaemonGlobalConfig struct {
	ListenAddr string `toml:"listen_addr"` // Address to listen on (optional, omit to only initiate)
	PrivateKey string `toml:"private_key"` // Path to our private key
	Interval   int    `toml:"interval"`    // Default interval in seconds
}

// PeerConfig represents configuration for a single peer
type PeerConfig struct {
	Name      string `toml:"name"`       // Peer identifier
	PublicKey string `toml:"public_key"` // Path to peer's public key
	Endpoint  string `toml:"endpoint"`   // Peer's address (host:port) - optional if only accepting
	OutputPSK string `toml:"output_psk"` // Where to save the shared PSK
	Interval  int    `toml:"interval"`   // Override default interval (optional, 0 = use default)
}

// LoadConfig loads configuration from a TOML file
func LoadConfig(filename string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(filename, &config); err != nil {
		return nil, fmt.Errorf("failed to parse TOML config: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate global config
	if c.Daemon.PrivateKey == "" {
		return fmt.Errorf("daemon.private_key is required")
	}
	if c.Daemon.Interval <= 0 {
		c.Daemon.Interval = 120 // Default to 120 seconds
	}

	// Validate peers
	if len(c.Peers) == 0 {
		return fmt.Errorf("at least one peer must be configured")
	}

	hasListenAddr := c.Daemon.ListenAddr != ""
	hasOutgoingPeer := false

	peerNames := make(map[string]bool)
	for i, peer := range c.Peers {
		if peer.Name == "" {
			return fmt.Errorf("peer %d: name is required", i)
		}
		if peerNames[peer.Name] {
			return fmt.Errorf("peer %d: duplicate name '%s'", i, peer.Name)
		}
		peerNames[peer.Name] = true

		if peer.PublicKey == "" {
			return fmt.Errorf("peer '%s': public_key is required", peer.Name)
		}
		if peer.OutputPSK == "" {
			return fmt.Errorf("peer '%s': output_psk is required", peer.Name)
		}

		// Track if we have any outgoing peers
		if peer.Endpoint != "" {
			hasOutgoingPeer = true
		}

		// If peer-specific interval not set, it will use the global default
		if peer.Interval <= 0 {
			c.Peers[i].Interval = c.Daemon.Interval
		}
	}

	// Must either listen OR have at least one outgoing peer
	if !hasListenAddr && !hasOutgoingPeer {
		return fmt.Errorf("must either specify daemon.listen_addr or configure at least one peer with an endpoint")
	}

	return nil
}
