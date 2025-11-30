package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"quantshake/pkg/kem"
)

// ------------------------ Key File Format ------------------------

// PublicKeyFile represents the JSON structure for public key files
type PublicKeyFile struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"` // base64 encoded
}

// SecretKeyFile represents the JSON structure for secret key files
type SecretKeyFile struct {
	Algorithm string `json:"algorithm"`
	SecretKey string `json:"secret_key"` // base64 encoded
}

// SavePublicKey saves a public key to a JSON file
func SavePublicKey(filename string, algorithm string, publicKey []byte) error {
	keyFile := PublicKeyFile{
		Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}

	data, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// #nosec G306 - Public keys are meant to be readable (0644 is appropriate)
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	return nil
}

// SaveSecretKey saves a secret key to a JSON file
func SaveSecretKey(filename string, algorithm string, secretKey []byte) error {
	keyFile := SecretKeyFile{
		Algorithm: algorithm,
		SecretKey: base64.StdEncoding.EncodeToString(secretKey),
	}

	data, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secret key: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write secret key file: %w", err)
	}

	return nil
}

// LoadPublicKey loads a public key from a JSON file
func LoadPublicKey(filename string) (algorithm string, publicKey []byte, err error) {
	// #nosec G304 - filename comes from CLI args or config, validated by caller
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	var keyFile PublicKeyFile
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	publicKey, err = base64.StdEncoding.DecodeString(keyFile.PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return keyFile.Algorithm, publicKey, nil
}

// LoadSecretKey loads a secret key from a JSON file
func LoadSecretKey(filename string) (algorithm string, secretKey []byte, err error) {
	// #nosec G304 - filename comes from CLI args or config, validated by caller
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read secret key file: %w", err)
	}

	var keyFile SecretKeyFile
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal secret key: %w", err)
	}

	secretKey, err = base64.StdEncoding.DecodeString(keyFile.SecretKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode secret key: %w", err)
	}

	return keyFile.Algorithm, secretKey, nil
}

// ------------------------ Commands ------------------------

func cmdGenkey(kemName, keyName string) error {
	// Get KEM implementation
	k := kem.Get(kemName)
	if k == nil {
		return fmt.Errorf("unknown KEM algorithm: %s\nAvailable KEMs: %s", kemName, strings.Join(kem.List(), ", "))
	}

	fmt.Printf("Generating %s keypair...\n", k.Name())

	// Generate keypair
	publicKey, secretKey, err := k.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	// Construct filenames
	pubFile := keyName + ".pub"
	secFile := keyName + ".sec"

	// Save keys to files
	if err := SavePublicKey(pubFile, k.Name(), publicKey); err != nil {
		return err
	}

	if err := SaveSecretKey(secFile, k.Name(), secretKey); err != nil {
		return err
	}

	fmt.Printf("✓ Generated %s keypair\n", k.Name())
	fmt.Printf("  Public key:  %s (%d bytes)\n", pubFile, len(publicKey))
	fmt.Printf("  Secret key:  %s (%d bytes)\n", secFile, len(secretKey))

	return nil
}

// ------------------------ Cobra Commands ------------------------

var rootCmd = &cobra.Command{
	Use:   "quantshake",
	Short: "QuantShake - Post-Quantum Key Exchange Daemon",
	Long:  "A Post-Quantum Cryptography (PQC) demonstration implementing a peer-to-peer key exchange daemon with support for multiple KEM algorithms.",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a keypair",
	Long:  "Generate a post-quantum cryptography keypair for the specified KEM algorithm.",
	RunE: func(cmd *cobra.Command, args []string) error {
		kemName, _ := cmd.Flags().GetString("kem")
		keyName, _ := cmd.Flags().GetString("name")

		if kemName == "" {
			fmt.Println("Error: --kem flag is required")
			fmt.Println()
			fmt.Println("Available KEM algorithms:")
			for _, k := range kem.List() {
				fmt.Printf("  - %s\n", k)
			}
			os.Exit(1)
		}

		return cmdGenkey(kemName, keyName)
	},
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run as daemon with periodic key exchange",
	Long:  "Run as a daemon that maintains continuous key exchange with peer(s). Can use either flags for single peer or --config for multiple peers.",
	RunE: func(cmd *cobra.Command, args []string) error {
		configFile, _ := cmd.Flags().GetString("config")

		// If config file provided, use multi-peer mode
		if configFile != "" {
			config, err := LoadConfig(configFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			mpd, err := NewMultiPeerDaemon(config)
			if err != nil {
				return fmt.Errorf("failed to create multi-peer daemon: %w", err)
			}

			return mpd.Start()
		}

		// Otherwise, use single-peer mode with flags
		listenAddr, _ := cmd.Flags().GetString("listen")
		endpoint, _ := cmd.Flags().GetString("endpoint")
		privateKey, _ := cmd.Flags().GetString("private-key")
		peerPublicKey, _ := cmd.Flags().GetString("peer-public-key")
		output, _ := cmd.Flags().GetString("output")
		interval, _ := cmd.Flags().GetInt("interval")

		// Validate required flags
		if privateKey == "" {
			return fmt.Errorf("--private-key / -k flag is required")
		}
		if peerPublicKey == "" {
			return fmt.Errorf("--peer-public-key / -p flag is required")
		}
		if output == "" {
			return fmt.Errorf("--output / -o flag is required")
		}

		config := DaemonConfig{
			ListenAddr:  listenAddr,
			ConnectAddr: endpoint,
			PeerKeyFile: peerPublicKey,
			KeyFile:     privateKey,
			Interval:    interval,
			PeerName:    output,
		}

		daemon, err := NewDaemon(config)
		if err != nil {
			return err
		}

		return daemon.Start()
	},
}

func init() {
	// Genkey command flags
	genkeyCmd.Flags().String("kem", "", "KEM algorithm (mlkem768, xwing, sntrup761) - required")
	genkeyCmd.Flags().String("name", "key", "Key name (creates <name>.pub and <name>.sec)")

	// Daemon command flags
	daemonCmd.Flags().StringP("config", "c", "", "Path to TOML configuration file (for multi-peer mode)")
	daemonCmd.Flags().String("listen", "127.0.0.1:8000", "Listen address (single-peer mode)")
	daemonCmd.Flags().StringP("endpoint", "e", "127.0.0.1:8001", "Peer endpoint address (single-peer mode)")
	daemonCmd.Flags().StringP("private-key", "k", "", "Path to our private key file (required in single-peer mode)")
	daemonCmd.Flags().StringP("peer-public-key", "p", "", "Path to peer's public key file (required in single-peer mode)")
	daemonCmd.Flags().StringP("output", "o", "", "Output PSK file path (required in single-peer mode)")
	daemonCmd.Flags().IntP("interval", "i", 120, "Key exchange interval in seconds (single-peer mode)")

	// Add commands to root
	rootCmd.AddCommand(genkeyCmd)
	rootCmd.AddCommand(daemonCmd)
}

// ------------------------ Main ------------------------

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
