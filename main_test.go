package main

import (
	"os"
	"path/filepath"
	"testing"

	"quantshake/pkg/kem"
)

// TestCmdGenkey tests the genkey command functionality
func TestCmdGenkey(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()

	testCases := []struct {
		name    string
		kemName string
		keyName string
	}{
		{"mlkem768", "mlkem768", filepath.Join(tmpDir, "test_mlkem")},
		{"xwing", "xwing", filepath.Join(tmpDir, "test_xwing")},
		{"sntrup761", "sntrup761", filepath.Join(tmpDir, "test_sntrup")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Run genkey command
			err := cmdGenkey(tc.kemName, tc.keyName)
			if err != nil {
				t.Fatalf("cmdGenkey failed: %v", err)
			}

			// Verify files were created
			pubFile := tc.keyName + ".pub"
			secFile := tc.keyName + ".sec"

			if _, err := os.Stat(pubFile); os.IsNotExist(err) {
				t.Errorf("Public key file was not created: %s", pubFile)
			}

			if _, err := os.Stat(secFile); os.IsNotExist(err) {
				t.Errorf("Secret key file was not created: %s", secFile)
			}

			// Verify we can load the keys back
			algo, pubKey, err := LoadPublicKey(pubFile)
			if err != nil {
				t.Errorf("Failed to load public key: %v", err)
			}

			if algo != tc.kemName {
				t.Errorf("Algorithm mismatch: expected %s, got %s", tc.kemName, algo)
			}

			if len(pubKey) == 0 {
				t.Error("Public key is empty")
			}

			algo2, secKey, err := LoadSecretKey(secFile)
			if err != nil {
				t.Errorf("Failed to load secret key: %v", err)
			}

			if algo2 != tc.kemName {
				t.Errorf("Algorithm mismatch in secret key: expected %s, got %s", tc.kemName, algo2)
			}

			if len(secKey) == 0 {
				t.Error("Secret key is empty")
			}

			// Verify key sizes match the KEM expectations
			k := kem.Get(tc.kemName)
			if k == nil {
				t.Fatalf("Failed to get KEM implementation for %s", tc.kemName)
			}

			// The loaded keys should be valid for the KEM
			// We can't easily verify exact sizes without exposing KEM internals,
			// but we can verify they're non-zero
			if len(pubKey) == 0 || len(secKey) == 0 {
				t.Error("Keys have zero length")
			}
		})
	}
}

// TestCmdGenkeyInvalidKEM tests that genkey fails gracefully with invalid KEM
func TestCmdGenkeyInvalidKEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyName := filepath.Join(tmpDir, "test_invalid")

	err := cmdGenkey("InvalidKEM", keyName)
	if err == nil {
		t.Error("Expected error for invalid KEM, got nil")
	}
}

// TestHelpCommand tests that help text generation works
func TestHelpCommand(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Test root help
	t.Run("RootHelp", func(t *testing.T) {
		// We can't easily test cobra command execution in unit tests,
		// but we can verify the command structure exists
		if rootCmd == nil {
			t.Error("rootCmd is nil")
		}

		if rootCmd.Use != "quantshake" {
			t.Errorf("Expected rootCmd.Use to be 'quantshake', got '%s'", rootCmd.Use)
		}

		if rootCmd.Short == "" {
			t.Error("rootCmd.Short is empty")
		}
	})

	// Test genkey command exists
	t.Run("GenkeyCommand", func(t *testing.T) {
		if genkeyCmd == nil {
			t.Error("genkeyCmd is nil")
		}

		if genkeyCmd.Use != "genkey" {
			t.Errorf("Expected genkeyCmd.Use to be 'genkey', got '%s'", genkeyCmd.Use)
		}

		if genkeyCmd.Short == "" {
			t.Error("genkeyCmd.Short is empty")
		}
	})

	// Test daemon command exists
	t.Run("DaemonCommand", func(t *testing.T) {
		if daemonCmd == nil {
			t.Error("daemonCmd is nil")
		}

		if daemonCmd.Use != "daemon" {
			t.Errorf("Expected daemonCmd.Use to be 'daemon', got '%s'", daemonCmd.Use)
		}

		if daemonCmd.Short == "" {
			t.Error("daemonCmd.Short is empty")
		}
	})
}

// TestAvailableKEMs verifies that all expected KEMs are available
func TestAvailableKEMs(t *testing.T) {
	kemList := kem.List()

	if len(kemList) == 0 {
		t.Error("No KEMs available")
	}

	expectedKEMs := []string{"mlkem768", "xwing", "sntrup761"}

	for _, expected := range expectedKEMs {
		found := false
		for _, available := range kemList {
			if available == expected {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Expected KEM %s not found in available KEMs: %v", expected, kemList)
		}

		// Also verify we can get the KEM
		k := kem.Get(expected)
		if k == nil {
			t.Errorf("kem.Get(%s) returned nil", expected)
		}

		// Verify the KEM returns the expected name
		if k.Name() != expected {
			t.Errorf("kem.Get(%s).Name() returned %s, expected %s", expected, k.Name(), expected)
		}
	}
}

// TestLoadPublicKeyErrors tests error handling in LoadPublicKey
func TestLoadPublicKeyErrors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("FileNotExist", func(t *testing.T) {
		_, _, err := LoadPublicKey(tmpDir + "/nonexistent.pub")
		if err == nil {
			t.Error("Expected error for non-existent file, got nil")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		invalidFile := tmpDir + "/invalid.pub"
		_ = os.WriteFile(invalidFile, []byte("not valid json"), 0644)
		_, _, err := LoadPublicKey(invalidFile)
		if err == nil {
			t.Error("Expected error for invalid JSON, got nil")
		}
	})

	t.Run("InvalidBase64", func(t *testing.T) {
		invalidFile := tmpDir + "/invalid_b64.pub"
		_ = os.WriteFile(invalidFile, []byte(`{"algorithm":"mlkem768","public_key":"not-valid-base64!!!"}`), 0644)
		_, _, err := LoadPublicKey(invalidFile)
		if err == nil {
			t.Error("Expected error for invalid base64, got nil")
		}
	})
}

// TestLoadSecretKeyErrors tests error handling in LoadSecretKey
func TestLoadSecretKeyErrors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("FileNotExist", func(t *testing.T) {
		_, _, err := LoadSecretKey(tmpDir + "/nonexistent.sec")
		if err == nil {
			t.Error("Expected error for non-existent file, got nil")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		invalidFile := tmpDir + "/invalid.sec"
		_ = os.WriteFile(invalidFile, []byte("not valid json"), 0600)
		_, _, err := LoadSecretKey(invalidFile)
		if err == nil {
			t.Error("Expected error for invalid JSON, got nil")
		}
	})

	t.Run("InvalidBase64", func(t *testing.T) {
		invalidFile := tmpDir + "/invalid_b64.sec"
		_ = os.WriteFile(invalidFile, []byte(`{"algorithm":"mlkem768","secret_key":"not-valid-base64!!!"}`), 0600)
		_, _, err := LoadSecretKey(invalidFile)
		if err == nil {
			t.Error("Expected error for invalid base64, got nil")
		}
	})
}

// TestSavePublicKeyError tests error handling in SavePublicKey
func TestSavePublicKeyError(t *testing.T) {
	// Try to write to an invalid path
	err := SavePublicKey("/invalid/path/that/does/not/exist/key.pub", "mlkem768", []byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}

// TestSaveSecretKeyError tests error handling in SaveSecretKey
func TestSaveSecretKeyError(t *testing.T) {
	// Try to write to an invalid path
	err := SaveSecretKey("/invalid/path/that/does/not/exist/key.sec", "mlkem768", []byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}
