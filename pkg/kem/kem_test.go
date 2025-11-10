package kem

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestKEMInterface tests that all KEM implementations satisfy the interface
func TestKEMInterface(t *testing.T) {
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		t.Run(k.Name(), func(t *testing.T) {
			if k.Name() == "" {
				t.Error("Name() returned empty string")
			}
			if k.PublicKeySize() <= 0 {
				t.Error("PublicKeySize() returned non-positive value")
			}
			if k.SecretKeySize() <= 0 {
				t.Error("SecretKeySize() returned non-positive value")
			}
			if k.CiphertextSize() <= 0 {
				t.Error("CiphertextSize() returned non-positive value")
			}
			if k.SharedSecretSize() <= 0 {
				t.Error("SharedSecretSize() returned non-positive value")
			}
		})
	}
}

// TestKEMKeyGeneration tests key generation for all KEMs
func TestKEMKeyGeneration(t *testing.T) {
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		t.Run(k.Name(), func(t *testing.T) {
			pk, sk, err := k.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey() failed: %v", err)
			}

			if len(pk) != k.PublicKeySize() {
				t.Errorf("Public key size mismatch: got %d, want %d", len(pk), k.PublicKeySize())
			}

			if len(sk) != k.SecretKeySize() {
				t.Errorf("Secret key size mismatch: got %d, want %d", len(sk), k.SecretKeySize())
			}

			// Check keys are not all zeros
			allZeroPk := true
			for _, b := range pk {
				if b != 0 {
					allZeroPk = false
					break
				}
			}
			if allZeroPk {
				t.Error("Public key is all zeros")
			}

			allZeroSk := true
			for _, b := range sk {
				if b != 0 {
					allZeroSk = false
					break
				}
			}
			if allZeroSk {
				t.Error("Secret key is all zeros")
			}
		})
	}
}

// TestKEMEncapsulateDecapsulate tests the full encapsulation/decapsulation flow
func TestKEMEncapsulateDecapsulate(t *testing.T) {
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		t.Run(k.Name(), func(t *testing.T) {
			// Generate keypair
			pk, sk, err := k.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey() failed: %v", err)
			}

			// Encapsulate
			ct, ss1, err := k.Encapsulate(pk, rand.Reader)
			if err != nil {
				t.Fatalf("Encapsulate() failed: %v", err)
			}

			if len(ct) != k.CiphertextSize() {
				t.Errorf("Ciphertext size mismatch: got %d, want %d", len(ct), k.CiphertextSize())
			}

			if len(ss1) != k.SharedSecretSize() {
				t.Errorf("Shared secret size mismatch: got %d, want %d", len(ss1), k.SharedSecretSize())
			}

			// Decapsulate
			ss2, err := k.Decapsulate(ct, sk)
			if err != nil {
				t.Fatalf("Decapsulate() failed: %v", err)
			}

			if len(ss2) != k.SharedSecretSize() {
				t.Errorf("Decapsulated shared secret size mismatch: got %d, want %d", len(ss2), k.SharedSecretSize())
			}

			// Verify shared secrets match
			if !bytes.Equal(ss1, ss2) {
				t.Error("Shared secrets do not match")
			}
		})
	}
}

// TestKEMMultipleEncapsulations tests that multiple encapsulations produce different ciphertexts
func TestKEMMultipleEncapsulations(t *testing.T) {
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		t.Run(k.Name(), func(t *testing.T) {
			// Generate keypair
			pk, sk, err := k.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey() failed: %v", err)
			}

			// Encapsulate twice
			ct1, ss1, err := k.Encapsulate(pk, rand.Reader)
			if err != nil {
				t.Fatalf("First Encapsulate() failed: %v", err)
			}

			ct2, ss2, err := k.Encapsulate(pk, rand.Reader)
			if err != nil {
				t.Fatalf("Second Encapsulate() failed: %v", err)
			}

			// Ciphertexts should be different (with high probability)
			if bytes.Equal(ct1, ct2) {
				t.Error("Multiple encapsulations produced identical ciphertexts")
			}

			// Shared secrets should be different
			if bytes.Equal(ss1, ss2) {
				t.Error("Multiple encapsulations produced identical shared secrets")
			}

			// Both should decapsulate correctly
			ss1Dec, err := k.Decapsulate(ct1, sk)
			if err != nil {
				t.Fatalf("Decapsulate ct1 failed: %v", err)
			}
			if !bytes.Equal(ss1, ss1Dec) {
				t.Error("First shared secret mismatch after decapsulation")
			}

			ss2Dec, err := k.Decapsulate(ct2, sk)
			if err != nil {
				t.Fatalf("Decapsulate ct2 failed: %v", err)
			}
			if !bytes.Equal(ss2, ss2Dec) {
				t.Error("Second shared secret mismatch after decapsulation")
			}
		})
	}
}

// TestKEMInvalidInputs tests error handling for invalid inputs
func TestKEMInvalidInputs(t *testing.T) {
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		t.Run(k.Name(), func(t *testing.T) {
			// Generate valid keypair
			pk, sk, err := k.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey() failed: %v", err)
			}

			// Test encapsulation with wrong public key size
			t.Run("InvalidPublicKeySize", func(t *testing.T) {
				shortPk := pk[:len(pk)/2]
				_, _, err := k.Encapsulate(shortPk, rand.Reader)
				if err == nil {
					t.Error("Encapsulate() should fail with short public key")
				}
			})

			// Test decapsulation with wrong ciphertext size
			t.Run("InvalidCiphertextSize", func(t *testing.T) {
				shortCt := make([]byte, k.CiphertextSize()/2)
				_, err := k.Decapsulate(shortCt, sk)
				if err == nil {
					t.Error("Decapsulate() should fail with short ciphertext")
				}
			})

			// Test decapsulation with wrong secret key size
			t.Run("InvalidSecretKeySize", func(t *testing.T) {
				// First get a valid ciphertext
				ct, _, err := k.Encapsulate(pk, rand.Reader)
				if err != nil {
					t.Fatalf("Encapsulate() failed: %v", err)
				}

				shortSk := sk[:len(sk)/2]
				_, err = k.Decapsulate(ct, shortSk)
				if err == nil {
					t.Error("Decapsulate() should fail with short secret key")
				}
			})

			// Test decapsulation with random ciphertext (should either error or return random secret)
			t.Run("RandomCiphertext", func(t *testing.T) {
				randomCt := make([]byte, k.CiphertextSize())
				_, _ = rand.Read(randomCt) // Best effort random fill

				// This may or may not error depending on the KEM implementation
				// Some KEMs have implicit rejection and will return a pseudo-random secret
				ss, err := k.Decapsulate(randomCt, sk)

				// If it doesn't error, it should at least return a valid-sized secret
				if err == nil && len(ss) != k.SharedSecretSize() {
					t.Errorf("Decapsulate() with random ciphertext returned wrong size: got %d, want %d", len(ss), k.SharedSecretSize())
				}
			})
		})
	}
}

// TestKEMDeterminism tests that key generation uses the provided randomness
func TestKEMDeterminism(t *testing.T) {
	// Note: This test is limited because we can't easily provide deterministic randomness
	// and the underlying libraries may use additional entropy sources
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		t.Run(k.Name(), func(t *testing.T) {
			// Generate two keypairs and verify they're different
			pk1, sk1, err := k.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("First GenerateKey() failed: %v", err)
			}

			pk2, sk2, err := k.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("Second GenerateKey() failed: %v", err)
			}

			// Keys should be different with overwhelming probability
			if bytes.Equal(pk1, pk2) {
				t.Error("Generated identical public keys")
			}
			if bytes.Equal(sk1, sk2) {
				t.Error("Generated identical secret keys")
			}
		})
	}
}

// TestGet tests the Get() function
func TestGet(t *testing.T) {
	tests := []struct {
		name     string
		kemName  string
		wantNil  bool
		wantName string
	}{
		{"mlkem768", "mlkem768", false, "mlkem768"},
		{"xwing", "xwing", false, "xwing"},
		{"sntrup761", "sntrup761", false, "sntrup761"},
		{"invalid", "invalid", true, ""},
		{"empty", "", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kem := Get(tt.kemName)
			if tt.wantNil {
				if kem != nil {
					t.Errorf("Get(%q) = %v, want nil", tt.kemName, kem)
				}
			} else {
				if kem == nil {
					t.Errorf("Get(%q) = nil, want non-nil", tt.kemName)
				} else if kem.Name() != tt.wantName {
					t.Errorf("Get(%q).Name() = %q, want %q", tt.kemName, kem.Name(), tt.wantName)
				}
			}
		})
	}
}

// TestList tests the List() function
func TestList(t *testing.T) {
	list := List()

	if len(list) == 0 {
		t.Error("List() returned empty slice")
	}

	// Check that all listed KEMs can be retrieved
	for _, name := range list {
		kem := Get(name)
		if kem == nil {
			t.Errorf("List() contains %q but Get(%q) returns nil", name, name)
		}
	}

	// Check for expected algorithms
	expectedAlgos := map[string]bool{
		"mlkem768":   false,
		"xwing":      false,
		"sntrup761":  false,
	}

	for _, name := range list {
		if _, ok := expectedAlgos[name]; ok {
			expectedAlgos[name] = true
		}
	}

	for algo, found := range expectedAlgos {
		if !found {
			t.Errorf("List() does not contain expected algorithm: %s", algo)
		}
	}
}

// BenchmarkKEMKeyGeneration benchmarks key generation for all KEMs
func BenchmarkKEMKeyGeneration(b *testing.B) {
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		b.Run(k.Name(), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, err := k.GenerateKey(rand.Reader)
				if err != nil {
					b.Fatalf("GenerateKey() failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkKEMEncapsulate benchmarks encapsulation for all KEMs
func BenchmarkKEMEncapsulate(b *testing.B) {
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		b.Run(k.Name(), func(b *testing.B) {
			// Setup: generate a keypair
			pk, _, err := k.GenerateKey(rand.Reader)
			if err != nil {
				b.Fatalf("GenerateKey() failed: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, err := k.Encapsulate(pk, rand.Reader)
				if err != nil {
					b.Fatalf("Encapsulate() failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkKEMDecapsulate benchmarks decapsulation for all KEMs
func BenchmarkKEMDecapsulate(b *testing.B) {
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		b.Run(k.Name(), func(b *testing.B) {
			// Setup: generate a keypair and ciphertext
			pk, sk, err := k.GenerateKey(rand.Reader)
			if err != nil {
				b.Fatalf("GenerateKey() failed: %v", err)
			}

			ct, _, err := k.Encapsulate(pk, rand.Reader)
			if err != nil {
				b.Fatalf("Encapsulate() failed: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := k.Decapsulate(ct, sk)
				if err != nil {
					b.Fatalf("Decapsulate() failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkKEMFullCycle benchmarks the complete KEM operation cycle
func BenchmarkKEMFullCycle(b *testing.B) {
	kems := []KEM{
		NewMLKEM768(),
		NewXWing(),
		NewSntrup761(),
	}

	for _, k := range kems {
		b.Run(k.Name(), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Key generation
				pk, sk, err := k.GenerateKey(rand.Reader)
				if err != nil {
					b.Fatalf("GenerateKey() failed: %v", err)
				}

				// Encapsulation
				ct, ss1, err := k.Encapsulate(pk, rand.Reader)
				if err != nil {
					b.Fatalf("Encapsulate() failed: %v", err)
				}

				// Decapsulation
				ss2, err := k.Decapsulate(ct, sk)
				if err != nil {
					b.Fatalf("Decapsulate() failed: %v", err)
				}

				// Verify
				if !bytes.Equal(ss1, ss2) {
					b.Fatal("Shared secrets do not match")
				}
			}
		})
	}
}
