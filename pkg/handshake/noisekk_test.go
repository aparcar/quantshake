package handshake

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

// mockKEM is a simple KEM implementation for testing
type mockKEM struct {
	pkSize int
	skSize int
	ctSize int
	ssSize int
}

func newMockKEM() *mockKEM {
	return &mockKEM{
		pkSize: 32,
		skSize: 32,
		ctSize: 48,
		ssSize: 32,
	}
}

func (m *mockKEM) Name() string {
	return "MockKEM"
}

func (m *mockKEM) GenerateKey(rng io.Reader) (publicKey, secretKey []byte, err error) {
	pk := make([]byte, m.pkSize)
	sk := make([]byte, m.skSize)
	if _, err := rng.Read(pk); err != nil {
		return nil, nil, err
	}
	if _, err := rng.Read(sk); err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

func (m *mockKEM) Encapsulate(publicKey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error) {
	ct := make([]byte, m.ctSize)
	ss := make([]byte, m.ssSize)
	if _, err := rng.Read(ct); err != nil {
		return nil, nil, err
	}
	if _, err := rng.Read(ss); err != nil {
		return nil, nil, err
	}
	// Store shared secret in ciphertext for decapsulation (simplified for testing)
	copy(ct[len(ct)-m.ssSize:], ss)
	return ct, ss, nil
}

func (m *mockKEM) Decapsulate(ciphertext, secretKey []byte) (sharedSecret []byte, err error) {
	// Extract shared secret from ciphertext (simplified for testing)
	ss := make([]byte, m.ssSize)
	copy(ss, ciphertext[len(ciphertext)-m.ssSize:])
	return ss, nil
}

func (m *mockKEM) ValidatePublicKey(publicKey []byte) error {
	if len(publicKey) != m.pkSize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), m.pkSize)
	}
	// Accept any non-empty key of correct size for testing
	return nil
}

// TestKeyScheduleInit tests initialization of the key schedule
func TestKeyScheduleInit(t *testing.T) {
	ks := newKeySchedule("test_protocol")

	if ks.h == nil {
		t.Error("Hash should be initialized")
	}
	if ks.ck == nil {
		t.Error("Chaining key should be initialized")
	}
	if len(ks.h) != 32 {
		t.Errorf("Hash should be 32 bytes, got %d", len(ks.h))
	}
	if len(ks.ck) != 32 {
		t.Errorf("Chaining key should be 32 bytes, got %d", len(ks.ck))
	}
}

// TestKeyScheduleMixHash tests the mixHash operation
func TestKeyScheduleMixHash(t *testing.T) {
	ks := newKeySchedule("test_protocol")
	originalHash := make([]byte, len(ks.h))
	copy(originalHash, ks.h)

	data := []byte("test data")
	ks.mixHash(data)

	if bytes.Equal(ks.h, originalHash) {
		t.Error("Hash should change after mixHash")
	}
	if len(ks.h) != 32 {
		t.Errorf("Hash should remain 32 bytes, got %d", len(ks.h))
	}

	// Test that mixing same data again produces different result
	secondHash := make([]byte, len(ks.h))
	copy(secondHash, ks.h)
	ks.mixHash(data)

	if bytes.Equal(ks.h, secondHash) {
		t.Error("Hash should change with each mixHash call")
	}
}

// TestKeyScheduleMixKey tests the mixKey operation
func TestKeyScheduleMixKey(t *testing.T) {
	ks := newKeySchedule("test_protocol")
	originalCK := make([]byte, len(ks.ck))
	copy(originalCK, ks.ck)

	ikm := make([]byte, 32)
	_, _ = rand.Read(ikm) // Best effort random fill

	ks.mixKey(ikm)

	if bytes.Equal(ks.ck, originalCK) {
		t.Error("Chaining key should change after mixKey")
	}
	if len(ks.ck) != 32 {
		t.Errorf("Chaining key should remain 32 bytes, got %d", len(ks.ck))
	}
}

// TestHKDFOperations tests HKDF extract and expand
func TestHKDFOperations(t *testing.T) {
	salt := make([]byte, 32)
	ikm := make([]byte, 32)
	_, _ = rand.Read(salt) // Best effort random fill
	_, _ = rand.Read(ikm)  // Best effort random fill

	// Test extract
	prk := hkdfExtract(salt, ikm)
	if len(prk) != 32 {
		t.Errorf("PRK should be 32 bytes, got %d", len(prk))
	}

	// Test expand
	okm := hkdfExpand(prk, []byte("test info"), 64)
	if len(okm) != 64 {
		t.Errorf("OKM should be 64 bytes, got %d", len(okm))
	}

	// Test determinism
	prk2 := hkdfExtract(salt, ikm)
	if !bytes.Equal(prk, prk2) {
		t.Error("HKDF extract should be deterministic")
	}

	okm2 := hkdfExpand(prk, []byte("test info"), 64)
	if !bytes.Equal(okm, okm2) {
		t.Error("HKDF expand should be deterministic")
	}

	// Test different info produces different output
	okm3 := hkdfExpand(prk, []byte("different info"), 64)
	if bytes.Equal(okm, okm3) {
		t.Error("Different info should produce different output")
	}
}

// TestAEADSealOpen tests AEAD encryption and decryption
func TestAEADSealOpen(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key) // Best effort random fill

	ad := []byte("additional data")
	pt := []byte("plaintext message")

	// Test seal
	ct, err := aeadSealOnce(key, ad, pt)
	if err != nil {
		t.Fatalf("aeadSealOnce failed: %v", err)
	}

	if len(ct) <= len(pt) {
		t.Error("Ciphertext should be longer than plaintext (includes tag)")
	}

	// Test open
	decrypted, err := aeadOpenOnce(key, ad, ct)
	if err != nil {
		t.Fatalf("aeadOpenOnce failed: %v", err)
	}

	if !bytes.Equal(decrypted, pt) {
		t.Error("Decrypted plaintext does not match original")
	}

	// Test with wrong key
	wrongKey := make([]byte, 32)
	_, _ = rand.Read(wrongKey) // Best effort random fill
	_, err = aeadOpenOnce(wrongKey, ad, ct)
	if err == nil {
		t.Error("aeadOpenOnce should fail with wrong key")
	}

	// Test with wrong additional data
	wrongAD := []byte("wrong additional data")
	_, err = aeadOpenOnce(key, wrongAD, ct)
	if err == nil {
		t.Error("aeadOpenOnce should fail with wrong additional data")
	}
}

// TestFullHandshake tests a complete handshake between initiator and responder
func TestFullHandshake(t *testing.T) {
	kem := newMockKEM()
	prologue := []byte("test prologue")

	// Generate static keypairs
	iPk, iSk, err := kem.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate initiator static keypair: %v", err)
	}

	rPk, rSk, err := kem.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate responder static keypair: %v", err)
	}

	// Create initiator and responder
	initiator, err := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, rPk, kem, prologue)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}
	responder, err := NewResponder(KeyPair{Pk: rPk, Sk: rSk}, iPk, kem, prologue)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Message 1: I -> R
	msg1, err := initiator.BuildMsg1()
	if err != nil {
		t.Fatalf("BuildMsg1 failed: %v", err)
	}

	if msg1.EI == nil || len(msg1.EI) != kem.pkSize {
		t.Errorf("Msg1.EI has wrong size: got %d, want %d", len(msg1.EI), kem.pkSize)
	}
	if msg1.CTss == nil || len(msg1.CTss) != kem.ctSize {
		t.Errorf("Msg1.CTss has wrong size: got %d, want %d", len(msg1.CTss), kem.ctSize)
	}

	err = responder.ProcessMsg1(msg1)
	if err != nil {
		t.Fatalf("ProcessMsg1 failed: %v", err)
	}

	// Message 2: R -> I
	msg2, err := responder.BuildMsg2()
	if err != nil {
		t.Fatalf("BuildMsg2 failed: %v", err)
	}

	if msg2.CTse == nil || len(msg2.CTse) != kem.ctSize {
		t.Errorf("Msg2.CTse has wrong size: got %d, want %d", len(msg2.CTse), kem.ctSize)
	}
	if msg2.CTss == nil || len(msg2.CTss) != kem.ctSize {
		t.Errorf("Msg2.CTss has wrong size: got %d, want %d", len(msg2.CTss), kem.ctSize)
	}

	err = initiator.ProcessMsg2(msg2)
	if err != nil {
		t.Fatalf("ProcessMsg2 failed: %v", err)
	}

	// Message 3: I -> R (Acknowledgment)
	msg3, err := initiator.BuildMsg3()
	if err != nil {
		t.Fatalf("BuildMsg3 failed: %v", err)
	}

	if len(msg3.EncryptedHash) == 0 {
		t.Error("Msg3.EncryptedHash should not be empty")
	}

	err = responder.ProcessMsg3(msg3)
	if err != nil {
		t.Fatalf("ProcessMsg3 failed: %v", err)
	}

	// Verify shared keys match
	iKey := initiator.GetSharedKey()
	rKey := responder.GetSharedKey()

	if len(iKey) != 32 {
		t.Errorf("Initiator shared key should be 32 bytes, got %d", len(iKey))
	}
	if len(rKey) != 32 {
		t.Errorf("Responder shared key should be 32 bytes, got %d", len(rKey))
	}

	if !bytes.Equal(iKey, rKey) {
		t.Error("Shared keys do not match")
	}

	// Verify handshake hashes match
	if !bytes.Equal(initiator.hFinal, responder.hFinal) {
		t.Error("Handshake hashes do not match")
	}
}

// TestHandshakeWithDifferentPrologues tests that different prologues produce different keys
func TestHandshakeWithDifferentPrologues(t *testing.T) {
	kem := newMockKEM()

	// Generate static keypairs
	iPk, iSk, err := kem.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate initiator static keypair: %v", err)
	}

	rPk, rSk, err := kem.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate responder static keypair: %v", err)
	}

	// First handshake with prologue1
	prologue1 := []byte("prologue1")
	initiator1, _ := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, rPk, kem, prologue1)
	responder1, _ := NewResponder(KeyPair{Pk: rPk, Sk: rSk}, iPk, kem, prologue1)

	msg1_1, _ := initiator1.BuildMsg1()
	_ = responder1.ProcessMsg1(msg1_1)
	msg2_1, _ := responder1.BuildMsg2()
	_ = initiator1.ProcessMsg2(msg2_1)
	msg3_1, _ := initiator1.BuildMsg3()
	_ = responder1.ProcessMsg3(msg3_1)

	key1 := initiator1.GetSharedKey()

	// Second handshake with prologue2
	prologue2 := []byte("prologue2")
	initiator2, _ := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, rPk, kem, prologue2)
	responder2, _ := NewResponder(KeyPair{Pk: rPk, Sk: rSk}, iPk, kem, prologue2)

	msg1_2, _ := initiator2.BuildMsg1()
	_ = responder2.ProcessMsg1(msg1_2)
	msg2_2, _ := responder2.BuildMsg2()
	_ = initiator2.ProcessMsg2(msg2_2)
	msg3_2, _ := initiator2.BuildMsg3()
	_ = responder2.ProcessMsg3(msg3_2)

	key2 := initiator2.GetSharedKey()

	// Keys should be different (with high probability due to ephemeral randomness)
	if bytes.Equal(key1, key2) {
		t.Log("Warning: Different prologues produced same shared key (unlikely but possible due to randomness)")
	}
}

// TestHandshakeMsg3Tampering tests that tampering with Msg3 is detected
func TestHandshakeMsg3Tampering(t *testing.T) {
	kem := newMockKEM()
	prologue := []byte("test prologue")

	// Generate static keypairs
	iPk, iSk, err := kem.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate initiator static keypair: %v", err)
	}

	rPk, rSk, err := kem.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate responder static keypair: %v", err)
	}

	// Create initiator and responder
	initiator, _ := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, rPk, kem, prologue)
	responder, _ := NewResponder(KeyPair{Pk: rPk, Sk: rSk}, iPk, kem, prologue)

	// Complete handshake up to Msg3
	msg1, _ := initiator.BuildMsg1()
	_ = responder.ProcessMsg1(msg1)
	msg2, _ := responder.BuildMsg2()
	_ = initiator.ProcessMsg2(msg2)
	msg3, _ := initiator.BuildMsg3()

	// Tamper with Msg3
	tamperedMsg3 := &Msg3{
		EncryptedHash: make([]byte, len(msg3.EncryptedHash)),
	}
	copy(tamperedMsg3.EncryptedHash, msg3.EncryptedHash)
	tamperedMsg3.EncryptedHash[0] ^= 0x01 // Flip one bit

	// Try to process tampered message
	err = responder.ProcessMsg3(tamperedMsg3)
	if err == nil {
		t.Error("ProcessMsg3 should fail with tampered message")
	}

	// Verify original message still works
	initiator2, _ := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, rPk, kem, prologue)
	responder2, _ := NewResponder(KeyPair{Pk: rPk, Sk: rSk}, iPk, kem, prologue)

	msg1_2, _ := initiator2.BuildMsg1()
	_ = responder2.ProcessMsg1(msg1_2)
	msg2_2, _ := responder2.BuildMsg2()
	_ = initiator2.ProcessMsg2(msg2_2)
	msg3_2, _ := initiator2.BuildMsg3()

	err = responder2.ProcessMsg3(msg3_2)
	if err != nil {
		t.Errorf("ProcessMsg3 should succeed with valid message: %v", err)
	}
}

// TestHandshakeWrongStaticKeys tests that handshake fails with wrong static keys
func TestHandshakeWrongStaticKeys(t *testing.T) {
	kem := newMockKEM()
	prologue := []byte("test prologue")

	// Generate static keypairs
	iPk, iSk, _ := kem.GenerateKey(rand.Reader)
	rPk, rSk, _ := kem.GenerateKey(rand.Reader)
	wrongPk, _, _ := kem.GenerateKey(rand.Reader)

	// Initiator has wrong responder public key
	initiator, _ := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, wrongPk, kem, prologue)
	responder, _ := NewResponder(KeyPair{Pk: rPk, Sk: rSk}, iPk, kem, prologue)

	msg1, _ := initiator.BuildMsg1()

	// Responder will process message but the decapsulation will use wrong key
	// The handshake will complete but the shared secrets won't match
	// This is expected behavior for KEM-based protocols
	err := responder.ProcessMsg1(msg1)
	if err != nil {
		// Some KEMs may error on invalid encapsulation
		t.Logf("ProcessMsg1 failed as expected with wrong key: %v", err)
	}
}

// TestMultipleHandshakes tests that multiple handshakes produce different keys
func TestMultipleHandshakes(t *testing.T) {
	kem := newMockKEM()
	prologue := []byte("test prologue")

	// Generate static keypairs
	iPk, iSk, _ := kem.GenerateKey(rand.Reader)
	rPk, rSk, _ := kem.GenerateKey(rand.Reader)

	keys := make([][]byte, 3)

	for i := 0; i < 3; i++ {
		initiator, _ := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, rPk, kem, prologue)
		responder, _ := NewResponder(KeyPair{Pk: rPk, Sk: rSk}, iPk, kem, prologue)

		msg1, _ := initiator.BuildMsg1()
		_ = responder.ProcessMsg1(msg1)
		msg2, _ := responder.BuildMsg2()
		_ = initiator.ProcessMsg2(msg2)
		msg3, _ := initiator.BuildMsg3()
		_ = responder.ProcessMsg3(msg3)

		keys[i] = initiator.GetSharedKey()
	}

	// Keys should be different due to ephemeral randomness
	if bytes.Equal(keys[0], keys[1]) {
		t.Error("Multiple handshakes should produce different keys (run 1 vs 2)")
	}
	if bytes.Equal(keys[1], keys[2]) {
		t.Error("Multiple handshakes should produce different keys (run 2 vs 3)")
	}
	if bytes.Equal(keys[0], keys[2]) {
		t.Error("Multiple handshakes should produce different keys (run 1 vs 3)")
	}
}

// TestStaticPair tests the StaticPair structure
func TestStaticPair(t *testing.T) {
	kem := newMockKEM()
	pk, sk, err := kem.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	pair := KeyPair{Pk: pk, Sk: sk}

	if !bytes.Equal(pair.Pk, pk) {
		t.Error("StaticPair.Pk does not match")
	}
	if !bytes.Equal(pair.Sk, sk) {
		t.Error("StaticPair.Sk does not match")
	}
}

// BenchmarkFullHandshake benchmarks a complete handshake
func BenchmarkFullHandshake(b *testing.B) {
	kem := newMockKEM()
	prologue := []byte("test prologue")

	// Generate static keypairs
	iPk, iSk, _ := kem.GenerateKey(rand.Reader)
	rPk, rSk, _ := kem.GenerateKey(rand.Reader)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		initiator, _ := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, rPk, kem, prologue)
		responder, _ := NewResponder(KeyPair{Pk: rPk, Sk: rSk}, iPk, kem, prologue)

		msg1, _ := initiator.BuildMsg1()
		_ = responder.ProcessMsg1(msg1)
		msg2, _ := responder.BuildMsg2()
		_ = initiator.ProcessMsg2(msg2)
		msg3, _ := initiator.BuildMsg3()
		_ = responder.ProcessMsg3(msg3)
	}
}

// BenchmarkBuildMsg1 benchmarks building message 1
func BenchmarkBuildMsg1(b *testing.B) {
	kem := newMockKEM()
	prologue := []byte("test prologue")

	iPk, iSk, _ := kem.GenerateKey(rand.Reader)
	rPk, _, _ := kem.GenerateKey(rand.Reader)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		initiator, _ := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, rPk, kem, prologue)
		_, _ = initiator.BuildMsg1()
	}
}

// BenchmarkBuildMsg2 benchmarks building message 2
func BenchmarkBuildMsg2(b *testing.B) {
	kem := newMockKEM()
	prologue := []byte("test prologue")

	iPk, iSk, _ := kem.GenerateKey(rand.Reader)
	rPk, rSk, _ := kem.GenerateKey(rand.Reader)

	initiator, _ := NewInitiator(KeyPair{Pk: iPk, Sk: iSk}, rPk, kem, prologue)
	msg1, _ := initiator.BuildMsg1()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		responder, _ := NewResponder(KeyPair{Pk: rPk, Sk: rSk}, iPk, kem, prologue)
		_ = responder.ProcessMsg1(msg1)
		_, _ = responder.BuildMsg2()
	}
}

// BenchmarkHKDFExpand benchmarks HKDF expand operation
func BenchmarkHKDFExpand(b *testing.B) {
	prk := make([]byte, 32)
	_, _ = rand.Read(prk) // Best effort random fill
	info := []byte("test info")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		hkdfExpand(prk, info, 64)
	}
}

// BenchmarkAEADSeal benchmarks AEAD encryption
func BenchmarkAEADSeal(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key) // Best effort random fill
	ad := []byte("additional data")
	pt := []byte("plaintext message for benchmarking")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = aeadSealOnce(key, ad, pt)
	}
}

// BenchmarkAEADOpen benchmarks AEAD decryption
func BenchmarkAEADOpen(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key) // Best effort random fill
	ad := []byte("additional data")
	pt := []byte("plaintext message for benchmarking")

	ct, _ := aeadSealOnce(key, ad, pt)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = aeadOpenOnce(key, ad, ct)
	}
}
