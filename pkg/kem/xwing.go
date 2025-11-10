package kem

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/xwing"
)

// XWing implements the KEM interface using X-Wing from Cloudflare's CIRCL library
// X-Wing is a hybrid KEM combining X25519 (classical ECDH) with ML-KEM-768 (post-quantum)
// This provides both classical and post-quantum security guarantees.
//
// Specification: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
type XWing struct{}

// NewXWing creates a new X-Wing KEM instance
func NewXWing() *XWing {
	return &XWing{}
}

func (k *XWing) Name() string {
	return "xwing"
}

func (k *XWing) PublicKeySize() int {
	return xwing.PublicKeySize
}

func (k *XWing) SecretKeySize() int {
	return xwing.PrivateKeySize
}

func (k *XWing) CiphertextSize() int {
	return xwing.CiphertextSize
}

func (k *XWing) SharedSecretSize() int {
	return xwing.SharedKeySize
}

func (k *XWing) GenerateKey(rng io.Reader) (publicKey, secretKey []byte, err error) {
	// Note: xwing.GenerateKeyPairPacked returns (privateKey, publicKey, error) - reversed order!
	secretKey, publicKey, err = xwing.GenerateKeyPairPacked(rng)
	return publicKey, secretKey, err
}

func (k *XWing) Encapsulate(publicKey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error) {
	// Validate input size to prevent panic
	if len(publicKey) != xwing.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), xwing.PublicKeySize)
	}

	// Recover from panics in the underlying library
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("encapsulation panic: %v", r)
			ciphertext = nil
			sharedSecret = nil
		}
	}()

	// Note: xwing.Encapsulate returns (ss, ct, err) - the order is reversed from our interface
	// seed parameter is nil to use crypto/rand.Reader
	ss, ct, err := xwing.Encapsulate(publicKey, nil)
	if err != nil {
		return nil, nil, err
	}

	return ct, ss, nil
}

func (k *XWing) Decapsulate(ciphertext, secretKey []byte) (sharedSecret []byte, err error) {
	// Validate input sizes to prevent panic
	if len(ciphertext) != xwing.CiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext size: got %d, want %d", len(ciphertext), xwing.CiphertextSize)
	}
	if len(secretKey) != xwing.PrivateKeySize {
		return nil, fmt.Errorf("invalid secret key size: got %d, want %d", len(secretKey), xwing.PrivateKeySize)
	}

	// Recover from panics in the underlying library
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decapsulation panic: %v", r)
			sharedSecret = nil
		}
	}()

	// xwing.Decapsulate only returns the shared secret (panics on invalid input)
	ss := xwing.Decapsulate(ciphertext, secretKey)
	return ss, nil
}

func (k *XWing) ValidatePublicKey(publicKey []byte) error {
	// Validate size
	if len(publicKey) != xwing.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), xwing.PublicKeySize)
	}

	// XWing public key is 1216 bytes:
	// - First 32 bytes: X25519 public key
	// - Remaining 1184 bytes: ML-KEM-768 public key
	
	// Validate X25519 component (first 32 bytes) - check for low-order points
	x25519Key := publicKey[:32]
	
	// Check for all-zero (invalid)
	allZero := true
	for _, b := range x25519Key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("invalid X25519 public key: all-zero")
	}
	
	// The ML-KEM-768 component validation is complex and handled internally
	// by the library during encapsulation. We rely on the library's validation.
	
	return nil
}
