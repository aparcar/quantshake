package kem

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

// MLKEM768 implements the KEM interface using ML-KEM-768 (formerly Kyber768)
type MLKEM768 struct {
	scheme kem.Scheme
}

// NewMLKEM768 creates a new ML-KEM-768 KEM instance
func NewMLKEM768() *MLKEM768 {
	return &MLKEM768{
		scheme: schemes.ByName("Kyber768"),
	}
}

func (k *MLKEM768) Name() string {
	return "mlkem768"
}

func (k *MLKEM768) PublicKeySize() int {
	return k.scheme.PublicKeySize()
}

func (k *MLKEM768) SecretKeySize() int {
	return k.scheme.PrivateKeySize()
}

func (k *MLKEM768) CiphertextSize() int {
	return k.scheme.CiphertextSize()
}

func (k *MLKEM768) SharedSecretSize() int {
	return k.scheme.SharedKeySize()
}

func (k *MLKEM768) GenerateKey(rng io.Reader) (publicKey, secretKey []byte, err error) {
	pk, sk, err := k.scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM-768 key generation failed: %w", err)
	}

	// Marshal keys to byte slices
	publicKey, err = pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	secretKey, err = sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal secret key: %w", err)
	}

	return publicKey, secretKey, nil
}

func (k *MLKEM768) Encapsulate(publicKey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error) {
	if len(publicKey) != k.PublicKeySize() {
		return nil, nil, fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), k.PublicKeySize())
	}

	// Unpack public key
	pk, err := k.scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	// Encapsulate
	ct, ss, err := k.scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	return ct, ss, nil
}

func (k *MLKEM768) Decapsulate(ciphertext, secretKey []byte) (sharedSecret []byte, err error) {
	if len(ciphertext) != k.CiphertextSize() {
		return nil, fmt.Errorf("invalid ciphertext size: got %d, want %d", len(ciphertext), k.CiphertextSize())
	}
	if len(secretKey) != k.SecretKeySize() {
		return nil, fmt.Errorf("invalid secret key size: got %d, want %d", len(secretKey), k.SecretKeySize())
	}

	// Unpack secret key
	sk, err := k.scheme.UnmarshalBinaryPrivateKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret key: %w", err)
	}

	// Decapsulate
	ss, err := k.scheme.Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}

	return ss, nil
}

func (k *MLKEM768) ValidatePublicKey(publicKey []byte) error {
	if len(publicKey) != k.PublicKeySize() {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), k.PublicKeySize())
	}

	// Attempt to unmarshal to verify it's well-formed
	_, err := k.scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	return nil
}
