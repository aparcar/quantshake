package kem

import (
	"crypto/rand"
	"fmt"
	"io"

	sntrup "github.com/companyzero/sntrup4591761"
)

// Sntrup761 implements the KEM interface using Streamlined NTRU Prime 761
type Sntrup761 struct{}

// NewSntrup761 creates a new sntrup761 KEM instance
func NewSntrup761() *Sntrup761 {
	return &Sntrup761{}
}

func (k *Sntrup761) Name() string {
	return "sntrup761"
}

func (k *Sntrup761) PublicKeySize() int {
	return sntrup.PublicKeySize
}

func (k *Sntrup761) SecretKeySize() int {
	return sntrup.PrivateKeySize
}

func (k *Sntrup761) CiphertextSize() int {
	return sntrup.CiphertextSize
}

func (k *Sntrup761) SharedSecretSize() int {
	return sntrup.SharedKeySize
}

func (k *Sntrup761) GenerateKey(rng io.Reader) (publicKey, secretKey []byte, err error) {
	// Generate key pair
	pub, priv, err := sntrup.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sntrup761 key generation failed: %w", err)
	}

	// Convert to byte slices
	publicKey = pub[:]
	secretKey = priv[:]

	return publicKey, secretKey, nil
}

func (k *Sntrup761) Encapsulate(publicKey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error) {
	if len(publicKey) != sntrup.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), sntrup.PublicKeySize)
	}

	var pub sntrup.PublicKey
	copy(pub[:], publicKey)

	// Encapsulate
	ct, ss, err := sntrup.Encapsulate(rand.Reader, &pub)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	ciphertext = ct[:]
	sharedSecret = ss[:]

	return ciphertext, sharedSecret, nil
}

func (k *Sntrup761) Decapsulate(ciphertext, secretKey []byte) (sharedSecret []byte, err error) {
	if len(ciphertext) != sntrup.CiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext size: got %d, want %d", len(ciphertext), sntrup.CiphertextSize)
	}
	if len(secretKey) != sntrup.PrivateKeySize {
		return nil, fmt.Errorf("invalid secret key size: got %d, want %d", len(secretKey), sntrup.PrivateKeySize)
	}

	var ct sntrup.Ciphertext
	var priv sntrup.PrivateKey

	copy(ct[:], ciphertext)
	copy(priv[:], secretKey)

	// Decapsulate
	ss, rc := sntrup.Decapsulate(&ct, &priv)
	if rc != 1 {
		return nil, fmt.Errorf("decapsulation failed with return code: %d", rc)
	}

	sharedSecret = ss[:]

	return sharedSecret, nil
}

func (k *Sntrup761) ValidatePublicKey(publicKey []byte) error {
	// Validate size
	if len(publicKey) != sntrup.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), sntrup.PublicKeySize)
	}

	// Check for all-zero key (invalid)
	allZero := true
	for _, b := range publicKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("invalid public key: all-zero")
	}

	// sntrup761 public keys are polynomial encodings.
	// Full validation would require checking if the polynomial is well-formed,
	// but this is computationally expensive and typically handled during encapsulation.
	// The library will fail gracefully if the key is malformed.

	return nil
}
