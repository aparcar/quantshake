package kem

import "io"

// KEM is the interface for Key Encapsulation Mechanisms
type KEM interface {
	Name() string
	PublicKeySize() int
	SecretKeySize() int
	CiphertextSize() int
	SharedSecretSize() int
	GenerateKey(rng io.Reader) (publicKey, secretKey []byte, err error)
	Encapsulate(publicKey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(ciphertext, secretKey []byte) (sharedSecret []byte, err error)
	ValidatePublicKey(publicKey []byte) error
}

// Get returns a KEM implementation by name
func Get(name string) KEM {
	switch name {
	case "mlkem768":
		return NewMLKEM768()
	case "xwing":
		return NewXWing()
	case "sntrup761":
		return NewSntrup761()
	default:
		return nil
	}
}

// List returns a list of available KEM algorithm names
func List() []string {
	return []string{
		"mlkem768",
		"xwing",
		"sntrup761",
	}
}
