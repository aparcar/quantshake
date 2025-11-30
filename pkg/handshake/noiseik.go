// Package handshake — Post-Quantum IK (pqIK) KEM handshake

package handshake

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ------------------------ KEM Interface ------------------------

type KEM interface {
	Name() string
	GenerateKey(rng io.Reader) (publicKey, secretKey []byte, err error)
	Encapsulate(publicKey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(ciphertext, secretKey []byte) (sharedSecret []byte, err error)
	ValidatePublicKey(publicKey []byte) error
}

// ------------------------ Utilities ------------------------

// zeroBytes securely zeros out a byte slice to prevent sensitive data from lingering in memory
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, l int) []byte {
	var res, t []byte
	for i := byte(1); len(res) < l; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		res = append(res, t...)
	}
	return res[:l]
}

// ------------------------ Hash / Key Schedule ------------------------

type keySchedule struct {
	h  []byte // transcript hash (public)
	ck []byte // chaining key (secret)
}

func newKeySchedule(proto string) *keySchedule {
	ph := sha256.Sum256([]byte(proto)) // bind to full suite string
	return &keySchedule{
		h:  ph[:],
		ck: ph[:],
	}
}

// encryptAndHash encrypts plaintext and mixes the ciphertext into the transcript
func (ks *keySchedule) encryptAndHash(plaintext []byte) ([]byte, error) {
	// For IK pattern: use current chaining key to derive encryption key
	prk := hkdfExtract(ks.ck, nil)
	key := hkdfExpand(prk, []byte("encrypt"), 32)
	defer zeroBytes(key)
	defer zeroBytes(prk)

	// Derive nonce from the key and current hash
	nonce, err := deriveAckNonce(key, ks.h)
	if err != nil {
		return nil, err
	}

	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// #nosec G407 - Nonce is cryptographically derived via HKDF
	ciphertext := a.Seal(nil, nonce[:], plaintext, ks.h)
	ks.mixHash(ciphertext)
	return ciphertext, nil
}

// decryptAndHash decrypts ciphertext and mixes it into the transcript
func (ks *keySchedule) decryptAndHash(ciphertext []byte) ([]byte, error) {
	// For IK pattern: use current chaining key to derive encryption key
	prk := hkdfExtract(ks.ck, nil)
	key := hkdfExpand(prk, []byte("encrypt"), 32)
	defer zeroBytes(key)
	defer zeroBytes(prk)

	// Derive nonce from the key and current hash
	nonce, err := deriveAckNonce(key, ks.h)
	if err != nil {
		return nil, err
	}

	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// #nosec G407 - Nonce is cryptographically derived via HKDF
	plaintext, err := a.Open(nil, nonce[:], ciphertext, ks.h)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	ks.mixHash(ciphertext)
	return plaintext, nil
}

func (ks *keySchedule) mixHash(data []byte) {
	h := sha256.New()
	h.Write(ks.h)
	h.Write(data)
	ks.h = h.Sum(nil)
}

func (ks *keySchedule) mixKey(ikm []byte) {
	prk := hkdfExtract(ks.ck, ikm)
	ks.ck = hkdfExpand(prk, []byte("MixKey"), 32)
}

// ------------------------ One-shot AEAD for optional Msg3 ------------------------

func deriveAckNonce(key, ad []byte) ([12]byte, error) {
	var n [12]byte
	prk := hkdfExtract(key, ad)
	okm := hkdfExpand(prk, []byte("ack-nonce|v1"), 12)
	copy(n[:], okm)
	return n, nil
}

func aeadSealOnce(key, ad, pt []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce, _ := deriveAckNonce(key, ad)
	// #nosec G407 - Nonce is cryptographically derived via HKDF from key and AD,
	// not hardcoded. Scanner cannot trace the derivation through deriveAckNonce().
	// This is safe because each (key, AD) pair produces a unique nonce.
	return a.Seal(nil, nonce[:], pt, ad), nil
}

func aeadOpenOnce(key, ad, ct []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce, _ := deriveAckNonce(key, ad)
	// #nosec G407 - Nonce is cryptographically derived via HKDF from key and AD,
	// not hardcoded. Scanner cannot trace the derivation through deriveAckNonce().
	// This is safe because each (key, AD) pair produces a unique nonce.
	return a.Open(nil, nonce[:], ct, ad)
}

// ------------------------ Types ------------------------

type KeyPair struct {
	Sk []byte
	Pk []byte
}

// Initiator
type Initiator struct {
	si  KeyPair
	sr  []byte
	kem KEM

	ei KeyPair

	ks         *keySchedule
	hFinal     []byte
	sharedKey  []byte // single 32-byte key derived at the end
}

// Responder
type Responder struct {
	sr  KeyPair
	si  []byte
	kem KEM

	ei []byte // from Msg1

	ks         *keySchedule
	hFinal     []byte
	sharedKey  []byte // single 32-byte key derived at the end
}

// ------------------------ Messages ------------------------

type Msg1 struct {
	CTss  []byte // SKEM ciphertext (encapsulated to responder's static key)
	EI    []byte // initiator ephemeral public key
	EncSI []byte // encrypted initiator static public key
}

type Msg2 struct {
	ER   []byte // responder ephemeral public key
	CTee []byte // EKEM ciphertext (encapsulated to initiator's ephemeral key)
	CTse []byte // SKEM ciphertext (encapsulated to initiator's static key)
}

type Msg3 struct {
	EncryptedHash []byte // optional ack
}

// ------------------------ Initiator ------------------------

func NewInitiator(si KeyPair, sr []byte, kem KEM, prologue []byte) (*Initiator, error) {
	// Validate responder's static public key
	if err := kem.ValidatePublicKey(sr); err != nil {
		return nil, fmt.Errorf("invalid responder public key: %w", err)
	}

	// Validate our own static public key
	if err := kem.ValidatePublicKey(si.Pk); err != nil {
		return nil, fmt.Errorf("invalid initiator public key: %w", err)
	}

	ks := newKeySchedule("pqIK_PQKEM_ChaChaPoly_SHA256")
	ks.mixHash(prologue)
	// Pre-message in IK: <- s (only responder's static key is known)
	ks.mixHash(sr)
	return &Initiator{si: si, sr: sr, kem: kem, ks: ks}, nil
}

func (i *Initiator) BuildMsg1() (*Msg1, error) {
	// -> skem (encapsulate to responder's static key)
	ctSS, ssSS, err := i.kem.Encapsulate(i.sr, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ss encapsulation failed: %w", err)
	}
	defer zeroBytes(ssSS)
	i.ks.mixKey(ssSS)
	i.ks.mixHash(ctSS)

	// Generate ephemeral key
	eiPk, eiSk, err := i.kem.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key generation failed: %w", err)
	}
	i.ei = KeyPair{Pk: eiPk, Sk: eiSk}

	// -> e
	i.ks.mixHash(i.ei.Pk)

	// -> s (encrypted initiator static public key)
	encSI, err := i.ks.encryptAndHash(i.si.Pk)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt static key: %w", err)
	}

	return &Msg1{CTss: ctSS, EI: i.ei.Pk, EncSI: encSI}, nil
}

func (i *Initiator) ProcessMsg2(m2 *Msg2) error {
	// Validate responder's ephemeral public key
	if err := i.kem.ValidatePublicKey(m2.ER); err != nil {
		return fmt.Errorf("invalid responder ephemeral public key: %w", err)
	}

	// <- e
	i.ks.mixHash(m2.ER)

	// <- ekem (decapsulate with initiator's ephemeral key)
	i.ks.mixHash(m2.CTee)
	ssEE, err := i.kem.Decapsulate(m2.CTee, i.ei.Sk)
	if err != nil {
		return fmt.Errorf("ee decapsulation failed: %w", err)
	}
	defer zeroBytes(ssEE)
	i.ks.mixKey(ssEE)

	// <- skem (decapsulate with initiator's static key)
	i.ks.mixHash(m2.CTse)
	ssSE, err := i.kem.Decapsulate(m2.CTse, i.si.Sk)
	if err != nil {
		return fmt.Errorf("se decapsulation failed: %w", err)
	}
	defer zeroBytes(ssSE)
	i.ks.mixKey(ssSE)

	// Zero ephemeral secret key (no longer needed)
	zeroBytes(i.ei.Sk)

	// Finalize transcript and derive single key
	i.hFinal = append([]byte{}, i.ks.h...)
	i.sharedKey = hkdfExpand(i.ks.ck, []byte("shared"), 32)
	return nil
}

func (i *Initiator) BuildMsg3() (*Msg3, error) {
	if len(i.hFinal) == 0 {
		return nil, fmt.Errorf("handshake not finalized")
	}
	// Derive ack key from transcript; AD = hFinal
	prk := hkdfExtract(nil, i.hFinal)
	defer zeroBytes(prk) // Zero PRK after use
	ackKey := hkdfExpand(prk, []byte("ack"), 32)
	defer zeroBytes(ackKey) // Zero ack key after use
	contextHash := sha256.Sum256(i.hFinal)
	enc, err := aeadSealOnce(ackKey, i.hFinal, contextHash[:])
	if err != nil {
		return nil, err
	}
	return &Msg3{EncryptedHash: enc}, nil
}

func (i *Initiator) GetSharedKey() []byte {
	if len(i.sharedKey) == 0 {
		return nil
	}
	return append([]byte(nil), i.sharedKey...)
}

// Destroy zeros out all sensitive material from the initiator state
func (i *Initiator) Destroy() {
	zeroBytes(i.si.Sk)
	zeroBytes(i.ei.Sk)
	zeroBytes(i.ks.ck)
	zeroBytes(i.sharedKey)
	zeroBytes(i.hFinal)
}

// ------------------------ Responder ------------------------

// NewResponder creates a new responder for IK pattern
// In IK, the responder doesn't know the initiator's static key yet
func NewResponder(sr KeyPair, kem KEM, prologue []byte) (*Responder, error) {
	// Validate our own static public key
	if err := kem.ValidatePublicKey(sr.Pk); err != nil {
		return nil, fmt.Errorf("invalid responder public key: %w", err)
	}

	ks := newKeySchedule("pqIK_PQKEM_ChaChaPoly_SHA256")
	ks.mixHash(prologue)
	// Pre-message in IK: <- s (only responder's static key is known)
	ks.mixHash(sr.Pk)
	return &Responder{sr: sr, kem: kem, ks: ks}, nil
}

func (r *Responder) ProcessMsg1(m1 *Msg1) error {
	// -> skem (decapsulate with responder's static key)
	r.ks.mixHash(m1.CTss)
	ssSS, err := r.kem.Decapsulate(m1.CTss, r.sr.Sk)
	if err != nil {
		return fmt.Errorf("ss decapsulation failed: %w", err)
	}
	defer zeroBytes(ssSS)
	r.ks.mixKey(ssSS)

	// Validate initiator's ephemeral public key
	if err := r.kem.ValidatePublicKey(m1.EI); err != nil {
		return fmt.Errorf("invalid initiator ephemeral public key: %w", err)
	}

	// -> e
	r.ei = m1.EI
	r.ks.mixHash(m1.EI)

	// -> s (decrypt initiator static public key)
	siPk, err := r.ks.decryptAndHash(m1.EncSI)
	if err != nil {
		return fmt.Errorf("failed to decrypt static key: %w", err)
	}

	// Validate initiator's static public key
	if err := r.kem.ValidatePublicKey(siPk); err != nil {
		return fmt.Errorf("invalid initiator static public key: %w", err)
	}
	r.si = siPk

	return nil
}

// GetInitiatorStaticKey returns the initiator's static public key
// This is only available after ProcessMsg1 has been called successfully
func (r *Responder) GetInitiatorStaticKey() []byte {
	if len(r.si) == 0 {
		return nil
	}
	return append([]byte(nil), r.si...)
}

func (r *Responder) BuildMsg2() (*Msg2, error) {
	// Generate responder ephemeral key
	erPk, erSk, err := r.kem.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key generation failed: %w", err)
	}
	defer zeroBytes(erSk) // Will be zeroed after use, not stored

	// <- e
	r.ks.mixHash(erPk)

	// <- ekem (encapsulate to initiator's ephemeral key)
	ctEE, ssEE, err := r.kem.Encapsulate(r.ei, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ee encapsulation failed: %w", err)
	}
	defer zeroBytes(ssEE)
	r.ks.mixKey(ssEE)
	r.ks.mixHash(ctEE)

	// <- skem (encapsulate to initiator's static key)
	ctSE, ssSE, err := r.kem.Encapsulate(r.si, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("se encapsulation failed: %w", err)
	}
	defer zeroBytes(ssSE)
	r.ks.mixKey(ssSE)
	r.ks.mixHash(ctSE)

	// Finalize transcript and derive single key
	r.hFinal = append([]byte{}, r.ks.h...)
	r.sharedKey = hkdfExpand(r.ks.ck, []byte("shared"), 32)

	return &Msg2{ER: erPk, CTee: ctEE, CTse: ctSE}, nil
}

func (r *Responder) ProcessMsg3(m3 *Msg3) error {
	if len(r.hFinal) == 0 {
		return fmt.Errorf("handshake not finalized")
	}
	// Same ack key derivation; AD = hFinal
	prk := hkdfExtract(nil, r.hFinal)
	defer zeroBytes(prk) // Zero PRK after use
	ackKey := hkdfExpand(prk, []byte("ack"), 32)
	defer zeroBytes(ackKey) // Zero ack key after use

	dec, err := aeadOpenOnce(ackKey, r.hFinal, m3.EncryptedHash)
	if err != nil {
		return fmt.Errorf("failed to decrypt msg3: %w", err)
	}
	defer zeroBytes(dec) // Zero decrypted data after use
	expected := sha256.Sum256(r.hFinal)
	if !hmac.Equal(dec, expected[:]) {
		return fmt.Errorf("handshake hash mismatch")
	}
	return nil
}

func (r *Responder) GetSharedKey() []byte {
	if len(r.sharedKey) == 0 {
		return nil
	}
	return append([]byte(nil), r.sharedKey...)
}

// Destroy zeros out all sensitive material from the responder state
func (r *Responder) Destroy() {
	zeroBytes(r.sr.Sk)
	zeroBytes(r.ks.ck)
	zeroBytes(r.sharedKey)
	zeroBytes(r.hFinal)
}
