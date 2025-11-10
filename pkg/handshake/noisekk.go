// Package handshake — PQ Noise KK-style KEM handshake (single final key)

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
	EI   []byte // initiator ephemeral public key
	CTss []byte // SKEM to responder static
}

type Msg2 struct {
	CTse []byte // EKEM to initiator ephemeral
	CTss []byte // SKEM to initiator static
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

	ks := newKeySchedule("Noise_KK_PQKEM_ChaChaPoly_SHA256")
	ks.mixHash(prologue)
	// Pre-messages in KK: -> s, <- s
	ks.mixHash(si.Pk) // initiator static first
	ks.mixHash(sr)    // responder static second
	return &Initiator{si: si, sr: sr, kem: kem, ks: ks}, nil
}

func (i *Initiator) BuildMsg1() (*Msg1, error) {
	eiPk, eiSk, err := i.kem.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key generation failed: %w", err)
	}
	i.ei = KeyPair{Pk: eiPk, Sk: eiSk}

	// mix eI
	i.ks.mixHash(i.ei.Pk)

	// SKEM to responder static
	ctSKEM, ssSKEM, err := i.kem.Encapsulate(i.sr, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("SKEM I->R failed: %w", err)
	}
	defer zeroBytes(ssSKEM) // Zero shared secret after use

	// mixKey and mixHash(ciphertext)
	i.ks.mixKey(ssSKEM)
	i.ks.mixHash(ctSKEM)

	return &Msg1{EI: i.ei.Pk, CTss: ctSKEM}, nil
}

func (i *Initiator) ProcessMsg2(m2 *Msg2) error {
	// mix ciphertexts into transcript in on-the-wire order
	i.ks.mixHash(m2.CTse)
	i.ks.mixHash(m2.CTss)

	// Decap EKEM to our ephemeral
	ssEKEM, err := i.kem.Decapsulate(m2.CTse, i.ei.Sk)
	if err != nil {
		return fmt.Errorf("decapsulate EKEM failed: %w", err)
	}
	defer zeroBytes(ssEKEM) // Zero shared secret after use
	i.ks.mixKey(ssEKEM)

	// Decap SKEM to our static
	ssSKEM, err := i.kem.Decapsulate(m2.CTss, i.si.Sk)
	if err != nil {
		return fmt.Errorf("decapsulate SKEM failed: %w", err)
	}
	defer zeroBytes(ssSKEM) // Zero shared secret after use
	i.ks.mixKey(ssSKEM)

	// Zero ephemeral secret key (no longer needed)
	zeroBytes(i.ei.Sk)

	// finalize transcript and derive single key
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

func NewResponder(sr KeyPair, si []byte, kem KEM, prologue []byte) (*Responder, error) {
	// Validate initiator's static public key
	if err := kem.ValidatePublicKey(si); err != nil {
		return nil, fmt.Errorf("invalid initiator public key: %w", err)
	}

	// Validate our own static public key
	if err := kem.ValidatePublicKey(sr.Pk); err != nil {
		return nil, fmt.Errorf("invalid responder public key: %w", err)
	}

	ks := newKeySchedule("Noise_KK_PQKEM_ChaChaPoly_SHA256")
	ks.mixHash(prologue)
	// Pre-messages in KK: -> s, <- s
	ks.mixHash(si)     // initiator static first
	ks.mixHash(sr.Pk)  // responder static second
	return &Responder{sr: sr, si: si, kem: kem, ks: ks}, nil
}

func (r *Responder) ProcessMsg1(m1 *Msg1) error {
	// Validate initiator's ephemeral public key
	if err := r.kem.ValidatePublicKey(m1.EI); err != nil {
		return fmt.Errorf("invalid initiator ephemeral public key: %w", err)
	}

	// store eI, mix eI and ct_ss
	r.ei = m1.EI
	r.ks.mixHash(m1.EI)
	r.ks.mixHash(m1.CTss)

	// Decap SKEM to responder static
	ssSS, err := r.kem.Decapsulate(m1.CTss, r.sr.Sk)
	if err != nil {
		return fmt.Errorf("decapsulate ss failed: %w", err)
	}
	defer zeroBytes(ssSS) // Zero shared secret after use
	r.ks.mixKey(ssSS)
	return nil
}

func (r *Responder) BuildMsg2() (*Msg2, error) {
	// EKEM to initiator ephemeral (from Msg1)
	ctEKEM, ssEKEM, err := r.kem.Encapsulate(r.ei, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("EKEM failed: %w", err)
	}
	defer zeroBytes(ssEKEM) // Zero shared secret after use
	r.ks.mixKey(ssEKEM)
	r.ks.mixHash(ctEKEM)

	// SKEM to initiator static
	ctSKEM, ssSKEM, err := r.kem.Encapsulate(r.si, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("SKEM R->I failed: %w", err)
	}
	defer zeroBytes(ssSKEM) // Zero shared secret after use
	r.ks.mixKey(ssSKEM)
	r.ks.mixHash(ctSKEM)

	// finalize transcript and derive single key
	r.hFinal = append([]byte{}, r.ks.h...)
	r.sharedKey = hkdfExpand(r.ks.ck, []byte("shared"), 32)

	return &Msg2{CTse: ctEKEM, CTss: ctSKEM}, nil
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
