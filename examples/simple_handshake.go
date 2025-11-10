package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"quantshake/pkg/handshake"
	"quantshake/pkg/kem"
)

func main() {
	fmt.Println("=== QuantShake Simple Handshake Example ===")
	fmt.Println()

	// Choose a KEM algorithm
	kemAlgo := kem.NewMLKEM768()
	fmt.Printf("Using KEM: %s\n\n", kemAlgo.Name())

	// Generate keypairs for Alice (initiator) and Bob (responder)
	fmt.Println("Generating keypairs...")
	alicePub, aliceSec, err := kemAlgo.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	bobPub, bobSec, err := kemAlgo.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("✓ Alice and Bob have their keypairs")
	fmt.Println()

	// Optional prologue for context binding
	prologue := []byte("example-handshake-v1")

	// Create initiator (Alice) and responder (Bob)
	alice, _ := handshake.NewInitiator(
		handshake.KeyPair{Pk: alicePub, Sk: aliceSec},
		bobPub,
		kemAlgo,
		prologue,
	)

	bob, _ := handshake.NewResponder(
		handshake.KeyPair{Pk: bobPub, Sk: bobSec},
		alicePub,
		kemAlgo,
		prologue,
	)

	// ===== Message 1: Alice -> Bob =====
	fmt.Println("--- Message 1: Alice -> Bob ---")
	msg1, err := alice.BuildMsg1()
	if err != nil {
		log.Fatalf("Alice failed to build Msg1: %v", err)
	}
	fmt.Printf("✓ Alice sends: ephemeral key + 2 KEM ciphertexts\n")
	fmt.Printf("  - Ephemeral key: %d bytes\n", len(msg1.EI))
	fmt.Printf("  - CTss: %d bytes\n\n", len(msg1.CTss))

	// Bob processes Message 1
	if err := bob.ProcessMsg1(msg1); err != nil {
		log.Fatalf("Bob failed to process Msg1: %v", err)
	}
	fmt.Println("✓ Bob processed Message 1")
	fmt.Println()


	// ===== Message 2: Bob -> Alice =====
	fmt.Println("--- Message 2: Bob -> Alice ---")
	msg2, err := bob.BuildMsg2()
	if err != nil {
		log.Fatalf("Bob failed to build Msg2: %v", err)
	}
	fmt.Printf("✓ Bob sends: ephemeral key + 2 KEM ciphertexts\n")
	fmt.Printf("  - CTse: %d bytes\n", len(msg2.CTse))
	fmt.Printf("  - CTss: %d bytes\n\n", len(msg2.CTss))

	// Alice processes Message 2
	if err := alice.ProcessMsg2(msg2); err != nil {
		log.Fatalf("Alice failed to process Msg2: %v", err)
	}
	fmt.Println("✓ Alice processed Message 2")
	fmt.Println("✓ Alice and Bob both derived shared keys")
	fmt.Println()


	// ===== Message 3: Alice -> Bob (Acknowledgment) =====
	fmt.Println("--- Message 3: Alice -> Bob (Acknowledgment) ---")
	msg3, err := alice.BuildMsg3()
	if err != nil {
		log.Fatalf("Alice failed to build Msg3: %v", err)
	}
	fmt.Printf("✓ Alice sends: encrypted handshake hash (%d bytes)\n\n", len(msg3.EncryptedHash))

	// Bob verifies Message 3
	if err := bob.ProcessMsg3(msg3); err != nil {
		log.Fatalf("Bob failed to verify Msg3: %v", err)
	}
	fmt.Println("✓ Bob verified Message 3 - handshake complete!")
	fmt.Println()

	// ===== Verify Shared Keys Match =====
	aliceKey := alice.GetSharedKey()
	bobKey := bob.GetSharedKey()

	fmt.Println("=== Handshake Complete ===")
	fmt.Printf("Alice's shared key: %x\n", aliceKey)
	fmt.Printf("Bob's shared key:   %x\n", bobKey)

	if string(aliceKey) == string(bobKey) {
		fmt.Println("\n✅ SUCCESS: Both parties derived the same 32-byte shared key!")
	} else {
		fmt.Println("\n❌ FAILURE: Keys don't match!")
		log.Fatal("Key mismatch")
	}
}
