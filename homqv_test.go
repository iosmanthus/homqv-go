package homqv

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAgreement(t *testing.T) {
	// Alice published her email
	aliceID := ID("alicetaylor@gmail.com")

	// Alice generates a long-term ed25519 key pair
	A, a, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)

	// Bob generates a long-term ed25519 key pair
	B, b, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)

	// And generate an ephemeral key pair (Y, y)
	Y, y, err := ed25519.GenerateKey(rand.Reader)

	// Bob connects to Alice
	client := NewClient(b)
	sharedB, err := client.Connect(NewRecipient(aliceID, A), y)
	assert.Nil(t, err)

	// Alice accepts Bob
	server := NewServer(aliceID, a)
	sharedA, err := server.Accept(NewSender(B), Y)
	assert.Nil(t, err)

	// Bob and Alice should have the same shared secret
	// It could be used to derive a symmetric key for encryption
	assert.Equal(t, sharedB, sharedA)
}

func BenchmarkAgreement(bm *testing.B) {
	// Alice published her email
	aliceID := ID("alicetaylor@gmail.com")

	// Alice generates a long-term ed25519 key pair
	A, a, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(bm, err)

	// Bob generates a long-term ed25519 key pair
	B, b, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(bm, err)

	// And generate an ephemeral key pair (Y, y)
	Y, y, err := ed25519.GenerateKey(rand.Reader)

	// Bob connects to Alice
	client := NewClient(b)
	// Alice accepts Bob
	server := NewServer(aliceID, a)

	bm.Run("Connect", func(bm *testing.B) {
		for i := 0; i < bm.N; i++ {
			_, _ = client.Connect(NewRecipient(aliceID, A), y)
		}
	})

	bm.Run("Accept", func(bm *testing.B) {
		for i := 0; i < bm.N; i++ {
			_, _ = server.Accept(NewSender(B), Y)
		}
	})

	skB, err := ecdh.X25519().GenerateKey(rand.Reader)
	skA, err := ecdh.X25519().GenerateKey(rand.Reader)
	// Initialize the public key
	_ = skA.PublicKey()
	assert.Nil(bm, err)
	// Compare with simple ECDH
	bm.Run("ECDH", func(bm *testing.B) {
		for i := 0; i < bm.N; i++ {
			_, _ = skB.ECDH(skA.PublicKey())
		}
	})
}
