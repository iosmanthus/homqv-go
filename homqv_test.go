package homqv

import (
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
