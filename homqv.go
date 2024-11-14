package homqv

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
)

type ID []byte

// Recipient is the other party that accepts the key exchange request.
type Recipient struct {
	id ID
	pk ed25519.PublicKey
}

// NewRecipient creates a new recipient with his ID and public key.
func NewRecipient(id ID, pk ed25519.PublicKey) Recipient {
	return Recipient{id: id, pk: pk}
}

// Client is the party that initiates the key exchange.
type Client struct {
	s *edwards25519.Scalar
}

// NewClient creates a new client with ed25519 private key.
func NewClient(sk ed25519.PrivateKey) Client {
	h := sha512.Sum512(sk.Seed())
	s, _ := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	return Client{s: s}
}

// Connect initiates the key exchange with the recipient, with an ephemeral private key,
// and returns the shared secret.
func (c *Client) Connect(r Recipient, nonce ed25519.PrivateKey) ([]byte, error) {
	A, err := new(edwards25519.Point).SetBytes(r.pk)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	// Recover the scaler from the ed25519 private key
	h0 := sha512.Sum512(nonce.Seed())
	y, _ := edwards25519.NewScalar().SetBytesWithClamping(h0[:32])

	Y := nonce.Public().(ed25519.PublicKey)
	h1 := sha512.Sum512(append(r.id, Y...))
	// e := h(Y, idA)
	e, _ := edwards25519.NewScalar().SetBytesWithClamping(h1[:32])

	// sigma = [A^(y+be)]^f
	b := c.s
	t := edwards25519.NewScalar().MultiplyAdd(b, e, y)
	result := new(edwards25519.Point)
	result.ScalarMult(t, A)
	result.MultByCofactor(result)
	return result.Bytes(), nil
}

// Sender is the other party that requests the key exchange.
type Sender struct {
	pk ed25519.PublicKey
}

// NewSender creates a new sender with his public key.
func NewSender(pk ed25519.PublicKey) Sender {
	return Sender{pk: pk}
}

// Server is the party that accepts the key exchange request.
type Server struct {
	id ID
	s  *edwards25519.Scalar
}

// NewServer creates a new server with an ID and ed25519 private key.
func NewServer(id ID, sk ed25519.PrivateKey) Server {
	h := sha512.Sum512(sk.Seed())
	s, _ := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	return Server{id: id, s: s}
}

// Accept accepts the key exchange request from the sender, with the sender's public nonce,
// and returns the shared secret.
func (s *Server) Accept(sender Sender, nonce ed25519.PublicKey) ([]byte, error) {
	B, err := new(edwards25519.Point).SetBytes(sender.pk)
	if err != nil {
		return nil, fmt.Errorf("invalid sender public key: %w", err)
	}

	Y, err := new(edwards25519.Point).SetBytes(nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid sender nonce: %w", err)
	}

	// e := h(Y, idA)
	h := sha512.Sum512(append(s.id, nonce...))
	e, _ := edwards25519.NewScalar().SetBytesWithClamping(h[:32])

	// sigma = [(YB^e)^a]^f
	a := s.s
	result := new(edwards25519.Point).ScalarMult(e, B)
	result.Add(result, Y)
	result.ScalarMult(a, result)
	result.MultByCofactor(result)

	return result.Bytes(), nil
}
