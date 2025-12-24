package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// generateCAKeypair generates an Ed25519 keypair for signing authorities
func generateCAKeypair() ([]byte, []byte, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// generateNodeKeypair generates an X25519 keypair for nodes (ECDH)
func generateNodeKeypair() ([]byte, []byte, error) {
	privkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		return nil, nil, err
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return pubkey, privkey, nil
}

// Artifacts holds the PEM encoded results of a generation operation
type Artifacts struct {
	CertPEM []byte
	KeyPEM  []byte
}
