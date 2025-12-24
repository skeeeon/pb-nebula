package crypto

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

// GenerateAuthority creates a new self-signed CA for a specific CIDR
func GenerateAuthority(name string, cidr string) (*Artifacts, error) {
	// 1. Parse Network
	ipNet, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr: %w", err)
	}

	// 2. Generate Keys (Ed25519 for CA)
	pub, priv, err := generateCAKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ca keys: %w", err)
	}

	// 3. Create TBS (To Be Signed) Template
	// We use Version 2 (ASN.1) and Curve25519 defaults
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      name,
		Networks:  []netip.Prefix{ipNet},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(time.Hour * 87600), // ~10 years
		PublicKey: pub,
		IsCA:      true,
		Curve:     cert.Curve_CURVE25519,
	}

	// 4. Self-Sign
	caCert, err := tbs.Sign(nil, cert.Curve_CURVE25519, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ca cert: %w", err)
	}

	// 5. Marshal to PEM
	certPEM, err := caCert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cert pem: %w", err)
	}

	// Marshal private key (Plaintext per requirement)
	keyPEM := cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, priv)

	return &Artifacts{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}
