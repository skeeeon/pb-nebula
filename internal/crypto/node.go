package crypto

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

// GenerateNode creates a new Node certificate signed by the provided CA
func GenerateNode(caCertPEM, caKeyPEM []byte, name string, ip string, groups []string) (*Artifacts, error) {
	// 1. Parse and Validate Inputs
	nodeIP, err := netip.ParsePrefix(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid node ip: %w", err)
	}

	// 2. Load CA Credentials
	// Note: We use UnmarshalSigningPrivateKeyFromPEM because CA keys are Ed25519 signing keys
	caKey, _, _, err := cert.UnmarshalSigningPrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ca key: %w", err)
	}

	caCert, _, err := cert.UnmarshalCertificateFromPEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ca cert: %w", err)
	}

	// 3. Validate CA validity
	if caCert.Expired(time.Now()) {
		return nil, fmt.Errorf("ca certificate is expired")
	}

	// 4. Generate Node Keys (X25519 for Encryption)
	nodePub, nodePriv, err := generateNodeKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate node keys: %w", err)
	}

	// 5. Create TBS Template
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      name,
		Networks:  []netip.Prefix{nodeIP},
		Groups:    groups,
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  caCert.NotAfter().Add(-1 * time.Second), // Expire just before CA
		PublicKey: nodePub,
		IsCA:      false,
		Curve:     cert.Curve_CURVE25519,
	}

	// 6. Sign with CA Key
	nodeCert, err := tbs.Sign(caCert, cert.Curve_CURVE25519, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign node cert: %w", err)
	}

	// 7. Marshal
	certPEM, err := nodeCert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node cert: %w", err)
	}

	// Marshal private key (X25519 Private Key Banner)
	keyPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, nodePriv)

	return &Artifacts{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}
