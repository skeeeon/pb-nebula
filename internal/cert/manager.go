// Package cert provides certificate generation for Nebula mesh VPN
package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
)

// Manager handles generating Nebula certificates for CAs and hosts.
// This is a thin wrapper around the nebula/cert package that provides
// a simpler interface for pb-nebula's needs.
//
// CRYPTO RESPONSIBILITY:
// We don't reimplement cryptography - we use nebula/cert package for all
// certificate generation, signing, and validation. This manager just provides
// a convenient API and handles PEM encoding.
//
// CURVE25519 ONLY:
// For simplicity, we only support CURVE25519 (Ed25519 for signing, X25519 for ECDH).
// This is Nebula's default and recommended curve.
type Manager struct {
	// Stateless - no fields needed
}

// NewManager creates a new certificate manager.
//
// RETURNS:
// - Manager instance ready for certificate operations
func NewManager() *Manager {
	return &Manager{}
}

// CAResult contains the generated CA certificate and keys.
type CAResult struct {
	CertificatePEM string    // PEM encoded CA certificate (public)
	PrivateKeyPEM  string    // PEM encoded CA private key (secret!)
	ExpiresAt      time.Time // Certificate expiration timestamp
}

// HostCertResult contains the generated host certificate and keys.
type HostCertResult struct {
	CertificatePEM string    // PEM encoded host certificate
	PrivateKeyPEM  string    // PEM encoded host private key
	ExpiresAt      time.Time // Certificate expiration timestamp
}

// HostCertParams contains all parameters needed to generate a host certificate.
type HostCertParams struct {
	Hostname        string    // Host name for certificate
	OverlayIP       string    // Overlay IP address (e.g., "10.128.0.100")
	Groups          []string  // Groups for firewall rules
	ValidityYears   int       // Certificate validity period
	CACertPEM       string    // CA certificate PEM (for signing)
	CAPrivateKeyPEM string    // CA private key PEM (for signing)
	CAExpiresAt     time.Time // CA expiration (host cert cannot outlive CA)
}

// GenerateCA creates a new self-signed Nebula CA certificate.
// The CA is the root of trust for all host certificates in the mesh.
//
// CA CHARACTERISTICS:
// - Self-signed (no issuer)
// - IsCA flag set to true
// - No IP networks or groups (CAs don't have these)
// - Long validity period (default 10 years)
//
// KEY GENERATION:
// Uses Ed25519 for signing (64 byte private key, 32 byte public key).
// Keys are generated using crypto/rand for security.
//
// PARAMETERS:
//   - name: Human-readable CA name
//   - validityYears: Certificate validity period
//
// RETURNS:
// - CAResult containing PEM encoded certificate and private key
// - error if key generation or certificate signing fails
//
// SIDE EFFECTS: None (pure generation)
func (m *Manager) GenerateCA(name string, validityYears int) (*CAResult, error) {
	// Generate Ed25519 key pair for CA
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key pair: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	notAfter := notBefore.AddDate(validityYears, 0, 0)

	// Create TBSCertificate (To Be Signed certificate)
	tbs := &nebulacert.TBSCertificate{
		Version:   nebulacert.Version2,
		Name:      name,
		IsCA:      true,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		PublicKey: pubKey,
		Curve:     nebulacert.Curve_CURVE25519,
		// Networks, UnsafeNetworks, Groups are empty for CA
	}

	// Self-sign the CA certificate (signer is nil for self-signed)
	certificate, err := tbs.Sign(nil, nebulacert.Curve_CURVE25519, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CA certificate: %w", err)
	}

	// Marshal to PEM format
	certPEM, err := certificate.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA certificate to PEM: %w", err)
	}

	privKeyPEM := nebulacert.MarshalSigningPrivateKeyToPEM(nebulacert.Curve_CURVE25519, privKey)

	return &CAResult{
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(privKeyPEM),
		ExpiresAt:      notAfter,
	}, nil
}

// GenerateHostCert creates a host certificate signed by the CA.
// Host certificates contain the overlay IP, groups, and are signed by the CA.
//
// HOST CERTIFICATE CHARACTERISTICS:
// - IsCA flag set to false
// - Contains overlay IP as a /32 network
// - Contains groups for firewall rules
// - Signed by CA (contains issuer fingerprint)
// - Validity cannot exceed CA validity
//
// KEY GENERATION:
// Uses Ed25519 for signing (same as CA).
// Each host gets a unique key pair.
//
// VALIDITY CONSTRAINT:
// Host certificate expiration is the minimum of:
// - Requested validity period
// - CA expiration date
// This ensures host certificates don't outlive their signing CA.
//
// PARAMETERS:
//   - params: All parameters needed for host certificate generation
//
// RETURNS:
// - HostCertResult containing PEM encoded certificate and private key
// - error if parsing, key generation, or signing fails
//
// SIDE EFFECTS: None (pure generation)
func (m *Manager) GenerateHostCert(params HostCertParams) (*HostCertResult, error) {
	// Parse CA certificate
	caCert, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(params.CACertPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	caPrivKey, _, _, err := nebulacert.UnmarshalSigningPrivateKeyFromPEM([]byte(params.CAPrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Generate Ed25519 key pair for host
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key pair: %w", err)
	}

	// Parse overlay IP and convert to /32 prefix
	addr, err := netip.ParseAddr(params.OverlayIP)
	if err != nil {
		return nil, fmt.Errorf("invalid overlay IP %q: %w", params.OverlayIP, err)
	}

	// Create /32 prefix from IP (single host)
	overlayPrefix := netip.PrefixFrom(addr, addr.BitLen())

	// Calculate expiration - min of requested or CA expiration
	notBefore := time.Now()
	requestedExpiry := notBefore.AddDate(params.ValidityYears, 0, 0)

	expiresAt := requestedExpiry
	if requestedExpiry.After(params.CAExpiresAt) {
		expiresAt = params.CAExpiresAt
	}

	// Create TBSCertificate for host
	tbs := &nebulacert.TBSCertificate{
		Version:   nebulacert.Version2,
		Name:      params.Hostname,
		Networks:  []netip.Prefix{overlayPrefix},
		Groups:    params.Groups,
		IsCA:      false,
		NotBefore: notBefore,
		NotAfter:  expiresAt,
		PublicKey: pubKey,
		Curve:     nebulacert.Curve_CURVE25519,
	}

	// Sign with CA
	certificate, err := tbs.Sign(caCert, nebulacert.Curve_CURVE25519, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign host certificate: %w", err)
	}

	// Marshal to PEM format
	certPEM, err := certificate.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal host certificate to PEM: %w", err)
	}

	// For host certificates, we use X25519 key format (not Ed25519 signing format)
	// The private key is the same bytes, but the PEM banner is different
	privKeyPEM := nebulacert.MarshalPrivateKeyToPEM(nebulacert.Curve_CURVE25519, privKey[:32])

	return &HostCertResult{
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(privKeyPEM),
		ExpiresAt:      expiresAt,
	}, nil
}
