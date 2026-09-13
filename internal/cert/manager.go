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
// The host certificate's expiration is clamped to the CA certificate's own
// NotAfter (parsed from CACertPEM), so the host cert can never outlive its CA.
type HostCertParams struct {
	Hostname      string   // Host name for certificate
	OverlayIP     string   // Overlay IP address (e.g., "10.128.0.100")
	Groups        []string // Groups for firewall rules
	ValidityYears int      // Certificate validity period

	// NetworkCIDR is the overlay network this host belongs to, in CIDR form
	// (e.g. "10.128.0.0/24"). REQUIRED: it supplies the mask the certificate's
	// network is signed with, and Nebula builds the host's routing table from
	// that mask. See overlayPrefix.
	NetworkCIDR string

	// UnsafeNetworks are the non-overlay prefixes this host is authorized to
	// route for. Nebula enforces routing on the certificate rather than on
	// config: a gateway whose cert omits the prefix silently refuses to route
	// it, and the packet is dropped before any firewall rule is consulted.
	// Empty for ordinary hosts.
	UnsafeNetworks []netip.Prefix

	CACertPEM       string // CA certificate PEM (for signing)
	CAPrivateKeyPEM string // CA private key PEM (for signing)
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
// - Contains the overlay IP carried at the NETWORK's mask (see overlayPrefix)
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
// - The CA certificate's NotAfter (parsed from the CA cert itself)
// This ensures host certificates don't outlive their signing CA. The bound
// must come from the parsed certificate, not an externally stored timestamp:
// cert NotAfter has whole-second precision, so a stored expiry with sub-second
// precision can land fractionally after the real NotAfter and the signing
// library would reject the host certificate.
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

	// The host's address carried at the OVERLAY network's mask -- not /32.
	// This is what Nebula turns into the tun address and the overlay route.
	network, err := overlayPrefix(params.OverlayIP, params.NetworkCIDR)
	if err != nil {
		return nil, err
	}

	// Calculate expiration - min of requested or the CA cert's own NotAfter
	notBefore := time.Now()
	requestedExpiry := notBefore.AddDate(params.ValidityYears, 0, 0)

	expiresAt := requestedExpiry
	if caNotAfter := caCert.NotAfter(); requestedExpiry.After(caNotAfter) {
		expiresAt = caNotAfter
	}

	// Create TBSCertificate for host
	tbs := &nebulacert.TBSCertificate{
		Version:        nebulacert.Version2,
		Name:           params.Hostname,
		Networks:       []netip.Prefix{network},
		UnsafeNetworks: params.UnsafeNetworks,
		Groups:         params.Groups,
		IsCA:           false,
		NotBefore:      notBefore,
		NotAfter:       expiresAt,
		PublicKey:      pubKey,
		Curve:          nebulacert.Curve_CURVE25519,
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

// overlayPrefix builds the prefix that goes into a host certificate's Networks:
// the host's own address, carried at the OVERLAY NETWORK's mask.
//
// WHY THE MASK IS THE NETWORK'S AND NOT /32:
// Nebula reads the certificate's networks straight onto the tun device. pki.go
// populates myVpnNetworks from crt.Networks(); main.go hands that slice to the
// device factory; overlay/tun_linux.go then adds the interface address with
// net.CIDRMask(prefix.Bits(), ...) and installs a link-scope route for
// prefix.Masked(). So the mask in the certificate IS the host's route to the
// overlay.
//
// A /32 therefore gives a host an address and a route covering only itself.
// The kernel has no route to any peer, so peer traffic never reaches the tun
// and no packet can cross the mesh -- while every certificate, config and
// handshake still looks correct. It also breaks the consumer half of gateway
// routing: Nebula only accepts an unsafe_routes gateway that
// isGatewayInVpnNetworks reports as inside the overlay (overlay/tun_linux.go),
// which a /32 can never satisfy.
//
// Every nebula-cert example upstream signs the host address at the overlay
// mask -- `-networks "192.168.100.10/24"` in the quick start, unsafe_routes and
// cert-v2 guides -- and Nebula's own e2e suite signs "10.128.0.1/24". This
// reproduces that.
//
// PARAMETERS:
//   - overlayIP: the host's address (e.g. "10.128.0.100")
//   - networkCIDR: the overlay network it belongs to (e.g. "10.128.0.0/24")
//
// RETURNS:
// - the host address at the network's mask (e.g. 10.128.0.100/24)
// - error if either value is unparseable, or the address is outside the network
//
// SIDE EFFECTS: None (pure).
func overlayPrefix(overlayIP, networkCIDR string) (netip.Prefix, error) {
	if networkCIDR == "" {
		return netip.Prefix{}, fmt.Errorf("network CIDR is required to size the certificate's network")
	}

	network, err := netip.ParsePrefix(networkCIDR)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid network CIDR %q: %w", networkCIDR, err)
	}

	addr, err := netip.ParseAddr(overlayIP)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid overlay IP %q: %w", overlayIP, err)
	}
	// A 4-in-6 address would not match an IPv4 prefix, and would be signed as
	// IPv6. Unmap so the two are compared, and stored, in the same family.
	addr = addr.Unmap()

	// Not a duplicate of ipam's ValidateHostIP: that runs on the request path,
	// while this also covers the rotation and renewal sweeps, which re-sign
	// records written long ago.
	if !network.Contains(addr) {
		return netip.Prefix{}, fmt.Errorf("overlay IP %s is not inside network %s", addr, network)
	}

	return netip.PrefixFrom(addr, network.Bits()), nil
}

// HostCertNetworkIsStale reports whether a stored host certificate carries a
// different network from the one GenerateHostCert would sign for it today.
//
// WHY THIS IS ONLY A QUESTION AND NEVER AN ACTION:
// Re-signing changes the certificate's fingerprint, and in Nebula a fingerprint
// is what pki.blocklist revokes. Doing that on the library's own initiative
// would move every fingerprint in a fleet at once, and would silently un-revoke
// any host whose old certificate is what peers are blocklisting. So callers
// warn; an operator re-issues, per host, through the `renew` action field.
//
// The comparison is exact rather than mask-only, so it also catches a host
// whose overlay_ip was changed underneath a certificate that was never
// re-signed. Any drift means the same thing: the stored certificate no longer
// describes this host's place in the overlay.
//
// PARAMETERS:
//   - certPEM: the host's stored certificate
//   - overlayIP: the host's current overlay address
//   - networkCIDR: the network's current CIDR range
//
// RETURNS:
// - true if the certificate's network differs from what would be signed now
// - error if the certificate, the address or the CIDR cannot be read
//
// SIDE EFFECTS: None (pure).
func HostCertNetworkIsStale(certPEM, overlayIP, networkCIDR string) (bool, error) {
	if certPEM == "" {
		// Never issued one. There is nothing stale about an absent
		// certificate, and the create hook owns filling it in.
		return false, nil
	}

	want, err := overlayPrefix(overlayIP, networkCIDR)
	if err != nil {
		return false, err
	}

	parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(certPEM))
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	networks := parsed.Networks()
	return len(networks) != 1 || networks[0] != want, nil
}

// FingerprintFromPEM returns the SHA-256 fingerprint of a PEM-encoded
// certificate, in the form Nebula's `pki.blocklist` expects.
//
// This is how a host certificate is revoked. Nebula has no CRL and no OCSP:
// revocation is a list of certificate fingerprints in every OTHER host's
// config, loaded into the CA pool at startup and on SIGHUP
// (nebula/pki.go, reloadCAPool). So "revoke this host" means "add its
// fingerprint to the blocklist of every peer that might handshake with it",
// which is a fan-out rather than a single central write.
//
// The fingerprint is derived from the stored certificate rather than cached in
// a column, because a cached fingerprint is a second copy of what the
// certificate already states and the two diverge the moment a certificate is
// re-issued -- which renewal and CA rotation now both do routinely. Parsing a
// PEM is cheap and the config generator already runs only on change.
//
// SIDE EFFECTS: None (pure).
func FingerprintFromPEM(certPEM string) (string, error) {
	if certPEM == "" {
		return "", fmt.Errorf("certificate is empty")
	}
	parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(certPEM))
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}
	fp, err := parsed.Fingerprint()
	if err != nil {
		return "", fmt.Errorf("failed to fingerprint certificate: %w", err)
	}
	return fp, nil
}

// ValidityFromPEM returns the NotBefore and NotAfter of a PEM-encoded certificate.
//
// WHY THIS EXISTS RATHER THAN READING THE expires_at COLUMN:
// The same reason GenerateHostCert clamps against the parsed CA certificate and
// not the stored timestamp. Certificate timestamps have whole-second precision,
// while a stored date can carry sub-second precision, so the column and the
// certificate can disagree by a fraction of a second -- enough for a renewal
// decision to be made against a value the certificate does not actually hold.
// The certificate is the thing Nebula enforces, so it is the thing to read.
//
// Renewal also needs NotBefore, which is not stored in any column at all: the
// decision is about the FRACTION of the lifetime consumed, so it needs both
// ends.
//
// PARAMETERS:
//   - certPEM: PEM encoded certificate
//
// RETURNS:
// - notBefore, notAfter as recorded in the certificate
// - error if the certificate is empty or does not parse
//
// SIDE EFFECTS: None (pure).
func ValidityFromPEM(certPEM string) (notBefore, notAfter time.Time, err error) {
	if certPEM == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("certificate is empty")
	}

	parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(certPEM))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return parsed.NotBefore(), parsed.NotAfter(), nil
}
