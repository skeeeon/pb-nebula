package cert

import (
	"net/netip"
	"testing"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
)

func TestGenerateCA(t *testing.T) {
	m := NewManager()

	result, err := m.GenerateCA("test-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if result.CertificatePEM == "" {
		t.Error("expected non-empty certificate PEM")
	}
	if result.PrivateKeyPEM == "" {
		t.Error("expected non-empty private key PEM")
	}

	// Parse the certificate back and verify its properties
	caCert, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(result.CertificatePEM))
	if err != nil {
		t.Fatalf("generated CA certificate does not parse: %v", err)
	}
	if !caCert.IsCA() {
		t.Error("expected IsCA to be true")
	}
	if caCert.Name() != "test-ca" {
		t.Errorf("expected name %q, got %q", "test-ca", caCert.Name())
	}

	// Expiration should be ~10 years out
	wantExpiry := time.Now().AddDate(10, 0, 0)
	if diff := result.ExpiresAt.Sub(wantExpiry); diff < -time.Hour || diff > time.Hour {
		t.Errorf("expected expiry near %v, got %v", wantExpiry, result.ExpiresAt)
	}

	// Private key must parse as a signing key
	if _, _, _, err := nebulacert.UnmarshalSigningPrivateKeyFromPEM([]byte(result.PrivateKeyPEM)); err != nil {
		t.Errorf("generated CA private key does not parse: %v", err)
	}
}

func TestGenerateHostCert(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("test-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	result, err := m.GenerateHostCert(HostCertParams{
		Hostname:        "web-01",
		OverlayIP:       "10.128.0.100",
		Groups:          []string{"web", "ssh"},
		ValidityYears:   1,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostCert failed: %v", err)
	}

	hostCert, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(result.CertificatePEM))
	if err != nil {
		t.Fatalf("generated host certificate does not parse: %v", err)
	}
	if hostCert.IsCA() {
		t.Error("expected IsCA to be false for host cert")
	}
	if hostCert.Name() != "web-01" {
		t.Errorf("expected name %q, got %q", "web-01", hostCert.Name())
	}

	// Overlay IP should be embedded as a /32
	wantPrefix := netip.MustParsePrefix("10.128.0.100/32")
	networks := hostCert.Networks()
	if len(networks) != 1 || networks[0] != wantPrefix {
		t.Errorf("expected networks [%v], got %v", wantPrefix, networks)
	}

	// Groups should be embedded
	groups := hostCert.Groups()
	if len(groups) != 2 || groups[0] != "web" || groups[1] != "ssh" {
		t.Errorf("expected groups [web ssh], got %v", groups)
	}

	// Signature must verify against the CA
	caCert, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(ca.CertificatePEM))
	if err != nil {
		t.Fatalf("CA certificate does not parse: %v", err)
	}
	caPool := nebulacert.NewCAPool()
	if err := caPool.AddCA(caCert); err != nil {
		t.Fatalf("failed to add CA to pool: %v", err)
	}
	if _, err := caPool.VerifyCertificate(time.Now(), hostCert); err != nil {
		t.Errorf("host certificate does not verify against its CA: %v", err)
	}
}

// TestGenerateHostCertClampsToCAExpiry guards the invariant that a host
// certificate can never outlive its signing CA.
func TestGenerateHostCertClampsToCAExpiry(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("short-ca", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Request 10 years of validity from a 1-year CA
	result, err := m.GenerateHostCert(HostCertParams{
		Hostname:        "long-host",
		OverlayIP:       "10.0.0.1",
		ValidityYears:   10,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostCert failed: %v", err)
	}

	// The clamp bound is the CA cert's own NotAfter (whole-second precision),
	// not the in-memory ExpiresAt, so compare against the parsed certificate
	caCert, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(ca.CertificatePEM))
	if err != nil {
		t.Fatalf("CA certificate does not parse: %v", err)
	}
	if result.ExpiresAt.After(caCert.NotAfter()) {
		t.Errorf("host cert expiry %v exceeds CA NotAfter %v", result.ExpiresAt, caCert.NotAfter())
	}
	if !result.ExpiresAt.Equal(caCert.NotAfter()) {
		t.Errorf("expected host cert expiry clamped to CA NotAfter %v, got %v", caCert.NotAfter(), result.ExpiresAt)
	}
}

func TestGenerateHostCertInvalidIP(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("test-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	_, err = m.GenerateHostCert(HostCertParams{
		Hostname:        "bad-host",
		OverlayIP:       "not-an-ip",
		ValidityYears:   1,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err == nil {
		t.Error("expected error for invalid overlay IP, got nil")
	}
}
