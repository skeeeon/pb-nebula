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

// The fingerprint must match what nebula's own CA pool computes, because that
// is the value `pki.blocklist` is compared against at handshake time. Deriving
// it any other way -- hashing the PEM text, hashing the DER by hand -- produces
// a string that looks plausible, blocks nothing, and reports no error.
func TestFingerprintFromPEMMatchesNebulasOwnValue(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("fp-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	host, err := m.GenerateHostCert(HostCertParams{
		Hostname:        "door-01",
		OverlayIP:       "10.128.0.7",
		ValidityYears:   1,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostCert failed: %v", err)
	}

	got, err := FingerprintFromPEM(host.CertificatePEM)
	if err != nil {
		t.Fatalf("FingerprintFromPEM failed: %v", err)
	}

	parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(host.CertificatePEM))
	if err != nil {
		t.Fatalf("host certificate does not parse: %v", err)
	}
	want, err := parsed.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	if got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
	if got == "" {
		t.Error("fingerprint is empty; a blocklist of empty strings blocks nothing")
	}
}

// Two different hosts must not share a fingerprint, or blocklisting one would
// take the other off the mesh with it.
func TestFingerprintFromPEMIsPerCertificate(t *testing.T) {
	m := NewManager()
	ca, err := m.GenerateCA("fp-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	fps := make(map[string]string)
	for _, name := range []string{"door-01", "door-02"} {
		host, err := m.GenerateHostCert(HostCertParams{
			Hostname:        name,
			OverlayIP:       "10.128.0.7",
			ValidityYears:   1,
			CACertPEM:       ca.CertificatePEM,
			CAPrivateKeyPEM: ca.PrivateKeyPEM,
		})
		if err != nil {
			t.Fatalf("GenerateHostCert(%s) failed: %v", name, err)
		}
		fp, err := FingerprintFromPEM(host.CertificatePEM)
		if err != nil {
			t.Fatalf("FingerprintFromPEM(%s) failed: %v", name, err)
		}
		if prev, dup := fps[fp]; dup {
			t.Fatalf("%s and %s share fingerprint %s", prev, name, fp)
		}
		fps[fp] = name
	}
}

func TestFingerprintFromPEMRejectsGarbage(t *testing.T) {
	if _, err := FingerprintFromPEM(""); err == nil {
		t.Error("expected an error for an empty certificate")
	}
	if _, err := FingerprintFromPEM("not a pem"); err == nil {
		t.Error("expected an error for a non-PEM string")
	}
}

// TestGenerateHostCertCarriesUnsafeNetworks reads the prefixes back out of the
// signed certificate using Nebula's own parser.
//
// This matters more than a struct-field assertion would suggest. Nebula
// authorizes routing on the CERTIFICATE, not on config: a gateway whose cert
// omits the prefix silently refuses to route it and the packet is dropped
// before any firewall rule is consulted. There is no error and no log line, so
// a prefix that fails to reach the cert looks exactly like a LAN outage.
func TestGenerateHostCertCarriesUnsafeNetworks(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("gateway-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	want := []netip.Prefix{
		netip.MustParsePrefix("192.168.50.0/24"),
		netip.MustParsePrefix("172.16.0.0/16"),
	}

	result, err := m.GenerateHostCert(HostCertParams{
		Hostname:        "gateway-01",
		OverlayIP:       "10.128.0.5",
		ValidityYears:   1,
		UnsafeNetworks:  want,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostCert failed: %v", err)
	}

	parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(result.CertificatePEM))
	if err != nil {
		t.Fatalf("generated certificate does not parse: %v", err)
	}

	got := parsed.UnsafeNetworks()
	if len(got) != len(want) {
		t.Fatalf("expected %d unsafe networks in the certificate, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("unsafe network %d: got %v, want %v", i, got[i], want[i])
		}
	}

	// The overlay IP must still be the host's own address, not widened by the
	// unsafe networks -- Nebula builds one routing table from both
	networks := parsed.Networks()
	if len(networks) != 1 || networks[0].Addr().String() != "10.128.0.5" {
		t.Errorf("expected exactly the overlay /32, got %v", networks)
	}
}

// TestGenerateHostCertOmitsUnsafeNetworksWhenUnset is the paired negative: an
// ordinary host must not acquire routing authority it never asked for.
func TestGenerateHostCertOmitsUnsafeNetworksWhenUnset(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("plain-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	result, err := m.GenerateHostCert(HostCertParams{
		Hostname:        "plain-01",
		OverlayIP:       "10.128.0.6",
		ValidityYears:   1,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostCert failed: %v", err)
	}

	parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(result.CertificatePEM))
	if err != nil {
		t.Fatalf("generated certificate does not parse: %v", err)
	}

	if got := parsed.UnsafeNetworks(); len(got) != 0 {
		t.Errorf("expected no unsafe networks on an ordinary host, got %v", got)
	}
}
