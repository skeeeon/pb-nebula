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
		NetworkCIDR:     "10.128.0.0/24",
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

	// Overlay IP should be embedded at the NETWORK's mask, not /32
	wantPrefix := netip.MustParsePrefix("10.128.0.100/24")
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
		NetworkCIDR:     "10.0.0.0/24",
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
		NetworkCIDR:     "10.128.0.0/24",
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
		NetworkCIDR:     "10.128.0.0/24",
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
			NetworkCIDR:     "10.128.0.0/24",
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
		NetworkCIDR:     "10.128.0.0/24",
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
		NetworkCIDR:     "10.128.0.0/24",
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

// TestValidityFromPEMMatchesTheCertificate checks the renewal decision reads
// the same window Nebula enforces.
//
// This has to come from the parsed certificate rather than a stored column: the
// certificate carries whole-second precision while a stored timestamp can carry
// sub-second precision, so the two can disagree by a fraction of a second --
// exactly the mismatch that already forced GenerateHostCert to clamp against
// the parsed CA rather than the expires_at value.
func TestValidityFromPEMMatchesTheCertificate(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("validity-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	result, err := m.GenerateHostCert(HostCertParams{
		Hostname:        "validity-01",
		OverlayIP:       "10.128.0.11",
		NetworkCIDR:     "10.128.0.0/24",
		ValidityYears:   1,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostCert failed: %v", err)
	}

	notBefore, notAfter, err := ValidityFromPEM(result.CertificatePEM)
	if err != nil {
		t.Fatalf("ValidityFromPEM failed: %v", err)
	}

	parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(result.CertificatePEM))
	if err != nil {
		t.Fatalf("certificate does not parse: %v", err)
	}
	if !notBefore.Equal(parsed.NotBefore()) {
		t.Errorf("notBefore: got %v, want %v", notBefore, parsed.NotBefore())
	}
	if !notAfter.Equal(parsed.NotAfter()) {
		t.Errorf("notAfter: got %v, want %v", notAfter, parsed.NotAfter())
	}

	// Whole-second precision is the property that makes reading the column
	// unsafe, so assert it rather than assuming it
	if notAfter.Nanosecond() != 0 {
		t.Errorf("expected whole-second precision in the certificate, got %v", notAfter)
	}
	if !notAfter.After(notBefore) {
		t.Errorf("expected a positive validity window, got %v to %v", notBefore, notAfter)
	}
}

func TestValidityFromPEMRejectsGarbage(t *testing.T) {
	if _, _, err := ValidityFromPEM(""); err == nil {
		t.Error("expected an error for an empty certificate")
	}
	if _, _, err := ValidityFromPEM("not a pem"); err == nil {
		t.Error("expected an error for a malformed certificate")
	}
}

// TestGenerateHostCertCarriesTheOverlayNetworkMask is the guard against
// re-introducing /32 host certificates.
//
// Nebula does not treat a certificate's network as "this host's address". It
// reads the prefix straight onto the tun device: pki.go fills myVpnNetworks
// from crt.Networks(), main.go hands that to the device factory, and
// overlay/tun_linux.go adds the interface address with
// net.CIDRMask(prefix.Bits(), ...) and installs a link-scope route for
// prefix.Masked(). The mask in the certificate IS the host's route to the
// overlay.
//
// So a /32 certificate produces a host whose only route is to itself. Nothing
// reports an error -- the certificate verifies, the config renders, the
// handshake completes -- but the kernel never hands peer traffic to the tun and
// no packet crosses the mesh. Every nebula-cert example upstream signs at the
// overlay mask, and Nebula's own e2e suite signs "10.128.0.1/24".
//
// The second assertion is the one that would have caught the bug: Contains is
// the predicate both the kernel route and Nebula's own isGatewayInVpnNetworks
// evaluate, and a /32 fails it for every peer.
func TestGenerateHostCertCarriesTheOverlayNetworkMask(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("mask-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cases := []struct {
		network string
		ip      string
		peer    string
	}{
		{"10.128.0.0/24", "10.128.0.5", "10.128.0.6"},
		{"10.128.0.0/16", "10.128.4.5", "10.128.9.9"},
		{"192.168.100.0/22", "192.168.100.10", "192.168.102.1"},
	}

	for _, tc := range cases {
		result, err := m.GenerateHostCert(HostCertParams{
			Hostname:        "host",
			OverlayIP:       tc.ip,
			NetworkCIDR:     tc.network,
			ValidityYears:   1,
			CACertPEM:       ca.CertificatePEM,
			CAPrivateKeyPEM: ca.PrivateKeyPEM,
		})
		if err != nil {
			t.Fatalf("GenerateHostCert(%s in %s) failed: %v", tc.ip, tc.network, err)
		}

		parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(result.CertificatePEM))
		if err != nil {
			t.Fatalf("generated certificate does not parse: %v", err)
		}

		networks := parsed.Networks()
		if len(networks) != 1 {
			t.Fatalf("expected exactly one network in the certificate, got %v", networks)
		}

		want := netip.PrefixFrom(netip.MustParseAddr(tc.ip), netip.MustParsePrefix(tc.network).Bits())
		if networks[0] != want {
			t.Errorf("expected network %v, got %v", want, networks[0])
		}

		// The host must be able to route to its peers. This is the property a
		// /32 silently destroys.
		peer := netip.MustParseAddr(tc.peer)
		if !networks[0].Contains(peer) {
			t.Errorf("certificate network %v does not cover peer %v -- this host cannot route to the mesh",
				networks[0], peer)
		}

		// Paired negative: the prefix this code used to emit covers nothing.
		single := netip.PrefixFrom(networks[0].Addr(), networks[0].Addr().BitLen())
		if single.Contains(peer) {
			t.Errorf("a single-address prefix %v unexpectedly covers %v; the test proves nothing", single, peer)
		}
	}
}

// TestGenerateHostCertRejectsAnIPOutsideItsNetwork keeps the signing path from
// minting a certificate whose address is not covered by its own mask. ipam
// validates this on the request path, but the rotation and renewal sweeps
// re-sign records written long before, so the check belongs here too.
func TestGenerateHostCertRejectsAnIPOutsideItsNetwork(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("outside-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	_, err = m.GenerateHostCert(HostCertParams{
		Hostname:        "stray",
		OverlayIP:       "10.200.0.5",
		NetworkCIDR:     "10.128.0.0/24",
		ValidityYears:   1,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err == nil {
		t.Error("expected an error for an overlay IP outside the network, got nil")
	}
}

// TestGenerateHostCertRequiresANetworkCIDR refuses to guess a mask. Falling
// back to /32 is what shipped before, and it fails silently at runtime; an
// error at signing time is the only failure mode an operator can act on.
func TestGenerateHostCertRequiresANetworkCIDR(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("nocidr-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	_, err = m.GenerateHostCert(HostCertParams{
		Hostname:        "unmasked",
		OverlayIP:       "10.128.0.5",
		ValidityYears:   1,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err == nil {
		t.Error("expected an error when NetworkCIDR is missing, got nil")
	}
}

// TestHostCertNetworkIsStale covers the predicate the bootstrap audit warns
// on. It has to be exact in both directions: a false positive tells an operator
// to re-issue a fleet for nothing, and a false negative leaves hosts unable to
// route while every screen says they are fine.
func TestHostCertNetworkIsStale(t *testing.T) {
	m := NewManager()

	ca, err := m.GenerateCA("stale-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	sign := func(ip, cidr string) string {
		t.Helper()
		res, err := m.GenerateHostCert(HostCertParams{
			Hostname:        "host",
			OverlayIP:       ip,
			NetworkCIDR:     cidr,
			ValidityYears:   1,
			CACertPEM:       ca.CertificatePEM,
			CAPrivateKeyPEM: ca.PrivateKeyPEM,
		})
		if err != nil {
			t.Fatalf("GenerateHostCert(%s in %s) failed: %v", ip, cidr, err)
		}
		return res.CertificatePEM
	}

	current := sign("10.128.0.5", "10.128.0.0/24")

	tests := []struct {
		name       string
		certPEM    string
		overlayIP  string
		cidr       string
		wantStale  bool
		wantErrors bool
	}{
		{
			name:      "a freshly signed certificate is current",
			certPEM:   current,
			overlayIP: "10.128.0.5",
			cidr:      "10.128.0.0/24",
		},
		{
			// The upgrade case: the network widened, or the certificate
			// predates the mask fix.
			name:      "a different mask is stale",
			certPEM:   current,
			overlayIP: "10.128.0.5",
			cidr:      "10.128.0.0/16",
			wantStale: true,
		},
		{
			// overlay_ip edited without a re-sign.
			name:      "a different address is stale",
			certPEM:   sign("10.128.0.9", "10.128.0.0/24"),
			overlayIP: "10.128.0.5",
			cidr:      "10.128.0.0/24",
			wantStale: true,
		},
		{
			// Mid-creation. Nothing to warn about, and warning would fire on
			// every host the moment it is created.
			name:      "no certificate yet is not stale",
			certPEM:   "",
			overlayIP: "10.128.0.5",
			cidr:      "10.128.0.0/24",
		},
		{
			name:       "an unreadable certificate is an error, not a verdict",
			certPEM:    "-----BEGIN NEBULA CERTIFICATE-----\nnope\n-----END NEBULA CERTIFICATE-----\n",
			overlayIP:  "10.128.0.5",
			cidr:       "10.128.0.0/24",
			wantErrors: true,
		},
		{
			name:       "an unreadable network CIDR is an error, not a verdict",
			certPEM:    current,
			overlayIP:  "10.128.0.5",
			cidr:       "not-a-cidr",
			wantErrors: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stale, err := HostCertNetworkIsStale(tc.certPEM, tc.overlayIP, tc.cidr)
			if tc.wantErrors {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("HostCertNetworkIsStale failed: %v", err)
			}
			if stale != tc.wantStale {
				t.Errorf("expected stale=%v, got %v", tc.wantStale, stale)
			}
		})
	}
}
