package config

import (
	"testing"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
	"gopkg.in/yaml.v3"

	"github.com/skeeeon/pb-nebula/internal/cert"
	"github.com/skeeeon/pb-nebula/internal/types"
)

// TestNebulasCAPoolAcceptsBothCertificatesInARotationBundle is the test that
// earns three-step CA rotation.
//
// The whole design rests on one property: a config whose pki.ca carries the
// outgoing and incoming CA concatenated lets a host verify peers presenting
// EITHER certificate. If that were false, rotation would split the mesh no
// matter how the steps were ordered, because Nebula verification is mutual --
// each peer checks the other against its own local pool, with no chain and no
// fallback (handshake_manager.go builds the verifier as
// pki.GetCAPool().VerifyCertificate).
//
// A YAML assertion cannot establish that. It would confirm the string we wrote
// is the string we meant to write, which is not the question. So this
// reproduces what nebula/pki.go does at startup -- NewCAPoolFromPEM over the
// generated pki.ca -- and asks the resulting pool to verify real certificates
// signed by each CA.
//
// The paired negative matters as much as the positives: a pool that trusted
// nothing would fail the negative, and a pool that trusted everything would
// pass both positives vacuously. Asserting all three pins it.
func TestNebulasCAPoolAcceptsBothCertificatesInARotationBundle(t *testing.T) {
	m := cert.NewManager()

	outgoing, err := m.GenerateCA("outgoing-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA(outgoing) failed: %v", err)
	}
	incoming, err := m.GenerateCA("incoming-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA(incoming) failed: %v", err)
	}
	// A third, unrelated CA: nothing signed by it should ever verify
	stranger, err := m.GenerateCA("stranger-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA(stranger) failed: %v", err)
	}

	sign := func(name, ip string, ca *cert.CAResult) *cert.HostCertResult {
		t.Helper()
		res, err := m.GenerateHostCert(cert.HostCertParams{
			Hostname:        name,
			OverlayIP:       ip,
			NetworkCIDR:     "10.128.0.0/24",
			ValidityYears:   1,
			CACertPEM:       ca.CertificatePEM,
			CAPrivateKeyPEM: ca.PrivateKeyPEM,
		})
		if err != nil {
			t.Fatalf("GenerateHostCert(%s) failed: %v", name, err)
		}
		return res
	}

	// A host that has not re-signed yet, and one that has
	notYetMigrated := sign("old-host", "10.128.0.20", outgoing)
	migrated := sign("new-host", "10.128.0.21", incoming)
	unrelated := sign("stranger-host", "10.128.0.22", stranger)

	// The bundle the rotation writes: outgoing first, incoming second
	bundle := outgoing.CertificatePEM + "\n" + incoming.CertificatePEM

	host := &types.HostRecord{
		ID:            "bundle-host",
		Hostname:      "bundle-host",
		OverlayIP:     "10.128.0.23",
		Certificate:   migrated.CertificatePEM,
		PrivateKey:    migrated.PrivateKeyPEM,
		CACertificate: incoming.CertificatePEM,
	}

	out, err := NewGenerator().GenerateHostConfig(HostConfigInput{
		Host:        host,
		Lighthouses: testLighthouses(),
		CABundle:    bundle,
	})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}

	// Pin the literal key path Nebula reads, rather than a generic map walk
	var cfg struct {
		PKI struct {
			CA string `yaml:"ca"`
		} `yaml:"pki"`
	}
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("generated config is not valid YAML: %v", err)
	}

	// Reproduce loadCAPoolFromConfig (nebula/pki.go)
	pool, err := nebulacert.NewCAPoolFromPEM([]byte(cfg.PKI.CA))
	if err != nil {
		t.Fatalf("Nebula refused the rotation bundle: %v", err)
	}
	if len(pool.CAs) != 2 {
		t.Fatalf("expected both CAs in the pool, got %d", len(pool.CAs))
	}

	now := time.Now()

	parse := func(pem string) nebulacert.Certificate {
		t.Helper()
		c, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(pem))
		if err != nil {
			t.Fatalf("certificate does not parse: %v", err)
		}
		return c
	}

	// A peer that has not fetched its new certificate yet still verifies
	if _, err := pool.VerifyCertificate(now, parse(notYetMigrated.CertificatePEM)); err != nil {
		t.Errorf("a host still on the outgoing CA must verify during rotation, got: %v", err)
	}

	// A peer that has already been re-signed verifies too
	if _, err := pool.VerifyCertificate(now, parse(migrated.CertificatePEM)); err != nil {
		t.Errorf("a host already on the incoming CA must verify during rotation, got: %v", err)
	}

	// Paired negative, so neither positive can pass vacuously
	if _, err := pool.VerifyCertificate(now, parse(unrelated.CertificatePEM)); err == nil {
		t.Error("a certificate from an unrelated CA must NOT verify against the rotation bundle")
	}
}

// TestRotationBundleStillHonoursTheBlocklist checks the two features compose.
//
// Rotation widens what a pool trusts; revocation narrows it. They touch the
// same pki block, and a bundle that quietly restored trust in a revoked
// certificate would be the worst possible interaction -- so assert that a
// blocklisted host stays refused while both CAs are trusted.
func TestRotationBundleStillHonoursTheBlocklist(t *testing.T) {
	m := cert.NewManager()

	outgoing, err := m.GenerateCA("rev-outgoing", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	incoming, err := m.GenerateCA("rev-incoming", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// A host deactivated before the rotation keeps its outgoing-CA certificate:
	// the commit sweep skips inactive hosts precisely so this fingerprint stays
	// the one every peer blocklists.
	revoked, err := m.GenerateHostCert(cert.HostCertParams{
		Hostname: "revoked-host", OverlayIP: "10.128.0.30", NetworkCIDR: "10.128.0.0/24", ValidityYears: 1,
		CACertPEM: outgoing.CertificatePEM, CAPrivateKeyPEM: outgoing.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostCert failed: %v", err)
	}
	revokedFP, err := cert.FingerprintFromPEM(revoked.CertificatePEM)
	if err != nil {
		t.Fatalf("FingerprintFromPEM failed: %v", err)
	}

	// A healthy host re-signed under the incoming CA
	healthy, err := m.GenerateHostCert(cert.HostCertParams{
		Hostname: "healthy-host", OverlayIP: "10.128.0.31", NetworkCIDR: "10.128.0.0/24", ValidityYears: 1,
		CACertPEM: incoming.CertificatePEM, CAPrivateKeyPEM: incoming.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostCert failed: %v", err)
	}

	host := &types.HostRecord{
		ID: "h", Hostname: "h", OverlayIP: "10.128.0.32",
		Certificate: healthy.CertificatePEM, PrivateKey: healthy.PrivateKeyPEM,
		CACertificate: incoming.CertificatePEM,
	}

	out, err := NewGenerator().GenerateHostConfig(HostConfigInput{
		Host:        host,
		Lighthouses: testLighthouses(),
		Blocklist:   []string{revokedFP},
		CABundle:    outgoing.CertificatePEM + "\n" + incoming.CertificatePEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}

	var cfg struct {
		PKI struct {
			CA        string   `yaml:"ca"`
			Blocklist []string `yaml:"blocklist"`
		} `yaml:"pki"`
	}
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("generated config is not valid YAML: %v", err)
	}

	pool, err := nebulacert.NewCAPoolFromPEM([]byte(cfg.PKI.CA))
	if err != nil {
		t.Fatalf("Nebula refused the rotation bundle: %v", err)
	}
	for _, fp := range cfg.PKI.Blocklist {
		pool.BlocklistFingerprint(fp)
	}

	now := time.Now()
	parse := func(pem string) nebulacert.Certificate {
		t.Helper()
		c, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(pem))
		if err != nil {
			t.Fatalf("certificate does not parse: %v", err)
		}
		return c
	}

	if _, err := pool.VerifyCertificate(now, parse(revoked.CertificatePEM)); err == nil {
		t.Error("a revoked certificate must stay refused even though its CA is still in the bundle")
	}
	if _, err := pool.VerifyCertificate(now, parse(healthy.CertificatePEM)); err != nil {
		t.Errorf("a healthy host must still verify alongside the blocklist, got: %v", err)
	}
}
