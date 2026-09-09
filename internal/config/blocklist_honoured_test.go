package config

import (
	"testing"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
	"gopkg.in/yaml.v3"

	"github.com/skeeeon/pb-nebula/internal/cert"
	"github.com/skeeeon/pb-nebula/internal/types"
)

// The blocklist a generated config carries must actually make Nebula's own CA
// pool refuse the certificate.
//
// This is the test that earns the feature. Every other assertion about
// revocation -- the YAML has a `pki.blocklist` key, it holds the right strings
// -- passes whether or not the value is in a form Nebula can use. Nebula
// ignores configuration it does not recognise and its blocklist is compared as
// an opaque string, so a fingerprint computed the wrong way (hashing the PEM
// text, hashing the DER by hand) yields a plausible-looking hex string that
// blocks nothing and reports no error at any layer. Nothing else in this
// repository, and nothing in the platform that consumes it, validates a config
// against Nebula's schema.
//
// It therefore reproduces loadCAPoolFromConfig (nebula/pki.go) using Nebula's
// OWN cert package: NewCAPoolFromPEM on the inline `pki.ca`, then
// BlocklistFingerprint for each `pki.blocklist` entry, then VerifyCertificate.
// Those are the real functions a host runs at startup and on SIGHUP.
//
// The one seam that is not Nebula's own code is reading the two values out of
// the YAML, because importing nebula/config (let alone the root package) would
// add transitive dependencies to a library for the sake of a test. So the paths
// are asserted as the literal strings Nebula reads -- `pki.ca` and
// `pki.blocklist` -- which is the part a refactor could plausibly break.
func TestNebulasCAPoolRefusesABlocklistedCertificate(t *testing.T) {
	m := cert.NewManager()

	ca, err := m.GenerateCA("blocklist-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	newHost := func(name, ip string) *cert.HostCertResult {
		t.Helper()
		h, err := m.GenerateHostCert(cert.HostCertParams{
			Hostname:        name,
			OverlayIP:       ip,
			ValidityYears:   1,
			CACertPEM:       ca.CertificatePEM,
			CAPrivateKeyPEM: ca.PrivateKeyPEM,
		})
		if err != nil {
			t.Fatalf("GenerateHostCert(%s) failed: %v", name, err)
		}
		return h
	}

	// reader stays on the mesh; revoked is the decommissioned device.
	reader := newHost("reader-01", "10.128.0.10")
	revoked := newHost("door-99", "10.128.0.99")

	revokedFP, err := cert.FingerprintFromPEM(revoked.CertificatePEM)
	if err != nil {
		t.Fatalf("FingerprintFromPEM failed: %v", err)
	}

	host := &types.HostRecord{
		ID:            "reader1",
		Hostname:      "reader-01",
		OverlayIP:     "10.128.0.10",
		Certificate:   reader.CertificatePEM,
		PrivateKey:    reader.PrivateKeyPEM,
		CACertificate: ca.CertificatePEM,
	}

	out, err := NewGenerator().GenerateHostConfig(host, testLighthouses(), []string{revokedFP})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}

	// Read pki.ca and pki.blocklist by the exact paths Nebula reads them by.
	var cfg struct {
		PKI struct {
			CA        string   `yaml:"ca"`
			Blocklist []string `yaml:"blocklist"`
		} `yaml:"pki"`
	}
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("generated config is not valid YAML: %v", err)
	}
	if cfg.PKI.CA == "" {
		t.Fatal("pki.ca is empty; Nebula would refuse to start")
	}
	if len(cfg.PKI.Blocklist) != 1 || cfg.PKI.Blocklist[0] != revokedFP {
		t.Fatalf("pki.blocklist = %v, want [%s]", cfg.PKI.Blocklist, revokedFP)
	}

	// Nebula's own CA pool, loaded and blocklisted the way nebula/pki.go does.
	pool, err := nebulacert.NewCAPoolFromPEM([]byte(cfg.PKI.CA))
	if err != nil {
		t.Fatalf("Nebula could not load the generated CA: %v", err)
	}
	for _, fp := range cfg.PKI.Blocklist {
		pool.BlocklistFingerprint(fp)
	}

	parse := func(pem string) nebulacert.Certificate {
		t.Helper()
		parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(pem))
		if err != nil {
			t.Fatalf("certificate does not parse: %v", err)
		}
		return parsed
	}

	now := time.Now()

	if _, err := pool.VerifyCertificate(now, parse(revoked.CertificatePEM)); err == nil {
		t.Error("Nebula accepted the blocklisted certificate: the fingerprint in pki.blocklist " +
			"is not the value Nebula compares against, so a deactivated host is still on the mesh")
	}

	// Paired allow: a certificate that is not on the list must still verify, or
	// the assertion above would pass for a pool that trusts nothing at all.
	if _, err := pool.VerifyCertificate(now, parse(reader.CertificatePEM)); err != nil {
		t.Errorf("Nebula refused a certificate that is not blocklisted: %v", err)
	}
}
