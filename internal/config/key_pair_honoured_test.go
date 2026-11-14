package config

import (
	"testing"

	nebulacert "github.com/slackhq/nebula/cert"

	"github.com/skeeeon/pb-nebula/internal/cert"
	"github.com/skeeeon/pb-nebula/internal/types"
)

// A generated config must carry a certificate and private key that Nebula will
// start on.
//
// Nebula's loadCertificateFromConfig (nebula/pki.go) reads `pki.cert` and
// `pki.key`, parses both, and refuses to start unless VerifyPrivateKey accepts
// the pair. This test replays those steps with Nebula's OWN cert package on the
// YAML the generator writes, the same approach and for the same reason as
// TestNebulasCAPoolRefusesABlocklistedCertificate: no other assertion here
// fails when the key is the wrong kind. Every host key pb-nebula issued before
// host keys became X25519 failed this check, and nothing noticed.
func TestNebulaStartsOnTheGeneratedCertificateAndKey(t *testing.T) {
	m := cert.NewManager()

	ca, err := m.GenerateCA("pair-ca", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	h, err := m.GenerateHostCert(cert.HostCertParams{
		Hostname:        "gw-01",
		OverlayIP:       "10.128.0.30",
		NetworkCIDR:     "10.128.0.0/24",
		ValidityYears:   1,
		CACertPEM:       ca.CertificatePEM,
		CAPrivateKeyPEM: ca.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("GenerateHostCert failed: %v", err)
	}

	host := &types.HostRecord{
		ID:            "gw1",
		Hostname:      "gw-01",
		OverlayIP:     "10.128.0.30",
		Certificate:   h.CertificatePEM,
		PrivateKey:    h.PrivateKeyPEM,
		CACertificate: ca.CertificatePEM,
	}
	out, err := NewGenerator().GenerateHostConfig(HostConfigInput{Host: host, Lighthouses: testLighthouses()})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}

	pki, ok := parseConfig(t, out)["pki"].(map[string]interface{})
	if !ok {
		t.Fatal("pki section missing or not a map")
	}
	certPEM, _ := pki["cert"].(string)
	keyPEM, _ := pki["key"].(string)
	if certPEM == "" || keyPEM == "" {
		t.Fatalf("pki.cert or pki.key is empty or not inline PEM (cert %d bytes, key %d bytes)", len(certPEM), len(keyPEM))
	}

	// What Nebula does at startup, in order.
	c, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(certPEM))
	if err != nil {
		t.Fatalf("Nebula cannot parse pki.cert: %v", err)
	}
	key, _, curve, err := nebulacert.UnmarshalPrivateKeyFromPEM([]byte(keyPEM))
	if err != nil {
		t.Fatalf("Nebula cannot parse pki.key: %v", err)
	}
	if curve != c.Curve() {
		t.Fatalf("pki.key is curve %v but pki.cert is %v", curve, c.Curve())
	}
	if err := c.VerifyPrivateKey(curve, key); err != nil {
		t.Fatalf("Nebula would refuse to start: %v", err)
	}
}
