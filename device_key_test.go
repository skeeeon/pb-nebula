package pbnebula_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	nebulacert "github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"

	pbnebula "github.com/skeeeon/pb-nebula"
)

// Device-held keys: the device runs `nebula-cert keygen`, keeps host.key, and
// sends host.pub. These drive real saves through the hooks, because the paths
// the guards cover (the create hook, the peer fan-out, renew, rotation) are
// exactly what a direct call would skip.

// deviceKeyPair makes a host key pair as `nebula-cert keygen` does, returning
// the public key PEM and the raw public key.
func deviceKeyPair(t *testing.T) (string, []byte) {
	t.Helper()
	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return string(nebulacert.MarshalPublicKeyToPEM(nebulacert.Curve_CURVE25519, pub)), pub
}

// newDeviceHost creates a device_key host, with pubPEM or waiting for one.
func newDeviceHost(t *testing.T, app core.App, networkID, hostname, ip, pubPEM string) (string, error) {
	t.Helper()
	hosts, err := app.FindCollectionByNameOrId("nebula_hosts")
	if err != nil {
		t.Fatal(err)
	}
	host := core.NewRecord(hosts)
	host.SetEmail(hostname + "@example.com")
	host.SetPassword("password123")
	host.Set("hostname", hostname)
	host.Set("network_id", networkID)
	host.Set("overlay_ip", ip)
	host.Set("validity_years", 1)
	host.Set("device_key", true)
	host.Set("public_key", pubPEM)
	return host.Id, app.Save(host)
}

func mustNewDeviceHost(t *testing.T, app core.App, networkID, hostname, ip, pubPEM string) string {
	t.Helper()
	id, err := newDeviceHost(t, app, networkID, hostname, ip, pubPEM)
	if err != nil {
		t.Fatalf("create device host %s: %v", hostname, err)
	}
	return id
}

// certPublicKey returns the key a host's stored certificate was signed for.
func certPublicKey(t *testing.T, host *core.Record) []byte {
	t.Helper()
	c, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(host.GetString("certificate")))
	if err != nil {
		t.Fatalf("parse certificate of host %s: %v", host.Id, err)
	}
	return c.PublicKey()
}

// pkiKey returns pki.key from a host's config_yaml.
func pkiKey(t *testing.T, host *core.Record) string {
	t.Helper()
	var cfg struct {
		PKI struct {
			Key string `yaml:"key"`
		} `yaml:"pki"`
	}
	if err := yaml.Unmarshal([]byte(host.GetString("config_yaml")), &cfg); err != nil {
		t.Fatalf("parse config of host %s: %v", host.Id, err)
	}
	return cfg.PKI.Key
}

func wantRefused(t *testing.T, err, target error) {
	t.Helper()
	if err == nil {
		t.Fatalf("save succeeded, want it refused with %q", target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("save refused with %v, want errors.Is(%q)", err, target)
	}
}

// A host waiting for its device holds nothing: no certificate, no config, no
// key. A peer fan-out does not hand it a config with an empty pki.cert, and
// editing it works.
func TestADeviceHostWaitsWithNothing(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	waiting := mustNewDeviceHost(t, app, networkID, "edge", "10.128.0.70", "")

	for _, field := range []string{"certificate", "private_key", "config_yaml"} {
		if got := load(t, app, waiting).GetString(field); got != "" {
			t.Errorf("waiting host %s is not empty", field)
		}
	}

	// A peer's deactivation fans out to every host under the CA.
	peer := newHost(t, app, networkID, "peer", "10.128.0.71")
	mustUpdate(t, app, peer, map[string]any{"active": false})
	if load(t, app, waiting).GetString("config_yaml") != "" {
		t.Error("a peer fan-out rendered a config for a host with no certificate")
	}

	// Edits to a cert field and a config field on the waiting host save.
	mustUpdate(t, app, waiting, map[string]any{"groups": []string{"edge"}})
	mustUpdate(t, app, waiting, map[string]any{"mtu": 1400})
	if load(t, app, waiting).GetString("certificate") != "" {
		t.Error("a waiting host got a certificate with no key to sign")
	}
}

// The key arriving signs a certificate for exactly that key. The config names
// the device's key file, and the platform stores no private key.
func TestADeviceKeyArrivingIsSigned(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	id := mustNewDeviceHost(t, app, networkID, "edge", "10.128.0.72", "")

	pubPEM, pub := deviceKeyPair(t)
	mustUpdate(t, app, id, map[string]any{"public_key": pubPEM})

	host := load(t, app, id)
	if !bytes.Equal(certPublicKey(t, host), pub) {
		t.Fatal("the certificate was not signed for the key the device sent")
	}
	if host.GetString("private_key") != "" {
		t.Error("a device-key host stores a private key")
	}
	if got := pkiKey(t, host); got != pbnebula.DeviceHostKeyPath {
		t.Errorf("pki.key = %q, want the device key path %q", got, pbnebula.DeviceHostKeyPath)
	}
}

// Every re-issue re-signs the same key: renew, and a CA rotation.
func TestADeviceKeyIsResignedNotReplaced(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	pubPEM, pub := deviceKeyPair(t)
	id := mustNewDeviceHost(t, app, networkID, "edge", "10.128.0.73", pubPEM)

	// A certificate carries whole seconds, so a re-sign of the same key inside
	// the same second is byte-identical (see the next test).
	time.Sleep(1100 * time.Millisecond)

	before := fingerprint(t, load(t, app, id))
	mustUpdate(t, app, id, map[string]any{"renew": true})
	host := load(t, app, id)
	if fingerprint(t, host) == before {
		t.Fatal("renew did not re-issue; nothing below proves anything")
	}
	if !bytes.Equal(certPublicKey(t, host), pub) {
		t.Error("renew signed a different key")
	}

	network, err := app.FindRecordById("nebula_networks", networkID)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"prepare", "commit"} {
		ca, err := app.FindRecordById("nebula_ca", network.GetString("ca_id"))
		if err != nil {
			t.Fatal(err)
		}
		ca.Set("rotate", verb)
		if err := app.Save(ca); err != nil {
			t.Fatalf("rotate %s: %v", verb, err)
		}
	}
	host = load(t, app, id)
	if !bytes.Equal(certPublicKey(t, host), pub) {
		t.Error("CA rotation signed a different key")
	}
	if host.GetString("private_key") != "" {
		t.Error("CA rotation stored a private key for a device-key host")
	}
}

// A key arriving on an inactive host is stored and not signed; reactivation
// signs it. The hook already refuses to re-sign an inactive host.
func TestADeviceKeyOnAnInactiveHostWaitsForReactivation(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	id := mustNewDeviceHost(t, app, networkID, "edge", "10.128.0.74", "")
	mustUpdate(t, app, id, map[string]any{"active": false})

	pubPEM, pub := deviceKeyPair(t)
	mustUpdate(t, app, id, map[string]any{"public_key": pubPEM})
	if load(t, app, id).GetString("certificate") != "" {
		t.Fatal("a key arriving on an inactive host was signed")
	}

	mustUpdate(t, app, id, map[string]any{"active": true})
	if !bytes.Equal(certPublicKey(t, load(t, app, id)), pub) {
		t.Error("reactivation did not sign the stored device key")
	}
}

// The invariants. Each "cannot" sits next to a "can" on the same kind of host
// in the tests above.
func TestDeviceKeyInvariants(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)

	enrolledPEM, _ := deviceKeyPair(t)
	enrolled := mustNewDeviceHost(t, app, networkID, "enrolled", "10.128.0.80", enrolledPEM)
	other, _ := deviceKeyPair(t)

	t.Run("write once", func(t *testing.T) {
		wantRefused(t, update(t, app, enrolled, map[string]any{"public_key": other}), pbnebula.ErrDeviceKeyEnrolled)
		wantRefused(t, update(t, app, enrolled, map[string]any{"public_key": ""}), pbnebula.ErrDeviceKeyEnrolled)
	})
	t.Run("frozen", func(t *testing.T) {
		wantRefused(t, update(t, app, enrolled, map[string]any{"device_key": false}), pbnebula.ErrDeviceKeyFrozen)
		platform := newHost(t, app, networkID, "platform", "10.128.0.81")
		wantRefused(t, update(t, app, platform, map[string]any{"device_key": true}), pbnebula.ErrDeviceKeyFrozen)
	})
	t.Run("public_key only on a device host", func(t *testing.T) {
		platform := newHost(t, app, networkID, "platform2", "10.128.0.82")
		wantRefused(t, update(t, app, platform, map[string]any{"public_key": other}), pbnebula.ErrPublicKeyNotDeviceHeld)
	})
	t.Run("no private key", func(t *testing.T) {
		wantRefused(t, update(t, app, enrolled, map[string]any{"private_key": "x"}), pbnebula.ErrDeviceKeyHasSecret)
	})
	t.Run("only an X25519 public key", func(t *testing.T) {
		waiting := mustNewDeviceHost(t, app, networkID, "waiting", "10.128.0.83", "")
		wantRefused(t, update(t, app, waiting, map[string]any{"public_key": "not a key"}), pbnebula.ErrInvalidDeviceKey)

		p256 := string(nebulacert.MarshalPublicKeyToPEM(nebulacert.Curve_P256, append([]byte{4}, make([]byte, 64)...)))
		wantRefused(t, update(t, app, waiting, map[string]any{"public_key": p256}), pbnebula.ErrInvalidDeviceKey)

		// A private key pasted by mistake is refused, not signed.
		priv := string(nebulacert.MarshalPrivateKeyToPEM(nebulacert.Curve_CURVE25519, make([]byte, 32)))
		wantRefused(t, update(t, app, waiting, map[string]any{"public_key": priv}), pbnebula.ErrInvalidDeviceKey)
	})
	t.Run("checked on create too", func(t *testing.T) {
		_, err := newDeviceHost(t, app, networkID, "bad", "10.128.0.84", "not a key")
		wantRefused(t, err, pbnebula.ErrInvalidDeviceKey)
	})
}

// A consumer that creates a waiting host and saves the same object again with
// the key must not be refused: that object's Original() is the blank pre-insert
// snapshot, where device_key looks like it flipped.
func TestADeviceHostCreatedThenSavedAgain(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)

	hosts, err := app.FindCollectionByNameOrId("nebula_hosts")
	if err != nil {
		t.Fatal(err)
	}
	host := core.NewRecord(hosts)
	host.SetEmail("edge@example.com")
	host.SetPassword("password123")
	host.Set("hostname", "edge")
	host.Set("network_id", networkID)
	host.Set("overlay_ip", "10.128.0.90")
	host.Set("device_key", true)
	if err := app.Save(host); err != nil {
		t.Fatalf("create: %v", err)
	}

	pubPEM, pub := deviceKeyPair(t)
	host.Set("public_key", pubPEM)
	if err := app.Save(host); err != nil {
		t.Fatalf("second save of the created object refused: %v", err)
	}
	if !bytes.Equal(certPublicKey(t, load(t, app, host.Id)), pub) {
		t.Error("the key was not signed")
	}
	if strings.Contains(load(t, app, host.Id).GetString("config_yaml"), "PRIVATE KEY") {
		t.Error("the config carries a private key")
	}
}

// Re-signing a device key in the same second gives a byte-identical
// certificate. renew revokes what it replaces, so treating that as a
// replacement put the host's current certificate on every blocklist. Run until
// the renew lands in the same second as the create, which is almost always the
// first try.
func TestARenewInTheSameSecondDoesNotRevokeTheHost(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	peer := newHost(t, app, networkID, "peer", "10.128.0.99")

	for i := 0; i < 5; i++ {
		pubPEM, _ := deviceKeyPair(t)
		id := mustNewDeviceHost(t, app, networkID, "edge"+string(rune('a'+i)), "10.128.0."+string(rune('1'+i)), pubPEM)
		before := fingerprint(t, load(t, app, id))
		mustUpdate(t, app, id, map[string]any{"renew": true})
		after := fingerprint(t, load(t, app, id))
		if after != before {
			continue // crossed a second boundary; try again
		}
		if strings.Contains(load(t, app, peer).GetString("config_yaml"), after) {
			t.Fatal("a same-second renew blocklisted the certificate the host still holds")
		}
		return
	}
	t.Skip("never landed a renew in the same second as its create")
}
