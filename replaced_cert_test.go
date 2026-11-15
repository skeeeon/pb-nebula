package pbnebula_test

import (
	"strings"
	"testing"
)

// A re-issue replaces the stored certificate, and pki.blocklist used to be
// built from stored certificates only -- so the certificate a re-issue replaced
// was never refused by anyone and stayed valid until it expired.

// TestAnEditRevokesTheCertificateItReplaces: an admin takes a host out of a
// group. The device that keeps its old config must not keep the group.
func TestAnEditRevokesTheCertificateItReplaces(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	hostID := newHost(t, app, networkID, "edited", "10.128.0.40")
	peerID := newHost(t, app, networkID, "peer", "10.128.0.41")

	mustUpdate(t, app, hostID, map[string]any{"groups": []string{"admin"}})
	withGroup := fingerprint(t, load(t, app, hostID))

	mustUpdate(t, app, hostID, map[string]any{"groups": []string{}})
	without := fingerprint(t, load(t, app, hostID))
	if without == withGroup {
		t.Fatal("removing the group did not re-issue the certificate; nothing below proves anything")
	}

	peer := load(t, app, peerID).GetString("config_yaml")
	if !strings.Contains(peer, withGroup) {
		t.Fatalf("peer does not blocklist %s, the certificate that still carries the removed group", withGroup)
	}
	if strings.Contains(peer, without) {
		t.Fatalf("peer blocklists %s, the host's current certificate", without)
	}
}

// TestRenewRevokesTheCertificateItReplaces: renew is the lever for a leaked
// host key, and a re-issue that leaves the leaked certificate valid fixes
// nothing.
func TestRenewRevokesTheCertificateItReplaces(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	hostID := newHost(t, app, networkID, "renewed", "10.128.0.45")
	peerID := newHost(t, app, networkID, "peer", "10.128.0.46")

	leaked := fingerprint(t, load(t, app, hostID))
	mustUpdate(t, app, hostID, map[string]any{"renew": true})
	fresh := fingerprint(t, load(t, app, hostID))
	if fresh == leaked {
		t.Fatal("renew did not re-issue the certificate; nothing below proves anything")
	}

	peer := load(t, app, peerID).GetString("config_yaml")
	if !strings.Contains(peer, leaked) {
		t.Fatalf("renew left %s, the certificate it replaced, off the peer's blocklist", leaked)
	}
	if strings.Contains(peer, fresh) {
		t.Fatalf("peer blocklists %s, the renewed host's new certificate", fresh)
	}
}

// TestTheRenewalSweepRetiresAndDeactivationRevokes: a routine renewal must
// not cut a host off before it fetches its new certificate, so the old one is
// not listed while the host is active. But the device may still hold it, so
// deactivating the host must list it alongside the current one.
func TestTheRenewalSweepRetiresAndDeactivationRevokes(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	hostID := newHost(t, app, networkID, "swept", "10.128.0.55")
	peerID := newHost(t, app, networkID, "peer", "10.128.0.56")

	// A key that does not pair makes the sweep re-issue a young certificate,
	// which is the only way to make it due without moving the clock.
	breakKey(t, app, hostID)
	before := fingerprint(t, load(t, app, hostID))
	runRenewalSweep(t, app)
	after := fingerprint(t, load(t, app, hostID))
	if after == before {
		t.Fatal("the sweep did not re-issue the host; nothing below proves anything")
	}

	// CANNOT: the renewed host's old certificate is not refused while it is active.
	mustUpdate(t, app, peerID, map[string]any{"mtu": 1400}) // regenerate the peer's config
	if strings.Contains(load(t, app, peerID).GetString("config_yaml"), before) {
		t.Fatalf("the sweep blocklisted %s while the host is active; it is cut off until it fetches", before)
	}

	// CAN: deactivation refuses both.
	mustUpdate(t, app, hostID, map[string]any{"active": false})
	peer := load(t, app, peerID).GetString("config_yaml")
	for _, fp := range []string{before, after} {
		if !strings.Contains(peer, fp) {
			t.Fatalf("deactivation did not blocklist %s; the device may still hold it", fp)
		}
	}
}

// TestRotationRetiresAndFinishClearsTheList: commit must not blocklist the
// certificates it replaces, or a host that has not fetched yet is cut off and
// the three steps buy nothing. A host deactivated between commit and finish
// must have its outgoing-CA certificate refused, since that CA is still
// trusted. After finish nothing the outgoing CA signed is listed: no host can
// verify it, and every entry costs config_yaml bytes.
func TestRotationRetiresAndFinishClearsTheList(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	hostID := newHost(t, app, networkID, "rotated", "10.128.0.60")
	peerID := newHost(t, app, networkID, "peer", "10.128.0.61")

	network, err := app.FindRecordById("nebula_networks", networkID)
	if err != nil {
		t.Fatal(err)
	}
	rotate := func(verb string) {
		t.Helper()
		ca, err := app.FindRecordById("nebula_ca", network.GetString("ca_id"))
		if err != nil {
			t.Fatal(err)
		}
		ca.Set("rotate", verb)
		if err := app.Save(ca); err != nil {
			t.Fatalf("rotate %s: %v", verb, err)
		}
	}

	outgoing := fingerprint(t, load(t, app, hostID))
	rotate("prepare")
	rotate("commit")
	incoming := fingerprint(t, load(t, app, hostID))
	if incoming == outgoing {
		t.Fatal("commit did not re-sign the host; nothing below proves anything")
	}

	// CANNOT: commit does not refuse the outgoing certificate of an active host.
	if strings.Contains(load(t, app, peerID).GetString("config_yaml"), outgoing) {
		t.Fatalf("commit blocklisted %s; a host that has not fetched yet is cut off", outgoing)
	}

	// CAN: deactivating between commit and finish refuses both.
	mustUpdate(t, app, hostID, map[string]any{"active": false})
	peer := load(t, app, peerID).GetString("config_yaml")
	for _, fp := range []string{outgoing, incoming} {
		if !strings.Contains(peer, fp) {
			t.Fatalf("deactivation during the rotation did not blocklist %s", fp)
		}
	}

	// finish drops the outgoing CA, and with it every certificate it signed.
	rotate("finish")
	peer = load(t, app, peerID).GetString("config_yaml")
	if strings.Contains(peer, outgoing) {
		t.Fatalf("after finish the peer still blocklists %s, signed by a CA it no longer trusts", outgoing)
	}
	if !strings.Contains(peer, incoming) {
		t.Fatalf("after finish the peer no longer blocklists %s, the deactivated host's current certificate", incoming)
	}
}

// TestReactivationKeepsTheRevokedCertificateRevoked: a host is deactivated
// after a leak and later brought back. Reactivation re-issues, and the
// certificate that leaked must stay on every blocklist.
func TestReactivationKeepsTheRevokedCertificateRevoked(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	hostID := newHost(t, app, networkID, "leaked", "10.128.0.50")
	peerID := newHost(t, app, networkID, "peer", "10.128.0.51")

	leaked := fingerprint(t, load(t, app, hostID))
	mustUpdate(t, app, hostID, map[string]any{"active": false})
	if !strings.Contains(load(t, app, peerID).GetString("config_yaml"), leaked) {
		t.Fatal("deactivation did not blocklist the certificate; nothing below proves anything")
	}

	mustUpdate(t, app, hostID, map[string]any{"active": true})
	fresh := fingerprint(t, load(t, app, hostID))
	if fresh == leaked {
		t.Fatal("reactivation did not re-issue the certificate")
	}

	peer := load(t, app, peerID).GetString("config_yaml")
	if !strings.Contains(peer, leaked) {
		t.Fatalf("reactivation took %s, the leaked certificate, off the peer's blocklist", leaked)
	}
	if strings.Contains(peer, fresh) {
		t.Fatalf("peer blocklists %s, the reactivated host's new certificate", fresh)
	}
}
