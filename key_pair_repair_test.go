package pbnebula_test

import (
	"crypto/rand"
	"testing"

	"ganigeorgiev.com/pocketbase/dbx"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	nebulacert "github.com/slackhq/nebula/cert"

	"github.com/skeeeon/pb-nebula/internal/cert"
	"github.com/skeeeon/pb-nebula/internal/types"
)

// Every host key pb-nebula issued before host keys became X25519 fails the
// check Nebula runs before it starts. The renewal sweep re-issues those hosts,
// so an upgraded deployment repairs itself; it must leave a healthy host and a
// revoked one alone.
func TestRenewalSweepReissuesAHostWhoseKeyDoesNotPair(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)

	broken := newHost(t, app, networkID, "broken", "10.128.0.11")
	healthy := newHost(t, app, networkID, "healthy", "10.128.0.12")
	revoked := newHost(t, app, networkID, "revoked", "10.128.0.13")
	mustUpdate(t, app, revoked, map[string]any{"active": false})

	// A new install issues pairs Nebula accepts.
	if !pairs(t, load(t, app, healthy)) {
		t.Fatal("a newly created host's key does not pair with its certificate")
	}

	// Put a key that does not belong to the certificate on two hosts, as an
	// older pb-nebula left them. Written with SQL so no hook repairs it first.
	breakKey(t, app, broken)
	breakKey(t, app, revoked)
	if pairs(t, load(t, app, broken)) {
		t.Fatal("breakKey left a pairing key; nothing below would prove anything")
	}

	brokenFP := fingerprint(t, load(t, app, broken))
	healthyFP := fingerprint(t, load(t, app, healthy))
	revokedFP := fingerprint(t, load(t, app, revoked))

	runRenewalSweep(t, app)

	// CAN: the active host with a broken pair is re-issued, with a pair that works.
	after := load(t, app, broken)
	if fingerprint(t, after) == brokenFP {
		t.Fatal("the sweep did not re-issue an active host whose key does not pair")
	}
	if !pairs(t, after) {
		t.Fatal("the sweep re-issued the host, but its new key still does not pair")
	}

	// CANNOT: a healthy young certificate is left alone.
	if fingerprint(t, load(t, app, healthy)) != healthyFP {
		t.Fatal("the sweep re-issued a healthy host; it must re-sign only what is broken or due")
	}

	// CANNOT: a revoked host is left alone, broken key and all. Re-issuing it
	// would move the fingerprint the blocklist revokes.
	if fingerprint(t, load(t, app, revoked)) != revokedFP {
		t.Fatal("the sweep re-issued an INACTIVE host, which un-revokes it")
	}
}

func pairs(t *testing.T, host *core.Record) bool {
	t.Helper()
	ok, err := cert.HostKeyPairs(host.GetString("certificate"), host.GetString("private_key"))
	if err != nil {
		t.Fatalf("check key pair of host %s: %v", host.Id, err)
	}
	return ok
}

// breakKey stores a random X25519 key that belongs to no certificate.
func breakKey(t *testing.T, app core.App, id string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	keyPEM := string(nebulacert.MarshalPrivateKeyToPEM(nebulacert.Curve_CURVE25519, raw))
	if _, err := app.DB().NewQuery("UPDATE nebula_hosts SET private_key = {:k} WHERE id = {:id}").
		Bind(dbx.Params{"k": keyPEM, "id": id}).Execute(); err != nil {
		t.Fatalf("break key of host %s: %v", id, err)
	}
}

// runRenewalSweep runs the scheduled renewal job once, as cron would.
func runRenewalSweep(t *testing.T, app core.App) {
	t.Helper()
	for _, job := range app.Cron().Jobs() {
		if job.Id() == types.HostRenewalCronJobID {
			job.Run()
			return
		}
	}
	t.Fatalf("no cron job %q is registered", types.HostRenewalCronJobID)
}
