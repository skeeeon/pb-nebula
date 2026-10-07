package pbnebula_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	nebulacert "github.com/slackhq/nebula/cert"

	pbnebula "github.com/skeeeon/pb-nebula"
	"github.com/skeeeon/pb-nebula/internal/cert"
)

// These tests stand up a real PocketBase, because what they assert is what the
// HOOKS do to a stored certificate -- and the hooks are exactly the part the
// pure tests elsewhere in this module cannot reach.
//
// Every update below is made on a record RELOADED from the database. The host
// hook keys renew on Original(), and Original() is the state at the last read,
// not the state before this write: a record saved twice in memory compares
// against the value from before the first save, so a renew set on it is not a
// false -> true transition and the hook never fires. A "certificate unchanged"
// assertion against a hook that never fired passes for the wrong reason, which
// is also why every "cannot" here is paired with a "can" on the same host.

// newApp boots pb-nebula against a throwaway data directory.
func newApp(t *testing.T) *pocketbase.PocketBase {
	t.Helper()
	if testing.Short() {
		t.Skip("needs a real PocketBase; run without -short")
	}

	app := pocketbase.NewWithConfig(pocketbase.Config{
		DefaultDataDir:  t.TempDir(),
		HideStartBanner: true,
	})
	opts := pbnebula.DefaultOptions()
	opts.LogToConsole = false
	if err := pbnebula.Setup(app, opts); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := app.Bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Registered after TempDir, so it runs first: close the database before
	// the directory holding it is removed (Windows will not delete an open file).
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	return app
}

// newNetwork creates a CA and one network under it, returning the network id.
func newNetwork(t *testing.T, app core.App) string {
	t.Helper()

	cas, err := app.FindCollectionByNameOrId("nebula_ca")
	if err != nil {
		t.Fatal(err)
	}
	ca := core.NewRecord(cas)
	ca.Set("name", "test-ca")
	ca.Set("validity_years", 2)
	if err := app.Save(ca); err != nil {
		t.Fatalf("create CA: %v", err)
	}

	networks, err := app.FindCollectionByNameOrId("nebula_networks")
	if err != nil {
		t.Fatal(err)
	}
	network := core.NewRecord(networks)
	network.Set("name", "test-net")
	network.Set("cidr_range", "10.128.0.0/24")
	network.Set("ca_id", ca.Id)
	if err := app.Save(network); err != nil {
		t.Fatalf("create network: %v", err)
	}
	return network.Id
}

// newHost creates a host and returns its id. pb-nebula issues the certificate
// in the create hook.
func newHost(t *testing.T, app core.App, networkID, hostname, ip string) string {
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
	if err := app.Save(host); err != nil {
		t.Fatalf("create host %s: %v", hostname, err)
	}
	if load(t, app, host.Id).GetString("certificate") == "" {
		t.Fatalf("host %s was created without a certificate; the create hook did not run", hostname)
	}
	return host.Id
}

func load(t *testing.T, app core.App, id string) *core.Record {
	t.Helper()
	record, err := app.FindRecordById("nebula_hosts", id)
	if err != nil {
		t.Fatalf("reload host %s: %v", id, err)
	}
	return record
}

func fingerprint(t *testing.T, record *core.Record) string {
	t.Helper()
	fp, err := cert.FingerprintFromPEM(record.GetString("certificate"))
	if err != nil {
		t.Fatalf("fingerprint host %s: %v", record.Id, err)
	}
	return fp
}

// update reloads the host, applies set, and saves it.
func update(t *testing.T, app core.App, id string, set map[string]any) error {
	t.Helper()
	record := load(t, app, id)
	for k, v := range set {
		record.Set(k, v)
	}
	return app.Save(record)
}

func mustUpdate(t *testing.T, app core.App, id string, set map[string]any) {
	t.Helper()
	if err := update(t, app, id, set); err != nil {
		t.Fatalf("update host %s with %v: %v", id, set, err)
	}
}

// TestRenewDoesNotReissueAnInactiveHost is the bug: renew re-signed a
// deactivated host, replacing the stored certificate that getBlocklist
// fingerprints, so the next blocklist rebuild under the CA listed a certificate
// nobody holds and dropped the one the device does.
func TestRenewDoesNotReissueAnInactiveHost(t *testing.T) {
	app := newApp(t)
	hostID := newHost(t, app, newNetwork(t, app), "parked", "10.128.0.10")

	// CAN: renew re-issues an active host. Without this, the assertion below
	// would pass against a hook that does nothing at all.
	before := fingerprint(t, load(t, app, hostID))
	mustUpdate(t, app, hostID, map[string]any{"renew": true})
	if fingerprint(t, load(t, app, hostID)) == before {
		t.Fatal("renew on an ACTIVE host did not re-issue its certificate; the hook is not running, so nothing below proves anything")
	}

	mustUpdate(t, app, hostID, map[string]any{"active": false})
	held := fingerprint(t, load(t, app, hostID))

	// CANNOT: renew on the inactive host.
	err := update(t, app, hostID, map[string]any{"renew": true})

	after := load(t, app, hostID)
	if got := fingerprint(t, after); got != held {
		t.Fatalf("renew re-issued an INACTIVE host's certificate: the blocklist now revokes %s, and %s -- the certificate the device holds -- is trusted again", got, held)
	}
	if !errors.Is(err, pbnebula.ErrHostInactive) {
		t.Fatalf("renew on an inactive host: got error %v, want ErrHostInactive so the caller learns why", err)
	}
	if after.GetBool("renew") {
		t.Fatal("a refused renew left the flag set; it would fire on the next save")
	}

	// A certificate field edit on an inactive host is ACCEPTED and deferred,
	// not refused: renaming a decommissioned host or freeing its overlay IP is
	// a legitimate edit. It must not re-sign, though.
	mustUpdate(t, app, hostID, map[string]any{"hostname": "parked-renamed"})
	if got := fingerprint(t, load(t, app, hostID)); got != held {
		t.Fatalf("a hostname edit re-issued an INACTIVE host's certificate (%s -> %s)", held, got)
	}

	// CAN: reactivation still re-issues -- it is the way back, and the deferred
	// hostname edit lands in the new certificate.
	mustUpdate(t, app, hostID, map[string]any{"active": true})
	back := load(t, app, hostID)
	if fingerprint(t, back) == held {
		t.Fatal("reactivation did not re-issue the certificate")
	}
	if name := certName(t, back); name != "parked-renamed" {
		t.Fatalf("reactivated certificate is named %q, want the hostname edited while inactive", name)
	}
}

// TestDeactivatingWhileEditingACertFieldRevokesTheHeldCertificate covers the
// same hole from the other side: one save that deactivates a host AND changes
// a certificate field. Re-signing there would blocklist the fresh certificate
// and never the one the device holds -- a deactivation that revokes nothing.
func TestDeactivatingWhileEditingACertFieldRevokesTheHeldCertificate(t *testing.T) {
	app := newApp(t)
	networkID := newNetwork(t, app)
	hostID := newHost(t, app, networkID, "leaving", "10.128.0.20")
	peerID := newHost(t, app, networkID, "peer", "10.128.0.21")

	held := fingerprint(t, load(t, app, hostID))
	mustUpdate(t, app, hostID, map[string]any{"active": false, "groups": []string{"retired"}})

	if got := fingerprint(t, load(t, app, hostID)); got != held {
		t.Fatalf("deactivation re-signed the host (%s -> %s); the device's certificate is not the one revoked", held, got)
	}
	if peerConfig := load(t, app, peerID).GetString("config_yaml"); !strings.Contains(peerConfig, held) {
		t.Fatalf("peer's pki.blocklist does not carry %s, the certificate the deactivated device holds", held)
	}
}

// TestRenewOnAnInactiveHostIsA400WithAReason drives the record API, which is
// what the Admin UI and every console use. The point of refusing rather than
// skipping is that the admin is told why; a generic 400 would tell them nothing.
func TestRenewOnAnInactiveHostIsA400WithAReason(t *testing.T) {
	app := newApp(t)
	hostID := newHost(t, app, newNetwork(t, app), "api-parked", "10.128.0.30")
	mustUpdate(t, app, hostID, map[string]any{"active": false})
	held := fingerprint(t, load(t, app, hostID))

	superusers, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	su := core.NewRecord(superusers)
	su.SetEmail("admin@example.com")
	su.SetPassword("password123")
	if err := app.Save(su); err != nil {
		t.Fatal(err)
	}
	token, err := su.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPatch,
		fmt.Sprintf("/api/collections/nebula_hosts/records/%s", hostID),
		strings.NewReader(`{"renew":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if got := fingerprint(t, load(t, app, hostID)); got != held {
		t.Fatalf("PATCH renew re-issued an INACTIVE host's certificate (%s -> %s)", held, got)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PATCH renew on an inactive host: status %d, want 400; body %s", rec.Code, rec.Body)
	}
	var body struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !strings.Contains(body.Message, "inactive") || !strings.Contains(body.Message, "reactivate") {
		t.Fatalf("400 does not say why or what to do instead: %q", body.Message)
	}
}

func certName(t *testing.T, record *core.Record) string {
	t.Helper()
	c, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(record.GetString("certificate")))
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return c.Name()
}
