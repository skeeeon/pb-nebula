package sync

import (
	"slices"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"

	"github.com/skeeeon/pb-nebula/internal/cert"
)

// testCA mints a CA and returns its certificate and a signer for host
// certificates under it.
func testCA(t *testing.T, name string) (caPEM string, sign func(hostname string) string) {
	t.Helper()
	cm := cert.NewManager()
	ca, err := cm.GenerateCA(name, 2)
	if err != nil {
		t.Fatal(err)
	}
	return ca.CertificatePEM, func(hostname string) string {
		t.Helper()
		host, err := cm.GenerateHostCert(cert.HostCertParams{
			Hostname:        hostname,
			OverlayIP:       "10.128.0.5",
			NetworkCIDR:     "10.128.0.0/24",
			ValidityYears:   1,
			CACertPEM:       ca.CertificatePEM,
			CAPrivateKeyPEM: ca.PrivateKeyPEM,
		})
		if err != nil {
			t.Fatal(err)
		}
		return host.CertificatePEM
	}
}

// replacedHost builds a detached host record with the real field types.
func replacedHost(t *testing.T, active bool, current string, revoked, retired []string) *core.Record {
	t.Helper()
	collection := core.NewBaseCollection("nebula_hosts")
	collection.Fields.Add(
		&core.BoolField{Name: "active"},
		&core.TextField{Name: "certificate", Max: 10000},
		&core.JSONField{Name: revokedCertsField},
		&core.JSONField{Name: retiredCertsField},
	)
	record := core.NewRecord(collection)
	record.Set("active", active)
	record.Set("certificate", current)
	record.Set(revokedCertsField, revoked)
	record.Set(retiredCertsField, retired)
	return record
}

// TestReplaceCertificate pins the two kinds of re-issue. A routine one keeps the
// old certificate working; one somebody asked for revokes it AND everything
// retired before it, since those carry the same name and groups.
func TestReplaceCertificate(t *testing.T) {
	caPEM, sign := testCA(t, "ca")
	trusted := trustedCAs(caPEM)
	now := time.Now()
	old, older, current := sign("old"), sign("older"), sign("current")

	retired := replacedHost(t, true, current, []string{old}, []string{older})
	replaceCertificate(retired, retire, trusted, now)
	if got := certList(retired, revokedCertsField); !slices.Equal(got, []string{old}) {
		t.Fatalf("retire changed the revoked list: %d entries, want the 1 already there", len(got))
	}
	if got := certList(retired, retiredCertsField); !slices.Equal(got, []string{older, current}) {
		t.Fatalf("retire did not append the replaced certificate to the retired list: %d entries, want 2", len(got))
	}

	revoked := replacedHost(t, true, current, []string{old}, []string{older})
	replaceCertificate(revoked, revoke, trusted, now)
	if got := certList(revoked, revokedCertsField); !slices.Equal(got, []string{old, older, current}) {
		t.Fatalf("revoke did not move the retired and replaced certificates to the revoked list: %d entries, want 3", len(got))
	}
	if got := certList(revoked, retiredCertsField); len(got) != 0 {
		t.Fatalf("revoke left %d retired certificates; they carry the same groups and must be revoked too", len(got))
	}

	// Nothing to replace: the create path.
	fresh := replacedHost(t, true, "", nil, nil)
	replaceCertificate(fresh, revoke, trusted, now)
	if n := len(certList(fresh, revokedCertsField)) + len(certList(fresh, retiredCertsField)); n != 0 {
		t.Fatalf("a host with no certificate recorded %d replaced certificates", n)
	}
}

// TestReplaceCertificateDropsWhatNoPeerAccepts keeps the lists bounded. Paired:
// the same certificate is kept at an earlier instant and under its own CA.
func TestReplaceCertificateDropsWhatNoPeerAccepts(t *testing.T) {
	caPEM, sign := testCA(t, "ca")
	trusted := trustedCAs(caPEM)
	held := sign("held")
	now := time.Now()

	// CAN: kept while unexpired and its CA is trusted.
	host := replacedHost(t, true, sign("current"), []string{held}, nil)
	replaceCertificate(host, revoke, trusted, now)
	if !slices.Contains(certList(host, revokedCertsField), held) {
		t.Fatal("a certificate that still verifies was dropped")
	}

	// CANNOT: past its NotAfter.
	host = replacedHost(t, true, sign("current"), []string{held}, nil)
	replaceCertificate(host, revoke, trusted, now.AddDate(2, 0, 0))
	if slices.Contains(certList(host, revokedCertsField), held) {
		t.Fatal("an expired certificate was kept")
	}

	// CANNOT: signed by a CA that has left the bundle.
	otherPEM, _ := testCA(t, "other")
	host = replacedHost(t, true, sign("current"), []string{held}, nil)
	replaceCertificate(host, revoke, trustedCAs(otherPEM), now)
	if slices.Contains(certList(host, revokedCertsField), held) {
		t.Fatal("a certificate whose CA left the bundle was kept")
	}

	// An unknown bundle drops nothing for its issuer.
	host = replacedHost(t, true, sign("current"), []string{held}, nil)
	replaceCertificate(host, revoke, trustedCAs("not a bundle"), now)
	if !slices.Contains(certList(host, revokedCertsField), held) {
		t.Fatal("an unreadable bundle dropped a certificate; it must drop nothing")
	}
}

// TestBlocklistCandidates: revoked certificates are refused whatever the host's
// state; the current and retired ones only once it is inactive.
func TestBlocklistCandidates(t *testing.T) {
	_, sign := testCA(t, "ca")
	current, revokedCert, retiredCert := sign("current"), sign("revoked"), sign("retired")

	active := blocklistCandidates(replacedHost(t, true, current, []string{revokedCert}, []string{retiredCert}))
	if !slices.Equal(active, []string{revokedCert}) {
		t.Fatalf("active host: %d candidates, want only its 1 revoked certificate", len(active))
	}

	inactive := blocklistCandidates(replacedHost(t, false, current, []string{revokedCert}, []string{retiredCert}))
	for _, want := range []string{current, revokedCert, retiredCert} {
		if !slices.Contains(inactive, want) {
			t.Fatalf("inactive host: %d candidates, want all 3 of its certificates", len(inactive))
		}
	}
}

// TestTrustedCAsReadsARotationBundle: both CAs of a [previous, current] bundle
// are trusted, as Nebula trusts them.
func TestTrustedCAsReadsARotationBundle(t *testing.T) {
	previousPEM, signPrevious := testCA(t, "previous")
	currentPEM, signCurrent := testCA(t, "current")
	trusted := trustedCAs(previousPEM + "\n" + currentPEM)

	for name, certPEM := range map[string]string{"previous": signPrevious("a"), "current": signCurrent("b")} {
		ok, err := stillAccepted(certPEM, trusted, time.Now())
		if err != nil || !ok {
			t.Fatalf("a certificate signed by the %s CA of the bundle is not accepted (%v)", name, err)
		}
	}
	if trustedCAs("") != nil {
		t.Fatal("an empty bundle must be unknown (nil), not an empty set that drops everything")
	}
}
