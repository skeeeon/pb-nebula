package sync

import (
	"encoding/json"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"

	nebulacert "github.com/slackhq/nebula/cert"
)

// The host columns that hold certificates a host was issued and no longer
// holds. pki.blocklist is built from them as well as from the stored
// certificate, because a certificate a re-issue replaces is still valid until it
// expires: Nebula has no CRL, so nothing else refuses it.
//
//   - revoked_certificates: refused by every peer, whatever the host's state.
//   - retired_certificates: refused only while the host is inactive.
//
// Both hold PEM, not fingerprints, so the fingerprint, expiry and issuer are
// read from the certificate the same way they are for the stored one.
const (
	revokedCertsField = "revoked_certificates"
	retiredCertsField = "retired_certificates"
)

// replacement says what a re-issue does with the certificate it replaces.
type replacement int

const (
	// retire is for a routine refresh: the renewal sweep and the CA rotation
	// sweep. The replaced certificate keeps working, so a host that has not
	// fetched its new config yet stays on the mesh. Blocklisting it would turn
	// every renewal into a cut-over, and it would undo the point of rotation,
	// which keeps the outgoing certificate valid until the operator finishes.
	// It is still recorded, so a later deactivation refuses it too.
	retire replacement = iota

	// revoke is for a change someone asked for: a certificate field, renew,
	// reactivation. Every certificate the host held before is refused from now
	// on, retired ones included -- they carry the same groups and name as the
	// one being replaced.
	revoke
)

// replaceCertificate records a host's current certificate before a re-issue
// overwrites it, and drops what no peer could accept any longer.
//
// PARAMETERS:
//   - record: the host, still holding the certificate about to be replaced
//   - how: retire or revoke
//   - trusted: fingerprints of the CAs in the trust bundle (see trustedCAs)
//   - now: evaluation time
//
// SIDE EFFECTS: Sets revoked_certificates and retired_certificates on record.
func replaceCertificate(record *core.Record, how replacement, trusted map[string]bool, now time.Time) {
	revoked := certList(record, revokedCertsField)
	retired := certList(record, retiredCertsField)

	if current := record.GetString("certificate"); current != "" {
		retired = append(retired, current)
	}
	if how == revoke {
		revoked = append(revoked, retired...)
		retired = nil
	}

	record.Set(revokedCertsField, keepAccepted(revoked, trusted, now))
	record.Set(retiredCertsField, keepAccepted(retired, trusted, now))
}

// blocklistCandidates returns the certificates a host's peers must refuse:
// everything it was revoked for and, once it is inactive, everything it holds
// or held. Check each with stillAccepted before fingerprinting it.
func blocklistCandidates(record *core.Record) []string {
	candidates := certList(record, revokedCertsField)
	if record.GetBool("active") {
		return candidates
	}
	if current := record.GetString("certificate"); current != "" {
		candidates = append(candidates, current)
	}
	return append(candidates, certList(record, retiredCertsField)...)
}

// stillAccepted reports whether a peer could still accept a certificate: it
// has not expired, and a CA in the trust bundle signed it.
//
// Blocklisting anything else buys nothing, because Nebula refuses it already,
// and every entry costs about 75 bytes of every config_yaml under the CA, which
// is capped at 50000. The issuer half is what lets a CA rotation clear the
// list: once finish drops the outgoing CA, nothing it signed is listed. That is
// safe because the bundle and the blocklist arrive in the same config_yaml, so
// no host ever holds the shorter list while it still trusts the old CA.
//
// A nil trusted means the bundle is unknown, and the issuer is not checked.
//
// RETURNS:
// - whether to keep the certificate
// - error if it does not parse
func stillAccepted(certPEM string, trusted map[string]bool, now time.Time) (bool, error) {
	c, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(certPEM))
	if err != nil {
		return false, err
	}
	if !now.Before(c.NotAfter()) {
		return false, nil
	}
	if trusted != nil && !trusted[c.Issuer()] {
		return false, nil
	}
	return true, nil
}

// keepAccepted filters a list with stillAccepted. A certificate that does not
// parse is dropped: it cannot be fingerprinted, so it can never be listed.
func keepAccepted(pems []string, trusted map[string]bool, now time.Time) []string {
	kept := make([]string, 0, len(pems))
	for _, pem := range pems {
		if ok, _ := stillAccepted(pem, trusted, now); ok {
			kept = append(kept, pem)
		}
	}
	return kept
}

// trustedCAs returns the fingerprints of the CAs a host trusts with this bundle
// in pki.ca, read with the function Nebula reads it with. An expired CA is left
// out, as Nebula leaves it out.
//
// nil, not empty, when the bundle does not parse or trusts nothing: an empty set
// would make stillAccepted drop every certificate.
func trustedCAs(bundle string) map[string]bool {
	pool, _ := nebulacert.NewCAPoolFromPEM([]byte(bundle)) // ErrExpired still returns the pool
	if pool == nil || len(pool.CAs) == 0 {
		return nil
	}
	trusted := make(map[string]bool, len(pool.CAs))
	for fp := range pool.CAs {
		trusted[fp] = true
	}
	return trusted
}

// certList reads one of the PEM list columns. An empty or unreadable column is
// an empty list.
func certList(record *core.Record, field string) []string {
	raw := record.GetString(field)
	if raw == "" || raw == "null" {
		return nil
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil
	}
	return list
}
