package pbnebula

import (
	"github.com/skeeeon/pb-nebula/internal/cert"
)

// HostCertNetworkIsStale reports whether a host's certificate still carries a
// network that no longer matches the overlay it belongs to.
//
// WHY THIS IS EXPORTED AT ALL:
// The library already audits this at bootstrap and writes a log line per
// affected host (see internal/sync/audit.go). A log line is the right surface
// for an operator tailing a server; it is the wrong one for a consumer with a
// console, which needs to badge the specific rows and offer the fix next to
// them. Re-deriving the predicate on the caller's side would mean parsing a
// Nebula certificate with slackhq/nebula directly and keeping a second copy of
// what "matches" means -- and the whole reason the /32 defect survived from the
// first commit is that nothing compared the two. One predicate, one home.
//
// WHAT COUNTS AS STALE:
// The comparison is exact, not mask-only: a certificate whose network is
// 10.128.0.5/24 is stale against overlayIP 10.128.0.6 as surely as against
// network 10.128.0.0/16. An edited overlay_ip leaves the certificate just as
// wrong as an unmigrated mask, and both are fixed the same way.
//
// AN EMPTY CERTIFICATE IS NOT STALE. A host mid-creation has no certificate
// yet; the create hook owns filling it in, and reporting it as stale would
// point the operator at a row that is about to fix itself.
//
// WHAT TO DO WITH A TRUE:
// Set renew = true on the host record. That re-issues the certificate at the
// correct mask on the next save. Do not sweep a fleet with it unprompted --
// re-signing moves a fingerprint, and a fingerprint is what pki.blocklist
// revokes, so a bulk re-issue rewrites every peer config in the network. The
// library deliberately never does this on its own.
//
// INACTIVE HOSTS: the caller should skip them. An inactive host is revoked, and
// re-signing it would publish a new fingerprint while the old certificate
// stayed valid and unblocklisted -- silently un-revoking it.
//
// PARAMETERS:
//   - certPEM: the host's stored certificate, PEM encoded ("" if not yet issued)
//   - overlayIP: the host's overlay_ip
//   - networkCIDR: its network's cidr_range
//
// RETURNS:
// - false, nil when certPEM is empty
// - true when the certificate's network is not exactly overlayIP at the network's mask
// - error if the certificate does not parse, or the IP/CIDR pair is not coherent
//
// SIDE EFFECTS: None (pure).
func HostCertNetworkIsStale(certPEM, overlayIP, networkCIDR string) (bool, error) {
	return cert.HostCertNetworkIsStale(certPEM, overlayIP, networkCIDR)
}
