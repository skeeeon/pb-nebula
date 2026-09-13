package pbnebula

import "testing"

// TestHostCertNetworkIsStaleIsWired checks that the exported predicate reaches
// the real implementation.
//
// The cases that matter -- a /32 certificate against a /24 network, an edited
// overlay_ip, an exact match -- are covered against real certificates in
// internal/cert, which can mint a CA to sign them. What CANNOT be caught there
// is this file quietly drifting: a re-export that swallowed its error or
// returned a zero value would leave every consumer's staleness badge dark and
// every test in internal/cert green.
func TestHostCertNetworkIsStaleIsWired(t *testing.T) {
	// A host mid-creation. Not stale, and not an error -- the create hook owns
	// filling the certificate in.
	stale, err := HostCertNetworkIsStale("", "10.128.0.5", "10.128.0.0/24")
	if err != nil {
		t.Errorf("empty certificate returned an error: %v", err)
	}
	if stale {
		t.Error("empty certificate reported stale; a host without one is not yet wrong")
	}

	// An unparseable certificate must surface rather than read as healthy.
	if _, err := HostCertNetworkIsStale("not a certificate", "10.128.0.5", "10.128.0.0/24"); err == nil {
		t.Error("unparseable certificate returned no error; a certificate we cannot read is not one we know to be correct")
	}

	// A malformed IP/CIDR pair is the caller's bug and has to be reported, not
	// absorbed into a false.
	if _, err := HostCertNetworkIsStale("not a certificate", "10.128.0.5", ""); err == nil {
		t.Error("missing network CIDR returned no error")
	}
}
