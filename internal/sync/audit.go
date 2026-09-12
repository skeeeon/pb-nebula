package sync

import (
	"github.com/pocketbase/dbx"

	"github.com/skeeeon/pb-nebula/internal/cert"
)

// AuditHostCertNetworkMasks warns about active hosts whose stored certificate
// no longer matches the network they belong to, and re-signs nothing.
//
// WHAT IT IS FOR:
// A host certificate's network is not a label -- Nebula lays the prefix onto
// the tun device and routes the overlay from its mask (see overlayPrefix in
// internal/cert). Every certificate pb-nebula issued before that was corrected
// carries a single-address network, which leaves the host unable to route to
// any peer while everything else about it looks healthy. The same drift appears
// whenever a network's cidr_range is edited, because changing it regenerates
// configs but re-signs nothing.
//
// WHY IT ONLY WARNS:
// Re-signing moves a certificate's fingerprint, and a fingerprint is what
// pki.blocklist revokes. A sweep that re-signed on its own initiative would
// churn every fingerprint in a fleet at once -- and every peer config with them
// -- on the strength of a library upgrade. That is the operator's call, and the
// `renew` action field is already the lever for it.
//
// INACTIVE HOSTS ARE SKIPPED, AND NOT AS AN OVERSIGHT:
// An inactive host is revoked: its fingerprint sits in every peer's blocklist.
// Re-signing it would publish a new fingerprint while the old certificate
// stayed valid, silently un-revoking it. Warning about one would invite exactly
// that, so it is left out -- the same rule the renewal and CA rotation sweeps
// follow.
//
// PARAMETERS:
//   - networkID: audit one network, or "" for every network
//
// SIDE EFFECTS: Logging only. Never writes, never signs.
func (sm *Manager) AuditHostCertNetworkMasks(networkID string) {
	filter := dbx.HashExp{"active": true}
	if networkID != "" {
		filter["network_id"] = networkID
	}

	hosts, err := sm.app.FindAllRecords(sm.options.HostCollectionName, filter)
	if err != nil {
		// Advisory only, and it runs at bootstrap: a failure here must not
		// stop the library coming up.
		sm.logger.Warning("Could not audit host certificate networks: %v", err)
		return
	}

	// Networks are looked up once each rather than per host: a fleet is mostly
	// many hosts across few networks.
	cidrs := make(map[string]string)
	stale := 0

	for _, host := range hosts {
		id := host.GetString("network_id")
		cidr, ok := cidrs[id]
		if !ok {
			network, err := sm.app.FindRecordById(sm.options.NetworkCollectionName, id)
			if err != nil {
				sm.logger.Warning("Cannot audit host %s: network %s not found: %v",
					host.GetString("hostname"), id, err)
				cidrs[id] = ""
				continue
			}
			cidr = network.GetString("cidr_range")
			cidrs[id] = cidr
		}
		if cidr == "" {
			continue
		}

		isStale, err := cert.HostCertNetworkIsStale(host.GetString("certificate"),
			host.GetString("overlay_ip"), cidr)
		if err != nil {
			sm.logger.Warning("Cannot audit certificate for host %s: %v",
				host.GetString("hostname"), err)
			continue
		}
		if isStale {
			sm.logger.Warning("Host %s has a certificate that does not match network %s -- "+
				"it cannot route to its peers until it is re-signed; set renew=true on the record",
				host.GetString("hostname"), cidr)
			stale++
		}
	}

	if stale > 0 {
		sm.logger.Warning("%d active host certificate(s) need re-issuing. "+
			"Nothing was re-signed: re-issuing moves a certificate's fingerprint, "+
			"so it is left to you to stage.", stale)
	}
}
