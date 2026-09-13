package sync

import (
	"fmt"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	nebulacert "github.com/slackhq/nebula/cert"

	"github.com/skeeeon/pb-nebula/internal/types"
)

// Rotation verbs, written to the CA record's `rotate` action field.
const (
	rotateVerbPrepare = "prepare"
	rotateVerbCommit  = "commit"
	rotateVerbFinish  = "finish"
)

// rotationState describes where a CA is in a rotation, derived from which of
// the two certificate fields is populated. There is no stored status column:
// the certificates already say this, and a second copy could only disagree.
type rotationState int

const (
	rotationIdle     rotationState = iota // neither field set
	rotationPrepared                      // next_certificate set: new CA minted, trust published, issuance unchanged
	rotationRotated                       // previous_certificate set: issuance switched, old CA still trusted
)

// caRotationState reports which phase a CA record is in.
func caRotationState(record *core.Record) rotationState {
	if record.GetString("next_certificate") != "" {
		return rotationPrepared
	}
	if record.GetString("previous_certificate") != "" {
		return rotationRotated
	}
	return rotationIdle
}

// caBundle returns the PEM to write into pki.ca for hosts under this CA.
//
// During a rotation the bundle carries two certificates so every host trusts
// the outgoing and incoming CA at once. The CONTENT is the same in both phases
// -- [old, new] either way -- which is what lets a host fetch at any instant
// from `prepare` onward and be able to handshake with every peer regardless of
// which certificate that peer is presenting.
//
// Nebula reads a concatenated bundle natively (NewCAPoolFromPEM loops over PEM
// blocks) and tolerates an expired CA among them, failing only if every CA in
// the pool is expired.
func caBundle(record *core.Record) string {
	current := record.GetString("certificate")

	if next := record.GetString("next_certificate"); next != "" {
		return current + "\n" + next
	}
	if previous := record.GetString("previous_certificate"); previous != "" {
		return previous + "\n" + current
	}

	return current
}

// validateCARotation checks a requested rotation verb against the CA's current
// state, and rejects hand-edits of the fields pb-nebula owns.
//
// WHY THIS RUNS IN THE REQUEST HOOK:
// OnRecordAfterUpdateSuccess runs after the write has already committed, so it
// cannot usefully refuse anything. Validating here means a bad verb returns 400
// and never persists -- the same two-hook split validateHostRecord already uses.
//
// THE INTERLOCK THAT MATTERS MOST:
// `prepare` is refused while previous_certificate is set. Two rotations in
// quick succession would drop generation 1 from every bundle while most hosts
// still hold generation-1 certificates, which is a mesh-wide outage -- and it
// is reachable by an impatient operator clicking Save twice, not just by a
// deliberate double rotation. `finish` is what clears the way, and `finish`
// itself refuses until every active host has actually migrated.
//
// ERRORS ARE ApiErrors, NOT PLAIN ERRORS:
// A plain error returned from a request hook is flattened by PocketBase into a
// generic "Something went wrong" 400, which throws away the only thing that
// makes these messages worth writing -- finish in particular names the host
// that is blocking it. router.NewBadRequestError carries the text through to
// the client.
//
// PARAMETERS:
//   - record: the incoming CA record
//   - orig: the stored record, or nil on create
//
// RETURNS:
// - nil if the request is allowed
// - *router.ApiError describing what to do instead
func (sm *Manager) validateCARotation(record, orig *core.Record) error {
	if err := sm.checkCARotation(record, orig); err != nil {
		return router.NewBadRequestError(err.Error(), nil)
	}
	return nil
}

// checkCARotation holds the actual rules; validateCARotation wraps whatever it
// returns so the reason survives the trip to the client.
func (sm *Manager) checkCARotation(record, orig *core.Record) error {
	if orig == nil {
		// Creation. Rotation fields have no meaning yet.
		if record.GetString("rotate") != "" {
			return fmt.Errorf("%w: a CA cannot be rotated at creation", types.ErrInvalidRotation)
		}
		return nil
	}

	// pb-nebula owns the certificate material. Hand-editing it from the Admin
	// UI or the API is never a repair -- at best it desynchronizes the record
	// from every config already handed out, and at worst a non-CA PEM pasted
	// into the bundle makes every host under this CA fail to start, because
	// NewCAPoolFromPEM treats a malformed or non-CA block as a hard error.
	for _, field := range []string{
		"certificate", "private_key",
		"next_certificate", "next_private_key",
		"previous_certificate", "expires_at", "rotated_at",
	} {
		if orig.GetString(field) != record.GetString(field) {
			return fmt.Errorf("%w: %s is managed by pb-nebula and cannot be edited directly; use the rotate field",
				types.ErrInvalidRotation, field)
		}
	}

	verb := record.GetString("rotate")
	if verb == "" || verb == orig.GetString("rotate") {
		return nil
	}

	switch verb {
	case rotateVerbPrepare:
		switch caRotationState(orig) {
		case rotationPrepared:
			return fmt.Errorf("%w: a rotation is already prepared; run commit, or clear next_certificate to abandon it",
				types.ErrInvalidRotation)
		case rotationRotated:
			return fmt.Errorf("%w: the previous rotation is not finished; run finish once every active host has migrated",
				types.ErrInvalidRotation)
		}

	case rotateVerbCommit:
		if caRotationState(orig) == rotationIdle {
			return fmt.Errorf("%w: nothing prepared to commit; run prepare first", types.ErrInvalidRotation)
		}

	case rotateVerbFinish:
		if caRotationState(orig) != rotationRotated {
			return fmt.Errorf("%w: nothing to finish; finish clears the outgoing CA after a commit",
				types.ErrInvalidRotation)
		}
		if err := sm.assertAllHostsMigrated(orig); err != nil {
			return err
		}

	default:
		return fmt.Errorf("%w: unknown verb %q, expected prepare, commit or finish",
			types.ErrInvalidRotation, verb)
	}

	return nil
}

// assertAllHostsMigrated refuses `finish` while any active host still holds a
// certificate signed by the outgoing CA.
//
// This is the interlock that makes `finish` safe to expose at all. Dropping the
// outgoing CA from the bundle while a host still presents a certificate signed
// by it takes that host off the mesh silently -- it keeps running, its peers
// simply stop being able to verify it. Nothing in this library knows when a
// host fetched its config, so without this check "has everyone migrated?" is a
// guess. Comparing each certificate's issuer against the current CA's
// fingerprint turns it into an answer.
//
// Inactive hosts are excluded deliberately: they are never re-signed by the
// commit sweep (re-signing would change the fingerprint their peers blocklist),
// so they hold an outgoing-CA certificate forever by design.
//
// SIDE EFFECTS: None (read-only).
func (sm *Manager) assertAllHostsMigrated(ca *core.Record) error {
	currentCert, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(ca.GetString("certificate")))
	if err != nil {
		return fmt.Errorf("%w: CA certificate does not parse: %v", types.ErrInvalidRotation, err)
	}
	currentFP, err := currentCert.Fingerprint()
	if err != nil {
		return fmt.Errorf("%w: cannot fingerprint CA certificate: %v", types.ErrInvalidRotation, err)
	}

	networks, err := sm.app.FindAllRecords(sm.options.NetworkCollectionName, dbx.HashExp{"ca_id": ca.Id})
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrInvalidRotation, err)
	}

	for _, network := range networks {
		hosts, err := sm.app.FindAllRecords(sm.options.HostCollectionName,
			dbx.HashExp{"network_id": network.Id, "active": true})
		if err != nil {
			return fmt.Errorf("%w: %v", types.ErrInvalidRotation, err)
		}

		for _, host := range hosts {
			certPEM := host.GetString("certificate")
			if certPEM == "" {
				continue
			}
			parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(certPEM))
			if err != nil {
				return fmt.Errorf("%w: certificate for host %s does not parse: %v",
					types.ErrInvalidRotation, host.GetString("hostname"), err)
			}
			if parsed.Issuer() != currentFP {
				return fmt.Errorf("%w: host %s is still on the outgoing CA; run commit again to re-sign it before finishing",
					types.ErrInvalidRotation, host.GetString("hostname"))
			}
		}
	}

	return nil
}

// rotateCA performs one rotation step on a CA record and resets the action field.
//
// WHY ROTATION TAKES THREE STEPS AND NOT ONE:
// Nebula verification is mutual -- each peer checks the other against its OWN
// local CA pool, with no chain and no fallback. Config distribution here is
// pull-based: a host reads config_yaml whenever it likes and nothing tells us
// when it did. So a single write carrying both the new trust bundle AND the new
// certificate splits the mesh: a host that has fetched presents a new-CA
// certificate to a host that has not, whose pool holds only the old CA, and the
// handshake fails in BOTH directions for as long as propagation takes.
//
// Publishing trust first and switching issuance second removes that window
// entirely. The wait between the two is operator judgment and cannot be
// designed away, only made visible.
//
//	prepare -> mint the incoming CA, fan out config-only. Trust published.
//	           Nothing is signed by it yet, no fingerprint changes.
//	commit  -> swap it in, then re-sign every active host. Both CAs trusted
//	           throughout, so re-signed and not-yet-re-signed hosts still talk.
//	finish  -> drop the outgoing CA, once every active host has migrated.
//
// COMMIT IS IDEMPOTENT AND RESUMABLE:
// Running it again after a partial sweep skips the swap and re-signs only the
// hosts whose certificates still name the outgoing CA. That makes recovery the
// same verb as the original action rather than a separate lever.
//
// SIDE EFFECTS: Mints CA key material, writes the CA record, re-signs and saves
// host records, regenerates peer configs.
func (sm *Manager) rotateCA(record *core.Record, verb string) error {
	switch verb {
	case rotateVerbPrepare:
		return sm.rotatePrepare(record)
	case rotateVerbCommit:
		return sm.rotateCommit(record)
	case rotateVerbFinish:
		return sm.rotateFinish(record)
	}
	return fmt.Errorf("%w: unknown verb %q", types.ErrInvalidRotation, verb)
}

// rotatePrepare mints the incoming CA and publishes trust in it.
//
// certificate, private_key and expires_at are deliberately untouched: issuance
// stays on the current CA, no host certificate changes, no fingerprint moves,
// and the blocklist is unaffected. That makes this phase fully reversible --
// clear next_certificate and fan out again.
func (sm *Manager) rotatePrepare(record *core.Record) error {
	validityYears := record.GetInt("validity_years")
	if validityYears == 0 {
		validityYears = sm.options.DefaultCAValidityYears
	}

	result, err := sm.certManager.GenerateCA(record.GetString("name"), validityYears)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrCertGeneration, err)
	}

	record.Set("next_certificate", result.CertificatePEM)
	if err := types.EncryptAndSet(record, "next_private_key", result.PrivateKeyPEM, sm.options.EncryptionKey); err != nil {
		return err
	}
	record.Set("rotate", "")

	if err := sm.saveInternal(record); err != nil {
		return fmt.Errorf("failed to save prepared CA: %w", err)
	}

	sm.logger.Cert("Prepared rotation for CA %s; publishing trust to all hosts", record.GetString("name"))
	sm.regenerateCANetworkConfigs(record)
	sm.logger.Success("CA %s rotation prepared. Let every host fetch its config, then run commit.",
		record.GetString("name"))

	return nil
}

// rotateCommit switches issuance to the incoming CA and re-signs active hosts.
//
// The swap is skipped when previous_certificate is already set, which is what
// makes the verb resumable after a partial sweep.
func (sm *Manager) rotateCommit(record *core.Record) error {
	resuming := caRotationState(record) == rotationRotated

	if !resuming {
		next := record.GetString("next_certificate")
		nextKey, err := types.DecryptField(record.GetString("next_private_key"), sm.options.EncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt incoming CA key: %w", err)
		}

		parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(next))
		if err != nil {
			return fmt.Errorf("%w: incoming CA certificate does not parse: %v", types.ErrInvalidRotation, err)
		}

		record.Set("previous_certificate", record.GetString("certificate"))
		record.Set("certificate", next)
		if err := types.EncryptAndSet(record, "private_key", nextKey, sm.options.EncryptionKey); err != nil {
			return err
		}
		record.Set("next_certificate", "")
		record.Set("next_private_key", "")
		// Read expiry from the certificate, not from a computed value: it is
		// what Nebula enforces and what the host cert clamp compares against.
		record.Set("expires_at", parsed.NotAfter())
		record.Set("rotated_at", time.Now())
	}

	record.Set("rotate", "")
	if err := sm.saveInternal(record); err != nil {
		return fmt.Errorf("failed to save rotated CA: %w", err)
	}

	if resuming {
		sm.logger.Cert("Resuming rotation for CA %s; re-signing hosts still on the outgoing CA", record.GetString("name"))
	} else {
		sm.logger.Cert("Committed rotation for CA %s; re-signing active hosts", record.GetString("name"))
	}

	sm.resignCAHosts(record)
	return nil
}

// rotateFinish drops the outgoing CA from the bundle.
//
// The precondition -- every active host already migrated -- was checked in the
// request hook, so by here this is just the write plus a fan-out.
func (sm *Manager) rotateFinish(record *core.Record) error {
	record.Set("previous_certificate", "")
	record.Set("rotate", "")

	if err := sm.saveInternal(record); err != nil {
		return fmt.Errorf("failed to save finished CA: %w", err)
	}

	sm.logger.Cert("Finishing rotation for CA %s; dropping the outgoing CA from every bundle", record.GetString("name"))
	sm.regenerateCANetworkConfigs(record)
	sm.logger.Success("CA %s rotation complete", record.GetString("name"))

	return nil
}

// regenerateCANetworkConfigs regenerates configs (config-only, no re-signing)
// for every host in every network under a CA.
//
// This is what distributes a changed trust bundle, and it is the cheap half of
// rotation: no certificate changes, so no fingerprints move and the blocklist
// is untouched. It reaches INACTIVE hosts too, which is correct -- they should
// carry the current bundle even though they are never re-signed.
//
// SIDE EFFECTS: Writes config_yaml on host records.
func (sm *Manager) regenerateCANetworkConfigs(ca *core.Record) {
	networks, err := sm.app.FindAllRecords(sm.options.NetworkCollectionName, dbx.HashExp{"ca_id": ca.Id})
	if err != nil {
		sm.logger.Error("Failed to list networks for CA %s: %v", ca.GetString("name"), err)
		return
	}

	for _, network := range networks {
		sm.regenerateNetworkHostConfigs(network.Id, "")
	}
}

// resignCAHosts re-issues certificates for every ACTIVE host under a CA whose
// certificate is not already signed by the current CA.
//
// INACTIVE HOSTS ARE SKIPPED:
// An inactive host is revoked -- its fingerprint is in every peer's
// pki.blocklist. Re-signing it would change that fingerprint, so getBlocklist
// would publish the NEW one while the OLD certificate stays valid under the
// outgoing CA that is still in the trust bundle. Re-signing a revoked host
// would therefore un-revoke it.
//
// PER-HOST FAILURES ARE LOGGED, NOT FATAL:
// nebula_hosts is an auth collection, so every save runs auth validation; one
// record with a pre-existing problem must not abort the sweep. commit is
// resumable, so whatever is missed is picked up by running it again.
//
// SIDE EFFECTS: Re-signs certificates, writes host records, regenerates peer
// configs.
func (sm *Manager) resignCAHosts(ca *core.Record) {
	currentFP := ""
	if parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(ca.GetString("certificate"))); err == nil {
		if fp, err := parsed.Fingerprint(); err == nil {
			currentFP = fp
		}
	}

	networks, err := sm.app.FindAllRecords(sm.options.NetworkCollectionName, dbx.HashExp{"ca_id": ca.Id})
	if err != nil {
		sm.logger.Error("Failed to list networks for CA %s: %v", ca.GetString("name"), err)
		return
	}

	resigned := 0
	for _, network := range networks {
		hosts, err := sm.app.FindAllRecords(sm.options.HostCollectionName,
			dbx.HashExp{"network_id": network.Id, "active": true})
		if err != nil {
			sm.logger.Warning("Failed to list hosts in network %s: %v", network.GetString("name"), err)
			continue
		}

		for _, host := range hosts {
			// Skip hosts already on the current CA, which is what makes a
			// re-run of commit resume rather than redo.
			if currentFP != "" && host.GetString("certificate") != "" {
				if parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(host.GetString("certificate"))); err == nil {
					if parsed.Issuer() == currentFP {
						continue
					}
				}
			}

			if err := sm.generateHostCertAndConfig(host); err != nil {
				sm.logger.Warning("Failed to re-sign host %s: %v", host.GetString("hostname"), err)
				continue
			}
			if err := sm.saveInternal(host); err != nil {
				sm.logger.Warning("Failed to save re-signed host %s: %v", host.GetString("hostname"), err)
				continue
			}
			resigned++
		}

		// Settle the blocklist from the final state. Without this, a host
		// deactivated DURING the sweep can leave its peers holding the old
		// fingerprint while it carries a fresh, unblocklisted certificate --
		// the silent un-revocation this phase exists to prevent, in its race
		// form.
		sm.regenerateNetworkHostConfigs(network.Id, "")
	}

	sm.logger.Success("Re-signed %d host certificate(s) under CA %s", resigned, ca.GetString("name"))
}
