// Package sync handles synchronization between PocketBase and Nebula config generation
package sync

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	stdsync "sync"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/skeeeon/pb-nebula/internal/cert"
	"github.com/skeeeon/pb-nebula/internal/config"
	"github.com/skeeeon/pb-nebula/internal/ipam"
	"github.com/skeeeon/pb-nebula/internal/types"
	"github.com/skeeeon/pb-nebula/internal/utils"
)

// Manager orchestrates real-time synchronization between PocketBase record changes
// and Nebula certificate/config generation.
//
// SYNCHRONIZATION STRATEGY:
//   - PocketBase Record Change → Certificate Generation → Config Generation
//   - Automatic generation on create/update
//   - Network CIDR changes trigger regeneration of all host configs
//   - Lighthouse changes trigger regeneration of peer host configs (their
//     static_host_map and lighthouse sections embed lighthouse data)
//
// RECURSION PREVENTION:
// Saves issued by pb-nebula itself (cert/config regeneration, peer fan-out)
// re-fire the update hooks, and e.Record.Original() inside those re-fired
// hooks still holds the PRE-REQUEST snapshot — so any field-diff check that
// triggered once would trigger again on the re-entry, looping forever. All
// internal writes therefore go through saveInternal, which marks the record
// ID in internalSaves; the update hook skips events for marked records.
//
// SERIALIZATION (generation mutex) — SECOND LOAD-BEARING INVARIANT:
// internalSaves is a set keyed by record ID and cleared by an unconditional
// defer, which is only safe while pb-nebula's own writes never overlap. The
// renewal cron broke that assumption: it writes host records on a schedule,
// concurrently with whatever an operator is doing. Three races follow — a
// dropped regeneration (the operator's hook sees the cron's mark and skips a
// real edit), a lost mark (the first defer clears while a second save for the
// same ID is still inside Save), and a lost update (the cron writes a record it
// loaded before the operator's edit).
//
// The generation mutex closes all three by serializing every generate-and-save
// sequence. This control plane does a handful of writes a minute, so the cost
// is nothing.
//
// The invariant: acquire it ONLY at top-level entry points (cron tick, the
// host/network/CA hooks), ALWAYS after the isInternalSave check, and NEVER
// inside saveInternal or anything it re-enters. Go mutexes are not reentrant,
// so a nested hook that reached Lock() would deadlock against its own caller.
// The isInternalSave guard is what stops that: a re-fired hook returns before
// it gets there.
type Manager struct {
	app           *pocketbase.PocketBase // PocketBase application instance
	certManager   *cert.Manager          // Certificate generation service
	configGen     *config.Generator      // Config generation service
	ipamManager   *ipam.Manager          // IP validation service
	options       types.Options          // Configuration options
	logger        *utils.Logger          // Logger for consistent output
	internalSaves stdsync.Map            // record IDs currently being saved by pb-nebula itself
	generation    stdsync.Mutex          // serializes generate-and-save sequences; see above
}

// saveInternal saves a record while marking it as a pb-nebula-initiated write,
// so the update hooks it re-fires are skipped (see RECURSION PREVENTION on
// Manager). PocketBase hooks run synchronously within Save, so the mark is
// guaranteed to still be set when the nested hook executes.
func (sm *Manager) saveInternal(record *core.Record) error {
	sm.internalSaves.Store(record.Id, struct{}{})
	defer sm.internalSaves.Delete(record.Id)
	return sm.app.Save(record)
}

// isInternalSave reports whether an event was triggered by saveInternal.
func (sm *Manager) isInternalSave(record *core.Record) bool {
	_, ok := sm.internalSaves.Load(record.Id)
	return ok
}

// NewManager creates a new sync manager with all required dependencies.
//
// PARAMETERS:
//   - app: PocketBase application instance
//   - certManager: Certificate manager for generating certificates
//   - configGen: Config generator for generating Nebula configs
//   - ipamManager: IPAM manager for IP validation
//   - options: Configuration options
//   - logger: Logger instance
//
// RETURNS:
// - Manager instance ready for hook setup
func NewManager(app *pocketbase.PocketBase, certManager *cert.Manager, configGen *config.Generator,
	ipamManager *ipam.Manager, options types.Options, logger *utils.Logger) *Manager {
	return &Manager{
		app:         app,
		certManager: certManager,
		configGen:   configGen,
		ipamManager: ipamManager,
		options:     options,
		logger:      logger,
	}
}

// SetupHooks registers PocketBase event hooks for real-time Nebula synchronization.
//
// HOOK CATEGORIES:
// - CA hooks: Handle CA creation
// - Network hooks: Handle network lifecycle and validation
// - Host hooks: Handle host lifecycle, certificate generation, and config generation
//
// RETURNS:
// - nil on successful hook registration
// - error if hook setup fails
func (sm *Manager) SetupHooks() error {
	sm.logger.Info("Setting up PocketBase hooks for Nebula sync...")

	// Setup hooks for each collection type
	sm.setupCAHooks()
	sm.setupNetworkHooks()
	sm.setupHostHooks()

	sm.logger.Success("PocketBase hooks configured for Nebula sync")

	return nil
}

// setupCAHooks registers hooks for CA lifecycle.
//
// CA EVENT HANDLING:
// - Validation: reject illegal rotation verbs and hand-edits of managed fields
// - Creation: Generate CA certificate and keys automatically after record is saved
// - Rotation: perform the requested rotation step and reset the action field
func (sm *Manager) setupCAHooks() {
	// Rotation validation. This belongs in the REQUEST hooks because
	// OnRecordAfterUpdateSuccess runs after the write has committed and so
	// cannot refuse anything -- the same split validateHostRecord uses.
	sm.app.OnRecordCreateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.CACollectionName {
			return e.Next()
		}
		if err := sm.validateCARotation(e.Record, nil); err != nil {
			return err
		}
		return e.Next()
	})

	sm.app.OnRecordUpdateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.CACollectionName {
			return e.Next()
		}
		if err := sm.validateCARotation(e.Record, e.Record.Original()); err != nil {
			return err
		}
		return e.Next()
	})

	// Rotation execution
	sm.app.OnRecordAfterUpdateSuccess().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().Name != sm.options.CACollectionName {
			return e.Next()
		}

		// CRITICAL, and not optional: the CA CREATE hook below calls
		// saveInternal on an already-persisted record, which fires an update
		// event. Without this guard, creating a CA would enter the rotation
		// path. It is also what keeps the generation mutex from deadlocking
		// against itself, since a re-fired hook returns before reaching Lock.
		if sm.isInternalSave(e.Record) {
			return e.Next()
		}

		if !sm.shouldHandleEvent(sm.options.CACollectionName, types.EventTypeCARotate) {
			return e.Next()
		}

		// Key on the TRANSITION, not the value. This hook runs after the
		// commit, so a crash between the two leaves `rotate` durably set --
		// and without this check the next unrelated CA edit would fire a
		// rotation nobody asked for. Same reason the network CIDR check
		// compares against Original().
		orig := e.Record.Original()
		verb := e.Record.GetString("rotate")
		if verb == "" || (orig != nil && orig.GetString("rotate") == verb) {
			return e.Next()
		}

		sm.generation.Lock()
		defer sm.generation.Unlock()

		if err := sm.rotateCA(e.Record, verb); err != nil {
			sm.logger.Error("CA rotation (%s) failed for %s: %v", verb, e.Record.GetString("name"), err)
		}

		return e.Next()
	})

	// CA creation - generate certificate automatically
	sm.app.OnRecordAfterCreateSuccess().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().Name != sm.options.CACollectionName {
			return e.Next()
		}

		// Skip if certificate already exists
		if e.Record.GetString("certificate") != "" {
			return e.Next()
		}

		sm.logger.Cert("Generating CA certificate for %s...", e.Record.GetString("name"))

		// Generate CA certificate
		if err := sm.generateCA(e.Record); err != nil {
			sm.logger.Error("Failed to generate CA certificate: %v", err)
			return fmt.Errorf("failed to generate CA certificate: %w", err)
		}

		if err := sm.saveInternal(e.Record); err != nil {
			return fmt.Errorf("failed to save CA record: %w", err)
		}

		sm.logger.Success("Generated CA certificate for %s", e.Record.GetString("name"))

		return e.Next()
	})
}

// setupNetworkHooks registers hooks for network lifecycle and validation.
//
// NETWORK EVENT HANDLING:
// - Validation: Validate CIDR format before creation/update
// - Updates: Regenerate configs for all hosts in network (only if CIDR changes)
func (sm *Manager) setupNetworkHooks() {
	// Network validation - validate CIDR before creation/update
	sm.app.OnRecordCreateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.NetworkCollectionName {
			return e.Next()
		}

		if err := sm.validateNetworkRecord(e.Record); err != nil {
			return err
		}

		return e.Next()
	})

	sm.app.OnRecordUpdateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.NetworkCollectionName {
			return e.Next()
		}

		if err := sm.validateNetworkRecord(e.Record); err != nil {
			return err
		}

		return e.Next()
	})

	// Network updates - regenerate all host configs ONLY if the CIDR changed.
	// Other fields like name/description don't affect host configs.
	sm.app.OnRecordAfterUpdateSuccess().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().Name != sm.options.NetworkCollectionName {
			return e.Next()
		}

		if !sm.shouldHandleEvent(sm.options.NetworkCollectionName, types.EventTypeNetworkUpdate) {
			return e.Next()
		}

		orig := e.Record.Original()
		if orig != nil && orig.GetString("cidr_range") == e.Record.GetString("cidr_range") {
			return e.Next()
		}

		sm.generation.Lock()
		defer sm.generation.Unlock()

		sm.logger.Info("Network CIDR changed for %s, regenerating host configs...", e.Record.GetString("name"))
		sm.regenerateNetworkHostConfigs(e.Record.Id, "")

		// A new CIDR changes the mask every host certificate should carry, and
		// regenerating configs re-signs nothing. Say so rather than leaving the
		// fleet quietly unable to route.
		sm.AuditHostCertNetworkMasks(e.Record.Id)

		return e.Next()
	})
}

// setupHostHooks registers hooks for host lifecycle, validation, and certificate/config generation.
//
// HOST EVENT HANDLING:
// - Creation: Generate certificate and config automatically after record is saved
// - Validation: Validate IP, lighthouse requirements before creation/update
// - Updates: Regenerate certificate or config when meaningful fields change
// - Deletion: Regenerate peer configs when an active lighthouse is removed
//
// REGENERATION TIERS:
//   - Certificate (expensive): hostname, overlay_ip, groups, validity_years —
//     these are embedded in the certificate itself
//   - Config only (cheap): is_lighthouse, public_host_port, firewall rules
//   - Peer fan-out: lighthouse-relevant changes (is_lighthouse, active,
//     public_host_port, overlay_ip on a lighthouse) regenerate every other
//     host's config in the network, since peers embed lighthouse data
//
// RECURSION PREVENTION:
// - Skip update processing if triggered by our own save during creation
// - Fan-out saves only touch config_yaml, which never triggers regeneration
func (sm *Manager) setupHostHooks() {
	// A host is born active.
	//
	// PocketBase bools have no schema-level default, so a create that omits
	// `active` lands as false -- and every host minted through the API omits it,
	// because nothing in the payload suggests it is required. That was nearly
	// harmless while `active` only gated getLighthouses: a non-lighthouse host
	// worked fine with the flag clear. It stopped being harmless when `active`
	// started driving pki.blocklist, because a freshly issued certificate would
	// then be blocklisted by every peer from the moment it was created.
	//
	// Forced rather than defaulted-if-absent for the reason PocketBase makes
	// unavoidable: by the time a hook sees the record, "field omitted" and
	// "explicitly false" are indistinguishable. Creating a host that is already
	// revoked is not a meaningful operation anyway -- deactivation is an update.
	sm.app.OnRecordCreate().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().Name != sm.options.HostCollectionName {
			return e.Next()
		}
		e.Record.Set("active", true)
		return e.Next()
	})

	// Host validation - validate IP, lighthouse requirements, and groups format
	sm.app.OnRecordCreateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.HostCollectionName {
			return e.Next()
		}

		if err := sm.validateHostRecord(e.Record); err != nil {
			return err
		}

		return e.Next()
	})

	sm.app.OnRecordUpdateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.HostCollectionName {
			return e.Next()
		}

		if err := sm.validateHostRecord(e.Record); err != nil {
			return err
		}

		return e.Next()
	})

	// Host creation - generate certificate and config
	sm.app.OnRecordAfterCreateSuccess().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().Name != sm.options.HostCollectionName {
			return e.Next()
		}

		// Skip if certificate already exists
		if e.Record.GetString("certificate") != "" {
			return e.Next()
		}

		sm.generation.Lock()
		defer sm.generation.Unlock()

		sm.logger.Cert("Generating certificate and config for host %s...", e.Record.GetString("hostname"))

		// Generate host certificate and config
		if err := sm.generateHostCertAndConfig(e.Record); err != nil {
			sm.logger.Error("Failed to generate host certificate/config: %v", err)
			return fmt.Errorf("failed to generate host certificate/config: %w", err)
		}

		if err := sm.saveInternal(e.Record); err != nil {
			return fmt.Errorf("failed to save host record: %w", err)
		}

		sm.logger.Success("Generated certificate and config for host %s", e.Record.GetString("hostname"))

		// A new active lighthouse or relay changes what every peer renders:
		// lighthouses land in static_host_map and the lighthouse section,
		// relays in the relay section
		if (e.Record.GetBool("is_lighthouse") || e.Record.GetBool("is_relay")) && e.Record.GetBool("active") {
			sm.logger.Config("New lighthouse/relay %s, regenerating peer configs...", e.Record.GetString("hostname"))
			sm.regenerateNetworkHostConfigs(e.Record.GetString("network_id"), e.Record.Id)
		}

		return e.Next()
	})

	// Host updates - regenerate certificate OR config depending on what changed
	sm.app.OnRecordAfterUpdateSuccess().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().Name != sm.options.HostCollectionName {
			return e.Next()
		}

		// CRITICAL: Skip events from our own saves. Original() in a re-fired
		// hook still holds the pre-request snapshot, so re-running the diff
		// checks below would loop forever (see RECURSION PREVENTION on Manager).
		if sm.isInternalSave(e.Record) {
			return e.Next()
		}

		// Serialize against the renewal cron. MUST come after isInternalSave:
		// a re-fired hook returns above and so never reaches this Lock, which
		// is what keeps a non-reentrant mutex from deadlocking on itself.
		sm.generation.Lock()
		defer sm.generation.Unlock()

		orig := e.Record.Original()

		// CRITICAL: Skip if certificate was JUST generated (prevents recursion during creation)
		// Only skip if: certificate went from empty -> populated (initial generation)
		if orig != nil &&
			orig.GetString("certificate") == "" &&
			e.Record.GetString("certificate") != "" {
			sm.logger.Info("Skipping regeneration for %s (initial certificate generation)", e.Record.GetString("hostname"))
			return e.Next()
		}

		// Check if event should be handled by user-defined filter
		if !sm.shouldHandleEvent(sm.options.HostCollectionName, types.EventTypeHostUpdate) {
			return e.Next()
		}

		needsCertRegeneration := false
		needsConfigRegeneration := false
		needsPeerFanOut := false
		needsRenewReset := false

		if orig != nil {
			// Check if CERTIFICATE regeneration is needed (expensive - new cert).
			// These fields are embedded in the certificate itself.
			if orig.GetString("hostname") != e.Record.GetString("hostname") {
				sm.logger.Info("Hostname changed for host %s, regenerating certificate", e.Record.GetString("hostname"))
				needsCertRegeneration = true
			}
			if orig.GetString("overlay_ip") != e.Record.GetString("overlay_ip") {
				sm.logger.Info("Overlay IP changed for host %s, regenerating certificate", e.Record.GetString("hostname"))
				needsCertRegeneration = true
			}
			if orig.GetString("groups") != e.Record.GetString("groups") {
				sm.logger.Info("Groups changed for host %s, regenerating certificate", e.Record.GetString("hostname"))
				needsCertRegeneration = true
			}
			// unsafe_networks is signed INTO the certificate -- Nebula
			// authorizes routing on the cert, so an edit here is completely
			// inert until a new certificate is issued
			if orig.GetString("unsafe_networks") != e.Record.GetString("unsafe_networks") {
				sm.logger.Info("Unsafe networks changed for host %s, regenerating certificate", e.Record.GetString("hostname"))
				needsCertRegeneration = true
			}
			if orig.GetInt("validity_years") != e.Record.GetInt("validity_years") && e.Record.GetInt("validity_years") > 0 {
				sm.logger.Info("Validity years changed for host %s, regenerating certificate", e.Record.GetString("hostname"))
				needsCertRegeneration = true
			}

			// Action field: force an immediate re-issue regardless of how much
			// lifetime is left. Keyed on the false -> true transition, and
			// reset below so the flag never stays set. This is the manual lever
			// the platform and the Admin UI both use, and it needs no new Go
			// API or HTTP route to expose.
			if !orig.GetBool("renew") && e.Record.GetBool("renew") &&
				sm.shouldHandleEvent(sm.options.HostCollectionName, types.EventTypeHostRenew) {
				sm.logger.Cert("Renewal requested for host %s, regenerating certificate", e.Record.GetString("hostname"))
				needsCertRegeneration = true
			}
			// Reset unconditionally: a renew that was skipped by the event
			// filter should not stay pending forever either.
			if e.Record.GetBool("renew") {
				e.Record.Set("renew", false)
				needsRenewReset = true
			}

			// Check if only CONFIG regeneration is needed (cheap - just YAML)
			if !needsCertRegeneration {
				if orig.GetBool("is_lighthouse") != e.Record.GetBool("is_lighthouse") {
					sm.logger.Info("Lighthouse status changed for host %s, regenerating config", e.Record.GetString("hostname"))
					needsConfigRegeneration = true
				}
				// The peer fan-out below deliberately excludes this record, so
				// the host's OWN config has to be regenerated here or it keeps
				// am_relay after it stops being a relay -- still relaying for
				// peers that no longer list it.
				if orig.GetBool("is_relay") != e.Record.GetBool("is_relay") {
					sm.logger.Info("Relay status changed for host %s, regenerating config", e.Record.GetString("hostname"))
					needsConfigRegeneration = true
				}
				if orig.GetString("public_host_port") != e.Record.GetString("public_host_port") {
					sm.logger.Info("Public host/port changed for host %s, regenerating config", e.Record.GetString("hostname"))
					needsConfigRegeneration = true
				}
				if orig.GetString("firewall_outbound") != e.Record.GetString("firewall_outbound") {
					sm.logger.Info("Firewall outbound rules changed for host %s, regenerating config", e.Record.GetString("hostname"))
					needsConfigRegeneration = true
				}
				if orig.GetString("firewall_inbound") != e.Record.GetString("firewall_inbound") {
					sm.logger.Info("Firewall inbound rules changed for host %s, regenerating config", e.Record.GetString("hostname"))
					needsConfigRegeneration = true
				}
				if orig.GetInt("mtu") != e.Record.GetInt("mtu") {
					sm.logger.Info("MTU changed for host %s, regenerating config", e.Record.GetString("hostname"))
					needsConfigRegeneration = true
				}
				if orig.GetString("tun_device") != e.Record.GetString("tun_device") {
					sm.logger.Info("Tun device changed for host %s, regenerating config", e.Record.GetString("hostname"))
					needsConfigRegeneration = true
				}
				// The consumer half of gateway routing lives only in this
				// host's own config -- no peer embeds it, so no fan-out
				if orig.GetString("unsafe_routes") != e.Record.GetString("unsafe_routes") {
					sm.logger.Info("Unsafe routes changed for host %s, regenerating config", e.Record.GetString("hostname"))
					needsConfigRegeneration = true
				}
			}

			// Deactivating a host revokes its certificate, and revocation in
			// Nebula lives in every OTHER host's pki.blocklist -- so an active
			// flip on ANY host, lighthouse or not, makes every peer config in the
			// network stale. This used to fan out only for lighthouses, which is
			// why active was a flag that removed a host from lighthouse lists and
			// otherwise did nothing: the certificate stayed trusted until expiry.
			// The host's own config is regenerated too, because the fan-out
			// deliberately excludes the record that changed.
			if orig.GetBool("active") != e.Record.GetBool("active") {
				sm.logger.Info("Active flag changed for host %s, refreshing revocation blocklist across the network", e.Record.GetString("hostname"))
				needsConfigRegeneration = true
				needsPeerFanOut = true
			}

			// Reactivation needs a NEW certificate, not just a config refresh.
			// A deactivated host is skipped by the CA rotation re-sign sweep on
			// purpose (re-signing it would change the fingerprint its peers
			// blocklist), so a host parked across a rotation comes back holding
			// a certificate signed by a CA that may since have been retired --
			// off the blocklist, looking healthy in the Admin UI, and able to
			// handshake with nobody. Its certificate may also simply have
			// expired while it was parked. Either way, re-issue.
			if !orig.GetBool("active") && e.Record.GetBool("active") {
				sm.logger.Info("Host %s reactivated, regenerating certificate", e.Record.GetString("hostname"))
				needsCertRegeneration = true
			}

			// Check if peer configs are now stale. Peers embed this host's
			// lighthouse data (overlay_ip -> public_host_port) in their own
			// configs, so changes to a lighthouse must fan out.
			if orig.GetBool("is_lighthouse") || e.Record.GetBool("is_lighthouse") {
				if orig.GetBool("is_lighthouse") != e.Record.GetBool("is_lighthouse") ||
					orig.GetBool("active") != e.Record.GetBool("active") ||
					orig.GetString("public_host_port") != e.Record.GetString("public_host_port") ||
					orig.GetString("overlay_ip") != e.Record.GetString("overlay_ip") {
					needsPeerFanOut = true
				}
			}

			// Same shape for relays: peers list this host's overlay_ip in their
			// relay section, so becoming or ceasing to be a relay -- or moving
			// -- makes every peer config in the network stale. public_host_port
			// is absent here on purpose: unlike a lighthouse, a relay's address
			// is not embedded in peer configs, only its overlay IP is.
			if orig.GetBool("is_relay") || e.Record.GetBool("is_relay") {
				if orig.GetBool("is_relay") != e.Record.GetBool("is_relay") ||
					orig.GetBool("active") != e.Record.GetBool("active") ||
					orig.GetString("overlay_ip") != e.Record.GetString("overlay_ip") {
					needsPeerFanOut = true
				}
			}
		} else {
			// If we don't have original data, regenerate cert to be safe
			sm.logger.Info("No original data available for host %s, regenerating certificate", e.Record.GetString("hostname"))
			needsCertRegeneration = true
		}

		if !needsCertRegeneration && !needsConfigRegeneration && !needsPeerFanOut {
			// A renew flag that produced no regeneration still has to be cleared,
			// or it stays set and fires again on the next unrelated edit.
			if needsRenewReset {
				if err := sm.saveInternal(e.Record); err != nil {
					sm.logger.Warning("Failed to reset renew flag for host %s: %v", e.Record.Id, err)
				}
				return e.Next()
			}
			sm.logger.Info("No meaningful changes detected for host %s, skipping regeneration", e.Record.GetString("hostname"))
			return e.Next()
		}

		// Regenerate certificate (which also regenerates config)
		if needsCertRegeneration {
			sm.logger.Cert("Regenerating certificate and config for host %s...", e.Record.GetString("hostname"))

			if err := sm.generateHostCertAndConfig(e.Record); err != nil {
				sm.logger.Error("Failed to regenerate certificate for host %s: %v", e.Record.Id, err)
				return e.Next()
			}

			if err := sm.saveInternal(e.Record); err != nil {
				sm.logger.Warning("Failed to save host %s: %v", e.Record.Id, err)
			}

			sm.logger.Success("Regenerated certificate and config for host %s", e.Record.GetString("hostname"))
		} else if needsConfigRegeneration {
			// Only regenerate config (cheaper operation)
			sm.logger.Config("Regenerating config for host %s...", e.Record.GetString("hostname"))

			if err := sm.generateHostConfig(e.Record); err != nil {
				sm.logger.Warning("Failed to regenerate config for host %s: %v", e.Record.Id, err)
				return e.Next()
			}

			if err := sm.saveInternal(e.Record); err != nil {
				sm.logger.Warning("Failed to save host %s: %v", e.Record.Id, err)
			}

			sm.logger.Success("Regenerated config for host %s", e.Record.GetString("hostname"))
		}

		// Fan out to peers AFTER this host's own regeneration so peers see
		// the host's final state (e.g. updated overlay_ip)
		if needsPeerFanOut {
			sm.logger.Config("Lighthouse settings changed for host %s, regenerating peer configs...", e.Record.GetString("hostname"))
			sm.regenerateNetworkHostConfigs(e.Record.GetString("network_id"), e.Record.Id)
		}

		return e.Next()
	})

	// Host deletion - removing an active lighthouse leaves stale entries in
	// peer static_host_maps, so regenerate them
	sm.app.OnRecordAfterDeleteSuccess().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().Name != sm.options.HostCollectionName {
			return e.Next()
		}

		if !sm.shouldHandleEvent(sm.options.HostCollectionName, types.EventTypeHostDelete) {
			return e.Next()
		}

		sm.generation.Lock()
		defer sm.generation.Unlock()

		if (e.Record.GetBool("is_lighthouse") || e.Record.GetBool("is_relay")) && e.Record.GetBool("active") {
			sm.logger.Config("Lighthouse/relay %s deleted, regenerating peer configs...", e.Record.GetString("hostname"))
			sm.regenerateNetworkHostConfigs(e.Record.GetString("network_id"), e.Record.Id)
		}

		return e.Next()
	})
}

// validateNetworkRecord validates a network record before create/update.
// Returned errors wrap the sentinel errors from internal/types.
func (sm *Manager) validateNetworkRecord(record *core.Record) error {
	if err := sm.ipamManager.ValidateNetworkCIDR(record.GetString("cidr_range")); err != nil {
		return fmt.Errorf("CIDR validation failed: %w", err)
	}
	return nil
}

// validateHostRecord validates a host record before create/update.
// Checks IP assignment, lighthouse requirements, and groups format.
// Returned errors wrap the sentinel errors from internal/types.
func (sm *Manager) validateHostRecord(record *core.Record) error {
	// Validate IP is well-formed and within the network CIDR
	if err := sm.ipamManager.ValidateHostIP(record.GetString("overlay_ip"), record.GetString("network_id")); err != nil {
		return fmt.Errorf("IP validation failed: %w", err)
	}

	// Validate lighthouse requirements
	if record.GetBool("is_lighthouse") && record.GetString("public_host_port") == "" {
		return types.ErrLighthouseNoPublicIP
	}

	// A relay needs a stable listening port for the same practical reason a
	// lighthouse does. Rejecting here rather than accepting and rendering
	// listen.port 0 keeps this from failing silently: the relay would be
	// advertised to every peer and then be unreachable at the port they try.
	if record.GetBool("is_relay") && record.GetString("public_host_port") == "" {
		return types.ErrRelayNoPublicIP
	}

	// Validate groups is valid JSON array
	groupsJSON := record.GetString("groups")
	if groupsJSON != "" && groupsJSON != "null" {
		var groups []string
		if err := json.Unmarshal([]byte(groupsJSON), &groups); err != nil {
			return fmt.Errorf("groups must be a valid JSON array of strings: %w", err)
		}
	}

	// Gateway routing. The two halves are validated independently because they
	// live on different hosts: unsafe_networks is what THIS host may route for
	// (and is signed into its certificate), unsafe_routes is what it sends to
	// other hosts.
	hostModel := &types.HostRecord{
		UnsafeNetworks: record.GetString("unsafe_networks"),
		UnsafeRoutes:   record.GetString("unsafe_routes"),
	}

	unsafeNetworks, err := hostModel.GetUnsafeNetworks()
	if err != nil {
		return fmt.Errorf("%w: unsafe_networks must be a JSON array of CIDR strings: %v",
			types.ErrInvalidUnsafeNetwork, err)
	}
	if err := sm.ipamManager.ValidateUnsafeNetworks(unsafeNetworks, record.GetString("network_id")); err != nil {
		return err
	}

	unsafeRoutes, err := hostModel.GetUnsafeRoutes()
	if err != nil {
		return fmt.Errorf("%w: unsafe_routes must be a JSON array of {route, via} objects: %v",
			types.ErrInvalidUnsafeRoute, err)
	}
	if err := sm.ipamManager.ValidateUnsafeRoutes(unsafeRoutes, record.GetString("network_id")); err != nil {
		return err
	}

	// Advisory only: the gateway's certificate may legitimately be updated after
	// the route is added, so this never blocks the write
	sm.warnOnUnroutableUnsafeRoutes(record, unsafeRoutes)

	return nil
}

// regenerateNetworkHostConfigs regenerates and saves config_yaml for every host
// in a network, optionally excluding one host (the record that triggered the
// fan-out, which handles its own regeneration).
//
// Failures on individual hosts are logged and skipped so one bad record
// doesn't block the rest of the network.
func (sm *Manager) regenerateNetworkHostConfigs(networkID, excludeHostID string) {
	hosts, err := sm.app.FindAllRecords(sm.options.HostCollectionName,
		dbx.HashExp{"network_id": networkID})
	if err != nil {
		sm.logger.Warning("Failed to find hosts in network %s: %v", networkID, err)
		return
	}

	regenerated := 0
	total := 0
	for _, host := range hosts {
		if host.Id == excludeHostID {
			continue
		}
		total++
		if err := sm.generateHostConfig(host); err != nil {
			sm.logger.Warning("Failed to regenerate config for host %s: %v", host.Id, err)
			continue
		}
		if err := sm.saveInternal(host); err != nil {
			sm.logger.Warning("Failed to save host %s: %v", host.Id, err)
			continue
		}
		regenerated++
	}

	sm.logger.Success("Regenerated configs for %d/%d hosts in network %s", regenerated, total, networkID)
}

// generateCA generates CA certificate and updates the record.
// The CA private_key is encrypted at rest if Options.EncryptionKey is set.
func (sm *Manager) generateCA(record *core.Record) error {
	name := record.GetString("name")
	validityYears := record.GetInt("validity_years")
	if validityYears == 0 {
		validityYears = sm.options.DefaultCAValidityYears
	}

	result, err := sm.certManager.GenerateCA(name, validityYears)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrCertGeneration, err)
	}

	record.Set("certificate", result.CertificatePEM)
	if err := types.EncryptAndSet(record, "private_key", result.PrivateKeyPEM, sm.options.EncryptionKey); err != nil {
		return err
	}
	record.Set("expires_at", result.ExpiresAt)
	record.Set("curve", "CURVE25519")
	if validityYears > 0 {
		record.Set("validity_years", validityYears)
	}

	return nil
}

// generateHostCertAndConfig generates host certificate and config, updating the record.
// The CA private key is decrypted on read; the host private_key is encrypted before
// it is written back to the record.
//
// ORDERING NOTE:
// The host private key is set as plaintext temporarily so generateHostConfig can read
// it via recordToHostModel and embed it into config_yaml. It is encrypted on the
// record afterwards, before the caller saves.
func (sm *Manager) generateHostCertAndConfig(record *core.Record) error {
	// Get network and CA
	network, err := sm.app.FindRecordById(sm.options.NetworkCollectionName, record.GetString("network_id"))
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrNetworkNotFound, err)
	}

	ca, err := sm.app.FindRecordById(sm.options.CACollectionName, network.GetString("ca_id"))
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrCANotFound, err)
	}

	// Decrypt CA private key for signing (no-op if encryption disabled or already plaintext)
	caPrivateKeyPEM, err := types.DecryptField(ca.GetString("private_key"), sm.options.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt CA private key: %w", err)
	}

	// Parse groups from JSON
	var groups []string
	groupsJSON := record.GetString("groups")
	if groupsJSON != "" && groupsJSON != "null" {
		if err := json.Unmarshal([]byte(groupsJSON), &groups); err != nil {
			return fmt.Errorf("failed to parse groups: %w", err)
		}
	}

	// Get validity years
	validityYears := record.GetInt("validity_years")
	if validityYears == 0 {
		validityYears = sm.options.DefaultHostValidityYears
	}

	// Prefixes this host may route for. These are signed INTO the certificate:
	// Nebula authorizes routing on the cert, so a gateway whose cert omits a
	// prefix silently refuses to route it.
	unsafeNetworks, err := sm.parseUnsafeNetworks(record)
	if err != nil {
		return err
	}

	// Generate host certificate (expiry is clamped to the CA cert's NotAfter)
	certResult, err := sm.certManager.GenerateHostCert(cert.HostCertParams{
		Hostname:      record.GetString("hostname"),
		OverlayIP:     record.GetString("overlay_ip"),
		Groups:        groups,
		ValidityYears: validityYears,
		// The mask Nebula builds the host's overlay route from. Sourced from
		// the network record on every signing rather than stored on the host,
		// so a corrected CIDR reaches a host the next time it is re-signed.
		NetworkCIDR:     network.GetString("cidr_range"),
		UnsafeNetworks:  unsafeNetworks,
		CACertPEM:       ca.GetString("certificate"),
		CAPrivateKeyPEM: caPrivateKeyPEM,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrCertGeneration, err)
	}

	// Store certificate and CA cert (denormalized).
	// Set private_key as plaintext temporarily so generateHostConfig can embed it
	// into config_yaml; we encrypt it on the record at the end of this function.
	record.Set("certificate", certResult.CertificatePEM)
	record.Set("private_key", certResult.PrivateKeyPEM)
	record.Set("ca_certificate", ca.GetString("certificate"))
	record.Set("expires_at", certResult.ExpiresAt)
	if validityYears > 0 {
		record.Set("validity_years", validityYears)
	}

	// Generate config (reads plaintext private_key from in-memory record)
	if err := sm.generateHostConfig(record); err != nil {
		return err
	}

	// Encrypt private_key for at-rest storage
	if err := types.EncryptAndSet(record, "private_key", certResult.PrivateKeyPEM, sm.options.EncryptionKey); err != nil {
		return err
	}

	return nil
}

// generateHostConfig generates Nebula config for a host and updates the record.
func (sm *Manager) generateHostConfig(record *core.Record) error {
	// Get network
	network, err := sm.app.FindRecordById(sm.options.NetworkCollectionName, record.GetString("network_id"))
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrNetworkNotFound, err)
	}

	// Trust bundle for pki.ca, read from the CA record on every generation.
	// That is what makes rotation self-healing: any regeneration, for any
	// reason, hands out the CURRENT bundle, so finishing a rotation or
	// recovering a partial one needs no re-signing. A lookup failure is not
	// fatal -- fall back to the denormalized single certificate, matching the
	// never-fatal discipline getBlocklist already follows.
	bundle := ""
	if ca, err := sm.app.FindRecordById(sm.options.CACollectionName, network.GetString("ca_id")); err == nil {
		bundle = caBundle(ca)
	} else {
		sm.logger.Warning("Cannot load CA for network %s, falling back to the host's stored CA certificate: %v",
			network.Id, err)
	}

	// Query lighthouses in this network
	lighthouses, err := sm.getLighthouses(network.Id)
	if err != nil {
		return fmt.Errorf("failed to get lighthouses: %w", err)
	}

	// Relays this host can route through when it cannot hole-punch to a peer
	relays, err := sm.getRelays(network.Id)
	if err != nil {
		return fmt.Errorf("failed to get relays: %w", err)
	}

	// Certificate fingerprints this network refuses. Nebula has no CRL, so a
	// deactivated host is only actually off the mesh once every peer config
	// carries its fingerprint -- see getBlocklist.
	blocklist, err := sm.getBlocklist(network.Id)
	if err != nil {
		// Never fatal: a config without a blocklist is the config this library
		// generated for years, and failing here would stop a host getting ANY
		// config at all.
		sm.logger.Warning("Failed to build revocation blocklist for network %s: %v", network.Id, err)
	}

	// Convert records to models
	hostModel := sm.recordToHostModel(record)

	// Generate config (now uses host-level firewall rules)
	configYAML, err := sm.configGen.GenerateHostConfig(config.HostConfigInput{
		Host:        hostModel,
		Lighthouses: lighthouses,
		Relays:      relays,
		Blocklist:   blocklist,
		CABundle:    bundle,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrConfigGeneration, err)
	}

	record.Set("config_yaml", configYAML)
	return nil
}

// getBlocklist returns the certificate fingerprints of every DEACTIVATED
// host in a network, sorted.
//
// This is the revocation list. Nebula has no CRL and no OCSP: the only way to
// refuse a certificate it has already signed is pki.blocklist, a list of
// fingerprints carried by every other host and loaded into the CA pool at
// startup and again on SIGHUP. Marking a host inactive used to drop it from
// its peers lighthouse lists and nothing else -- its certificate stayed valid
// until it expired, so a decommissioned device kept its place on the mesh.
//
// Sorted so an unchanged network renders a byte-identical config. Without
// that, map iteration order would make every regeneration look like a change.
//
// A host with no certificate yet (mid-creation) is skipped rather than treated
// as an error: there is nothing to revoke.
//
// NOTE the boundary this cannot cross. A DELETED host record takes its
// certificate with it, and a fingerprint absent from the database cannot be
// blocklisted. To take a device off the mesh, DEACTIVATE it; deleting is for
// hosts whose certificate you are content to leave valid until it expires.
func (sm *Manager) getBlocklist(networkID string) ([]string, error) {
	records, err := sm.app.FindAllRecords(sm.options.HostCollectionName,
		dbx.HashExp{"network_id": networkID, "active": false})
	if err != nil {
		return nil, err
	}

	now := time.Now()
	fingerprints := make([]string, 0, len(records))
	for _, record := range records {
		certPEM := record.GetString("certificate")
		if certPEM == "" {
			continue // never issued one; nothing to revoke
		}
		// Drop expired certificates. Nebula refuses an expired certificate on
		// its own, so blocklisting one buys nothing -- and without this the
		// list only ever grows, in a config_yaml field capped at 50000 bytes.
		// Read the validity from the certificate, not from expires_at, for the
		// same reason the expiry clamp does.
		if _, notAfter, err := cert.ValidityFromPEM(certPEM); err == nil && !now.Before(notAfter) {
			continue
		}
		fp, err := cert.FingerprintFromPEM(certPEM)
		if err != nil {
			// One unparseable certificate must not cost the network its whole
			// blocklist, so log it and keep the rest.
			sm.logger.Warning("Cannot fingerprint certificate for host %s, omitting from blocklist: %v", record.Id, err)
			continue
		}
		fingerprints = append(fingerprints, fp)
	}

	sort.Strings(fingerprints)
	return fingerprints, nil
}

// getLighthouses queries all active lighthouse hosts in a network.
func (sm *Manager) getLighthouses(networkID string) ([]types.LighthouseInfo, error) {
	records, err := sm.app.FindAllRecords(sm.options.HostCollectionName,
		dbx.HashExp{"network_id": networkID, "is_lighthouse": true, "active": true})
	if err != nil {
		return nil, err
	}

	lighthouses := make([]types.LighthouseInfo, len(records))
	for i, record := range records {
		lighthouses[i] = types.LighthouseInfo{
			OverlayIP:      record.GetString("overlay_ip"),
			PublicHostPort: record.GetString("public_host_port"),
		}
	}

	return lighthouses, nil
}

// parseUnsafeNetworks reads a host record's unsafe_networks into the prefix type
// the cert package signs. Validation has already run in the request hook, so a
// failure here means the stored JSON is malformed rather than the input was.
//
// PARAMETERS:
//   - record: Host record
//
// RETURNS:
// - []netip.Prefix: Prefixes to embed in the certificate, nil if none
// - error wrapping ErrInvalidUnsafeNetwork if the stored value cannot be parsed
func (sm *Manager) parseUnsafeNetworks(record *core.Record) ([]netip.Prefix, error) {
	raw := record.GetString("unsafe_networks")
	if raw == "" || raw == "null" {
		return nil, nil
	}

	var cidrs []string
	if err := json.Unmarshal([]byte(raw), &cidrs); err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrInvalidUnsafeNetwork, err)
	}

	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", types.ErrInvalidUnsafeNetwork, cidr, err)
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

// warnOnUnroutableUnsafeRoutes logs a warning for each route whose gateway does
// not declare the prefix in its own unsafe_networks.
//
// WHY THIS WARNS RATHER THAN REJECTS:
// The two halves of gateway routing live on different hosts and are configured
// independently, so a route can legitimately be added before the gateway's
// certificate is updated. Rejecting would force a specific ordering; staying
// silent would leave the operator with the failure this whole function exists to
// surface -- Nebula drops the packet with no log line, which reads like a peer
// or LAN outage rather than a configuration error.
//
// Failures to look up a peer are themselves only logged: this is advisory.
//
// SIDE EFFECTS: Logging only.
func (sm *Manager) warnOnUnroutableUnsafeRoutes(record *core.Record, routes []types.UnsafeRoute) {
	if len(routes) == 0 {
		return
	}

	for _, route := range routes {
		peers, err := sm.app.FindAllRecords(sm.options.HostCollectionName,
			dbx.HashExp{"network_id": record.GetString("network_id"), "overlay_ip": route.Via})
		if err != nil || len(peers) == 0 {
			sm.logger.Warning("Host %s routes %s via %s, but no host in this network has that overlay IP",
				record.GetString("hostname"), route.Route, route.Via)
			continue
		}

		gateway := peers[0]
		declared, err := (&types.HostRecord{UnsafeNetworks: gateway.GetString("unsafe_networks")}).GetUnsafeNetworks()
		if err != nil {
			continue
		}

		if !slices.Contains(declared, route.Route) {
			sm.logger.Warning("Host %s routes %s via %s, but %s does not declare %s in unsafe_networks -- "+
				"Nebula will drop this traffic until it does",
				record.GetString("hostname"), route.Route, route.Via,
				gateway.GetString("hostname"), route.Route)
		}
	}
}

// getRelays returns the overlay IPs of every active relay in a network, sorted.
//
// Only active relays are advertised: an inactive host's certificate is
// blocklisted, so naming it as a relay path would hand every peer a route
// through a host none of them will complete a handshake with.
//
// SORTED, FOR THE SAME REASON getBlocklist IS:
// Query order is not guaranteed, and an unsorted list would reorder itself
// between regenerations -- making every config look changed and every peer
// reload for nothing.
//
// PARAMETERS:
//   - networkID: Network to search
//
// RETURNS:
// - []string: Overlay IPs of active relays, sorted
// - error if the query fails
func (sm *Manager) getRelays(networkID string) ([]string, error) {
	records, err := sm.app.FindAllRecords(sm.options.HostCollectionName,
		dbx.HashExp{"network_id": networkID, "is_relay": true, "active": true})
	if err != nil {
		return nil, err
	}

	relays := make([]string, 0, len(records))
	for _, record := range records {
		relays = append(relays, record.GetString("overlay_ip"))
	}
	sort.Strings(relays)

	return relays, nil
}

// shouldHandleEvent determines if an event should be processed based on configured filters.
func (sm *Manager) shouldHandleEvent(collectionName, eventType string) bool {
	if sm.options.EventFilter != nil {
		return sm.options.EventFilter(collectionName, eventType)
	}
	return true
}

// Helper: Convert PocketBase record to host model.
// Decrypts private_key transparently — DecryptField is a no-op on plaintext or
// when encryption is disabled, so this is safe regardless of mode.
func (sm *Manager) recordToHostModel(record *core.Record) *types.HostRecord {
	privateKey, err := types.DecryptField(record.GetString("private_key"), sm.options.EncryptionKey)
	if err != nil {
		sm.logger.Warning("Failed to decrypt private_key for host %s: %v", record.Id, err)
		privateKey = record.GetString("private_key")
	}

	return &types.HostRecord{
		ID:               record.Id,
		Hostname:         record.GetString("hostname"),
		OverlayIP:        record.GetString("overlay_ip"),
		Groups:           record.GetString("groups"),
		IsLighthouse:     record.GetBool("is_lighthouse"),
		IsRelay:          record.GetBool("is_relay"),
		PublicHostPort:   record.GetString("public_host_port"),
		MTU:              record.GetInt("mtu"),
		TunDevice:        record.GetString("tun_device"),
		Certificate:      record.GetString("certificate"),
		PrivateKey:       privateKey,
		CACertificate:    record.GetString("ca_certificate"),
		ConfigYAML:       record.GetString("config_yaml"),
		FirewallOutbound: record.GetString("firewall_outbound"),
		FirewallInbound:  record.GetString("firewall_inbound"),
		UnsafeNetworks:   record.GetString("unsafe_networks"),
		UnsafeRoutes:     record.GetString("unsafe_routes"),
	}
}
