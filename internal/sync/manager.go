// Package sync handles synchronization between PocketBase and Nebula config generation
package sync

import (
	"encoding/json"
	"fmt"
	stdsync "sync"

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
type Manager struct {
	app           *pocketbase.PocketBase // PocketBase application instance
	certManager   *cert.Manager          // Certificate generation service
	configGen     *config.Generator      // Config generation service
	ipamManager   *ipam.Manager          // IP validation service
	options       types.Options          // Configuration options
	logger        *utils.Logger          // Logger for consistent output
	internalSaves stdsync.Map            // record IDs currently being saved by pb-nebula itself
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
// - Creation: Generate CA certificate and keys automatically after record is saved
func (sm *Manager) setupCAHooks() {
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

		sm.logger.Info("Network CIDR changed for %s, regenerating host configs...", e.Record.GetString("name"))
		sm.regenerateNetworkHostConfigs(e.Record.Id, "")

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

		// New active lighthouse - peers need it in their static_host_map
		if e.Record.GetBool("is_lighthouse") && e.Record.GetBool("active") {
			sm.logger.Config("New lighthouse %s, regenerating peer configs...", e.Record.GetString("hostname"))
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
			if orig.GetInt("validity_years") != e.Record.GetInt("validity_years") && e.Record.GetInt("validity_years") > 0 {
				sm.logger.Info("Validity years changed for host %s, regenerating certificate", e.Record.GetString("hostname"))
				needsCertRegeneration = true
			}

			// Check if only CONFIG regeneration is needed (cheap - just YAML)
			if !needsCertRegeneration {
				if orig.GetBool("is_lighthouse") != e.Record.GetBool("is_lighthouse") {
					sm.logger.Info("Lighthouse status changed for host %s, regenerating config", e.Record.GetString("hostname"))
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
		} else {
			// If we don't have original data, regenerate cert to be safe
			sm.logger.Info("No original data available for host %s, regenerating certificate", e.Record.GetString("hostname"))
			needsCertRegeneration = true
		}

		if !needsCertRegeneration && !needsConfigRegeneration && !needsPeerFanOut {
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

		if e.Record.GetBool("is_lighthouse") && e.Record.GetBool("active") {
			sm.logger.Config("Lighthouse %s deleted, regenerating peer configs...", e.Record.GetString("hostname"))
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

	// Validate groups is valid JSON array
	groupsJSON := record.GetString("groups")
	if groupsJSON != "" && groupsJSON != "null" {
		var groups []string
		if err := json.Unmarshal([]byte(groupsJSON), &groups); err != nil {
			return fmt.Errorf("groups must be a valid JSON array of strings: %w", err)
		}
	}

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

	// Generate host certificate (expiry is clamped to the CA cert's NotAfter)
	certResult, err := sm.certManager.GenerateHostCert(cert.HostCertParams{
		Hostname:        record.GetString("hostname"),
		OverlayIP:       record.GetString("overlay_ip"),
		Groups:          groups,
		ValidityYears:   validityYears,
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

	// Query lighthouses in this network
	lighthouses, err := sm.getLighthouses(network.Id)
	if err != nil {
		return fmt.Errorf("failed to get lighthouses: %w", err)
	}

	// Convert records to models
	hostModel := sm.recordToHostModel(record)

	// Generate config (now uses host-level firewall rules)
	configYAML, err := sm.configGen.GenerateHostConfig(hostModel, lighthouses)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrConfigGeneration, err)
	}

	record.Set("config_yaml", configYAML)
	return nil
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
		PublicHostPort:   record.GetString("public_host_port"),
		Certificate:      record.GetString("certificate"),
		PrivateKey:       privateKey,
		CACertificate:    record.GetString("ca_certificate"),
		ConfigYAML:       record.GetString("config_yaml"),
		FirewallOutbound: record.GetString("firewall_outbound"),
		FirewallInbound:  record.GetString("firewall_inbound"),
	}
}
