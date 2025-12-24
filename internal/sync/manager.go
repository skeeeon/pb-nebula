// Package sync handles synchronization between PocketBase and Nebula config generation
package sync

import (
	"encoding/json"
	"fmt"

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
// - PocketBase Record Change → Certificate Generation → Config Generation
// - Automatic generation on create/update
// - Network updates trigger regeneration of all host configs
type Manager struct {
	app         *pocketbase.PocketBase // PocketBase application instance
	certManager *cert.Manager          // Certificate generation service
	configGen   *config.Generator      // Config generation service
	ipamManager *ipam.Manager          // IP validation service
	options     types.Options          // Configuration options
	logger      *utils.Logger          // Logger for consistent output
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

		// Generate CA certificate
		if err := sm.generateCA(e.Record); err != nil {
			sm.logger.Error("Failed to generate CA certificate: %v", err)
			return fmt.Errorf("failed to generate CA certificate: %w", err)
		}

		if err := sm.app.Save(e.Record); err != nil {
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
// - Updates: Regenerate configs for all hosts in network
func (sm *Manager) setupNetworkHooks() {
	// Network validation - validate CIDR before creation/update
	sm.app.OnRecordCreateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.NetworkCollectionName {
			return e.Next()
		}

		cidr := e.Record.GetString("cidr_range")
		if err := sm.ipamManager.ValidateCIDRFormat(cidr); err != nil {
			return fmt.Errorf("invalid CIDR format: %w", err)
		}

		if err := sm.ipamManager.ValidateNetworkCIDR(cidr); err != nil {
			return fmt.Errorf("CIDR validation failed: %w", err)
		}

		return e.Next()
	})

	sm.app.OnRecordUpdateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.NetworkCollectionName {
			return e.Next()
		}

		cidr := e.Record.GetString("cidr_range")
		if err := sm.ipamManager.ValidateCIDRFormat(cidr); err != nil {
			return fmt.Errorf("invalid CIDR format: %w", err)
		}

		if err := sm.ipamManager.ValidateNetworkCIDR(cidr); err != nil {
			return fmt.Errorf("CIDR validation failed: %w", err)
		}

		return e.Next()
	})

	// Network updates - regenerate all host configs in network
	sm.app.OnRecordAfterUpdateSuccess().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().Name != sm.options.NetworkCollectionName {
			return e.Next()
		}

		if sm.shouldHandleEvent(sm.options.NetworkCollectionName, types.EventTypeNetworkUpdate) {
			// Find all hosts in this network
			hosts, err := sm.app.FindAllRecords(sm.options.HostCollectionName,
				dbx.HashExp{"network_id": e.Record.Id})
			if err != nil {
				sm.logger.Warning("Failed to find hosts in network %s: %v", e.Record.Id, err)
				return e.Next()
			}

			// Regenerate config for each host
			for _, host := range hosts {
				if err := sm.generateHostConfig(host); err != nil {
					sm.logger.Warning("Failed to regenerate config for host %s: %v", host.Id, err)
					continue
				}
				if err := sm.app.Save(host); err != nil {
					sm.logger.Warning("Failed to save host %s: %v", host.Id, err)
				}
			}

			sm.logger.Success("Regenerated configs for %d hosts in network %s", len(hosts), e.Record.GetString("name"))
		}

		return e.Next()
	})
}

// setupHostHooks registers hooks for host lifecycle, validation, and certificate/config generation.
//
// HOST EVENT HANDLING:
// - Creation: Generate certificate and config automatically after record is saved
// - Validation: Validate IP, lighthouse requirements before creation/update
// - Updates: Regenerate config when host changes
func (sm *Manager) setupHostHooks() {
	// Host validation - validate IP and lighthouse requirements
	sm.app.OnRecordCreateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.HostCollectionName {
			return e.Next()
		}

		// Validate IP format
		if err := sm.ipamManager.ValidateIPFormat(e.Record.GetString("overlay_ip")); err != nil {
			return fmt.Errorf("invalid IP format: %w", err)
		}

		// Validate IP is within network
		if err := sm.ipamManager.ValidateHostIP(e.Record.GetString("overlay_ip"), e.Record.GetString("network_id")); err != nil {
			return fmt.Errorf("IP validation failed: %w", err)
		}

		// Validate lighthouse requirements
		if e.Record.GetBool("is_lighthouse") && e.Record.GetString("public_host_port") == "" {
			return fmt.Errorf("lighthouse hosts must specify public_host_port")
		}

		return e.Next()
	})

	sm.app.OnRecordUpdateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Collection.Name != sm.options.HostCollectionName {
			return e.Next()
		}

		// Validate IP format
		if err := sm.ipamManager.ValidateIPFormat(e.Record.GetString("overlay_ip")); err != nil {
			return fmt.Errorf("invalid IP format: %w", err)
		}

		// Validate IP is within network
		if err := sm.ipamManager.ValidateHostIP(e.Record.GetString("overlay_ip"), e.Record.GetString("network_id")); err != nil {
			return fmt.Errorf("IP validation failed: %w", err)
		}

		// Validate lighthouse requirements
		if e.Record.GetBool("is_lighthouse") && e.Record.GetString("public_host_port") == "" {
			return fmt.Errorf("lighthouse hosts must specify public_host_port")
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

		// Generate host certificate and config
		if err := sm.generateHostCertAndConfig(e.Record); err != nil {
			sm.logger.Error("Failed to generate host certificate/config: %v", err)
			return fmt.Errorf("failed to generate host certificate/config: %w", err)
		}

		if err := sm.app.Save(e.Record); err != nil {
			return fmt.Errorf("failed to save host record: %w", err)
		}

		sm.logger.Success("Generated certificate and config for host %s", e.Record.GetString("hostname"))

		return e.Next()
	})

	// Host updates - regenerate config
	sm.app.OnRecordAfterUpdateSuccess().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().Name != sm.options.HostCollectionName {
			return e.Next()
		}

		if sm.shouldHandleEvent(sm.options.HostCollectionName, types.EventTypeHostUpdate) {
			// Regenerate config
			if err := sm.generateHostConfig(e.Record); err != nil {
				sm.logger.Warning("Failed to regenerate config for host %s: %v", e.Record.Id, err)
				return e.Next()
			}

			if err := sm.app.Save(e.Record); err != nil {
				sm.logger.Warning("Failed to save host %s: %v", e.Record.Id, err)
			}

			sm.logger.Success("Regenerated config for host %s", e.Record.GetString("hostname"))
		}

		return e.Next()
	})
}

// generateCA generates CA certificate and updates the record.
func (sm *Manager) generateCA(record *core.Record) error {
	name := record.GetString("name")
	validityYears := record.GetInt("validity_years")
	if validityYears == 0 {
		validityYears = sm.options.DefaultCAValidityYears
	}

	result, err := sm.certManager.GenerateCA(name, validityYears)
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	record.Set("certificate", result.CertificatePEM)
	record.Set("private_key", result.PrivateKeyPEM)
	record.Set("expires_at", result.ExpiresAt)
	record.Set("curve", "CURVE25519")
	if validityYears > 0 {
		record.Set("validity_years", validityYears)
	}

	return nil
}

// generateHostCertAndConfig generates host certificate and config, updating the record.
func (sm *Manager) generateHostCertAndConfig(record *core.Record) error {
	// Get network and CA
	network, err := sm.app.FindRecordById(sm.options.NetworkCollectionName, record.GetString("network_id"))
	if err != nil {
		return fmt.Errorf("network not found: %w", err)
	}

	ca, err := sm.app.FindRecordById(sm.options.CACollectionName, network.GetString("ca_id"))
	if err != nil {
		return fmt.Errorf("CA not found: %w", err)
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

	// Generate host certificate
	certResult, err := sm.certManager.GenerateHostCert(cert.HostCertParams{
		Hostname:        record.GetString("hostname"),
		OverlayIP:       record.GetString("overlay_ip"),
		Groups:          groups,
		ValidityYears:   validityYears,
		CACertPEM:       ca.GetString("certificate"),
		CAPrivateKeyPEM: ca.GetString("private_key"),
		CAExpiresAt:     ca.GetDateTime("expires_at").Time(),
	})
	if err != nil {
		return fmt.Errorf("failed to generate host certificate: %w", err)
	}

	// Store certificate and CA cert (denormalized)
	record.Set("certificate", certResult.CertificatePEM)
	record.Set("private_key", certResult.PrivateKeyPEM)
	record.Set("ca_certificate", ca.GetString("certificate"))
	record.Set("expires_at", certResult.ExpiresAt)
	if validityYears > 0 {
		record.Set("validity_years", validityYears)
	}

	// Generate config
	return sm.generateHostConfig(record)
}

// generateHostConfig generates Nebula config for a host and updates the record.
func (sm *Manager) generateHostConfig(record *core.Record) error {
	// Get network
	network, err := sm.app.FindRecordById(sm.options.NetworkCollectionName, record.GetString("network_id"))
	if err != nil {
		return fmt.Errorf("network not found: %w", err)
	}

	// Query lighthouses in this network
	lighthouses, err := sm.getLighthouses(network.Id)
	if err != nil {
		return fmt.Errorf("failed to get lighthouses: %w", err)
	}

	// Convert records to models
	hostModel := sm.recordToHostModel(record)
	networkModel := sm.recordToNetworkModel(network)

	// Generate config
	configYAML, err := sm.configGen.GenerateHostConfig(hostModel, networkModel, lighthouses)
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	record.Set("config_yaml", configYAML)
	return nil
}

// getLighthouses queries all lighthouse hosts in a network.
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

// Helper: Convert PocketBase record to host model
func (sm *Manager) recordToHostModel(record *core.Record) *types.HostRecord {
	return &types.HostRecord{
		ID:             record.Id,
		Hostname:       record.GetString("hostname"),
		OverlayIP:      record.GetString("overlay_ip"),
		Groups:         record.GetString("groups"),
		IsLighthouse:   record.GetBool("is_lighthouse"),
		PublicHostPort: record.GetString("public_host_port"),
		Certificate:    record.GetString("certificate"),
		PrivateKey:     record.GetString("private_key"),
		CACertificate:  record.GetString("ca_certificate"),
		ConfigYAML:     record.GetString("config_yaml"),
	}
}

// Helper: Convert PocketBase record to network model
func (sm *Manager) recordToNetworkModel(record *core.Record) *types.NetworkRecord {
	return &types.NetworkRecord{
		ID:               record.Id,
		Name:             record.GetString("name"),
		CIDRRange:        record.GetString("cidr_range"),
		FirewallOutbound: record.GetString("firewall_outbound"),
		FirewallInbound:  record.GetString("firewall_inbound"),
	}
}
