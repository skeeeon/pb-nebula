// Package collections handles PocketBase collection initialization
package collections

import (
	"fmt"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
	pbtypes "github.com/skeeeon/pb-nebula/internal/types"
)

// Manager handles creation and management of PocketBase collections required for Nebula mesh VPN.
// This component ensures all necessary database structures exist before other components use them.
//
// COLLECTION ARCHITECTURE:
// - nebula_ca: Single CA record (root of trust, admin only)
// - nebula_networks: Network definitions (isolation boundaries)
// - nebula_hosts: Host configurations (auth collection with Nebula credentials)
//
// INITIALIZATION ORDER:
// Collections must be created in dependency order to support foreign key relationships:
// 1. CA (no dependencies)
// 2. Networks (depends on CA)
// 3. Hosts (depends on networks)
type Manager struct {
	app     *pocketbase.PocketBase // PocketBase instance for database operations
	options pbtypes.Options        // Configuration options including collection names
}

// NewManager creates a new collection manager with PocketBase integration.
//
// PARAMETERS:
//   - app: PocketBase application instance
//   - options: Configuration including custom collection names
//
// RETURNS:
// - Manager instance ready for collection initialization
func NewManager(app *pocketbase.PocketBase, options pbtypes.Options) *Manager {
	return &Manager{
		app:     app,
		options: options,
	}
}

// InitializeCollections creates or updates all required collections in dependency order.
// This is idempotent - existing collections are left unchanged.
//
// DEPENDENCY ORDER:
// 1. CA (no dependencies)
// 2. Networks (depends on CA)
// 3. Hosts (depends on networks)
//
// IDEMPOTENT BEHAVIOR:
// - Checks if collection exists before creating
// - Skips creation if collection already exists
// - Does not modify existing collection schemas
//
// RETURNS:
// - nil on successful initialization
// - error if any collection creation fails
func (cm *Manager) InitializeCollections() error {
	// Initialize in dependency order
	if err := cm.createCACollection(); err != nil {
		return fmt.Errorf("failed to create CA collection: %w", err)
	}

	if err := cm.createNetworksCollection(); err != nil {
		return fmt.Errorf("failed to create networks collection: %w", err)
	}

	if err := cm.createHostsCollection(); err != nil {
		return fmt.Errorf("failed to create hosts collection: %w", err)
	}

	return nil
}

// createCACollection creates the CA collection (admin only, single record).
// This collection stores the root Nebula Certificate Authority.
//
// SECURITY MODEL:
// - No public access rules (only admin can access)
// - Contains root cryptographic keys
// - Single record per deployment (enforced by application logic)
// - private_key field is HIDDEN (not exposed via API)
//
// SCHEMA:
// - Identity fields: name
// - Certificates: certificate, private_key (HIDDEN)
// - Validity: validity_years, expires_at, curve
// - Metadata: created, updated timestamps
//
// RETURNS:
// - nil if collection created successfully or already exists
// - error if collection creation fails
func (cm *Manager) createCACollection() error {
	// Check if collection already exists
	_, err := cm.app.FindCollectionByNameOrId(cm.options.CACollectionName)
	if err == nil {
		// Collection already exists
		return nil
	}

	collection := core.NewBaseCollection(cm.options.CACollectionName)

	// Admin only access - no public access
	collection.ListRule = nil
	collection.ViewRule = nil
	collection.CreateRule = nil
	collection.UpdateRule = nil
	collection.DeleteRule = nil

	// Add fields
	collection.Fields.Add(&core.TextField{
		Name:     "name",
		Required: true,
		Max:      100,
	})
	collection.Fields.Add(&core.TextField{
		Name: "certificate",
		Max:  10000,
	})
	collection.Fields.Add(&core.TextField{
		Name:   "private_key",
		Hidden: true, // HIDDEN field - not exposed via API
		Max:    10000,
	})
	collection.Fields.Add(&core.NumberField{
		Name:    "validity_years",
		OnlyInt: true,
		Min:     types.Pointer(1.0),
		Max:     types.Pointer(50.0),
	})
	collection.Fields.Add(&core.DateField{
		Name: "expires_at",
	})
	collection.Fields.Add(&core.TextField{
		Name: "curve",
		Max:  50,
	})

	// Add timestamps
	collection.Fields.Add(&core.AutodateField{
		Name:     "created",
		OnCreate: true,
	})
	collection.Fields.Add(&core.AutodateField{
		Name:     "updated",
		OnCreate: true,
		OnUpdate: true,
	})

	// Create unique index on name (enforce single CA)
	collection.Indexes = types.JSONArray[string]{
		"CREATE UNIQUE INDEX idx_ca_name ON " + cm.options.CACollectionName + " (name)",
	}

	return cm.app.Save(collection)
}

// createNetworksCollection creates the networks collection for tenant isolation.
// Networks define CIDR ranges, firewall rules, and lighthouse configurations.
//
// SECURITY MODEL:
// - Authenticated users can list and view active networks
// - Only authenticated users can create/update/delete networks
// - Network isolation handled by Nebula, not PocketBase rules
//
// SCHEMA:
// - Identity: name, description
// - Network: cidr_range (IPv4 only for now)
// - Relation: ca_id (to nebula_ca)
// - Firewall: firewall_outbound, firewall_inbound (Nebula JSON format)
// - Management: active (enable/disable)
// - Metadata: created, updated timestamps
//
// RETURNS:
// - nil if collection created successfully or already exists
// - error if collection creation fails
func (cm *Manager) createNetworksCollection() error {
	// Check if collection already exists
	_, err := cm.app.FindCollectionByNameOrId(cm.options.NetworkCollectionName)
	if err == nil {
		// Collection already exists
		return nil
	}

	collection := core.NewBaseCollection(cm.options.NetworkCollectionName)

	// Security rules - authenticated users can access
	collection.ListRule = types.Pointer("@request.auth.id != '' && active = true")
	collection.ViewRule = types.Pointer("@request.auth.id != '' && active = true")
	collection.CreateRule = types.Pointer("@request.auth.id != ''")
	collection.UpdateRule = types.Pointer("@request.auth.id != ''")
	collection.DeleteRule = types.Pointer("@request.auth.id != ''")

	// Add identity fields
	collection.Fields.Add(&core.TextField{
		Name:     "name",
		Required: true,
		Max:      100,
	})
	collection.Fields.Add(&core.TextField{
		Name: "description",
		Max:  500,
	})

	// Add network configuration
	collection.Fields.Add(&core.TextField{
		Name:     "cidr_range",
		Required: true,
		Max:      50,
	})

	// Add management field
	collection.Fields.Add(&core.BoolField{
		Name: "active",
	})

	// Add firewall rules (stored as JSON text)
	collection.Fields.Add(&core.TextField{
		Name: "firewall_outbound",
		Max:  10000,
	})
	collection.Fields.Add(&core.TextField{
		Name: "firewall_inbound",
		Max:  10000,
	})

	// Add timestamps
	collection.Fields.Add(&core.AutodateField{
		Name:     "created",
		OnCreate: true,
	})
	collection.Fields.Add(&core.AutodateField{
		Name:     "updated",
		OnCreate: true,
		OnUpdate: true,
	})

	// Save collection first, then add relation
	if err := cm.app.Save(collection); err != nil {
		return fmt.Errorf("failed to save networks collection: %w", err)
	}

	// Add relation to CA
	caCollection, err := cm.app.FindCollectionByNameOrId(cm.options.CACollectionName)
	if err != nil {
		return fmt.Errorf("CA collection not found: %w", err)
	}

	collection.Fields.Add(&core.RelationField{
		Name:          "ca_id",
		Required:      true,
		MaxSelect:     1,
		CollectionId:  caCollection.Id,
		CascadeDelete: false,
	})

	// Create unique index on cidr_range
	collection.Indexes = types.JSONArray[string]{
		"CREATE UNIQUE INDEX idx_network_cidr ON " + cm.options.NetworkCollectionName + " (cidr_range)",
	}

	return cm.app.Save(collection)
}

// createHostsCollection creates the hosts collection (auth collection with Nebula integration).
// This is an auth collection that extends PocketBase users with Nebula-specific fields.
//
// AUTH COLLECTION FEATURES:
// - Built-in email/password authentication
// - Email verification support
// - Standard PocketBase user management
// - Extended with Nebula credentials
//
// SECURITY MODEL:
// - Users can only access their own records (self-service)
// - Authenticated users can create new users
// - Admin users can manage all users
//
// NEBULA INTEGRATION:
// - hostname: Nebula identity
// - Generated keys: certificate, private_key
// - Relations: network_id (foreign key)
// - Generated: ca_certificate (denormalized), config_yaml (complete Nebula config)
// - Lighthouse: is_lighthouse, public_host_port
//
// SPECIAL FIELDS:
// - groups: JSON array of group names for firewall rules
// - validity_years: Certificate validity period
// - expires_at: Certificate expiration timestamp
//
// TWO-PHASE CREATION:
// Collection must be saved before adding relation fields due to PocketBase requirements.
//
// RETURNS:
// - nil if collection created successfully or already exists
// - error if collection creation fails
func (cm *Manager) createHostsCollection() error {
	// Check if collection already exists
	_, err := cm.app.FindCollectionByNameOrId(cm.options.HostCollectionName)
	if err == nil {
		// Collection already exists
		return nil
	}

	collection := core.NewAuthCollection(cm.options.HostCollectionName)

	// Security rules - users can only access their own records
	collection.ListRule = types.Pointer("@request.auth.id = id")
	collection.ViewRule = types.Pointer("@request.auth.id = id")
	collection.CreateRule = types.Pointer("@request.auth.id != ''")
	collection.UpdateRule = types.Pointer("@request.auth.id = id")
	collection.DeleteRule = types.Pointer("@request.auth.id = id")

	// Add Nebula-specific fields
	collection.Fields.Add(&core.TextField{
		Name:     "hostname",
		Required: true,
		Max:      100,
	})
	collection.Fields.Add(&core.TextField{
		Name:     "overlay_ip",
		Required: true,
		Max:      50,
	})
	collection.Fields.Add(&core.TextField{
		Name: "groups",
		Max:  1000,
	})
	collection.Fields.Add(&core.BoolField{
		Name: "is_lighthouse",
	})
	collection.Fields.Add(&core.TextField{
		Name: "public_host_port",
		Max:  100,
	})

	// Add certificate fields
	collection.Fields.Add(&core.TextField{
		Name: "certificate",
		Max:  10000,
	})
	collection.Fields.Add(&core.TextField{
		Name: "private_key",
		Max:  10000,
	})
	collection.Fields.Add(&core.TextField{
		Name: "ca_certificate",
		Max:  10000,
	})
	collection.Fields.Add(&core.TextField{
		Name: "config_yaml",
		Max:  50000,
	})

	// Add validity fields
	collection.Fields.Add(&core.NumberField{
		Name:    "validity_years",
		OnlyInt: true,
		Min:     types.Pointer(1.0),
		Max:     types.Pointer(10.0),
	})
	collection.Fields.Add(&core.DateField{
		Name: "expires_at",
	})

	// Add management field
	collection.Fields.Add(&core.BoolField{
		Name: "active",
	})

	// Save collection first to get ID for relations
	if err := cm.app.Save(collection); err != nil {
		return fmt.Errorf("failed to save hosts collection: %w", err)
	}

	// Add relation to networks
	networksCollection, err := cm.app.FindCollectionByNameOrId(cm.options.NetworkCollectionName)
	if err != nil {
		return fmt.Errorf("networks collection not found: %w", err)
	}

	collection.Fields.Add(&core.RelationField{
		Name:          "network_id",
		Required:      true,
		MaxSelect:     1,
		CollectionId:  networksCollection.Id,
		CascadeDelete: false,
	})

	// Create composite unique index on (network_id, overlay_ip) and unique index on hostname
	collection.Indexes = types.JSONArray[string]{
		"CREATE UNIQUE INDEX idx_host_network_ip ON " + cm.options.HostCollectionName + " (network_id, overlay_ip)",
		"CREATE UNIQUE INDEX idx_host_hostname ON " + cm.options.HostCollectionName + " (hostname)",
	}

	return cm.app.Save(collection)
}
