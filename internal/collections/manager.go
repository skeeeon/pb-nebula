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
// - nebula_ca: CA records (roots of trust, admin only; multiple CAs supported)
// - nebula_networks: Network definitions (isolation boundaries, unique per CA)
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
//
// DEPENDENCY ORDER:
// 1. CA (no dependencies)
// 2. Networks (depends on CA)
// 3. Hosts (depends on networks)
//
// IDEMPOTENT BEHAVIOR:
// - Creates a collection that does not exist yet
// - For a collection that does exist, ADDS any declared field it is missing
// - Never removes, retypes, or narrows an existing field
// - Never alters indexes or access rules on an existing collection
//
// WHY FIELDS MIGRATE BUT INDEXES DO NOT:
// Adding a column is safe on a populated table; every existing row simply gets
// the zero value, which is what a record created before the field existed would
// have meant anyway. Adding a UNIQUE index is not safe — if any existing rows
// violate it the whole save fails, taking the rest of initialization with it.
// Index changes therefore remain a manual operation, as they always were.
//
// RETURNS:
// - nil on successful initialization
// - error if any collection creation or migration fails
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

// addMissingFields adds any declared field the collection does not already have,
// and saves the collection only if something actually changed.
//
// DESIGN:
// This is the whole schema-migration story for pb-nebula, and it is deliberately
// the smallest thing that works. A field is identified by name: if the collection
// already has one with that name it is left completely alone, whatever its type
// or options. So a deployment that widened a Max keeps its value, and a field
// whose type genuinely changed is a migration we refuse to guess at rather than
// silently destroy data over.
//
// The counterpart to this restraint is that the *declaration* must be shared:
// caFields, networkFields and hostFields are read both here and by the create
// path, so a field added to one of them cannot reach a fresh database and miss
// an existing one.
//
// RELATION FIELDS ARE NOT HANDLED HERE:
// ca_id and network_id need their target collection's ID resolved at runtime and
// are added in the second phase of the create path. They exist on every
// deployment that has the collection at all, so there is nothing to migrate.
//
// PARAMETERS:
//   - collection: an existing collection, already loaded
//   - want: the full declared non-relation field set for that collection
//
// RETURNS:
// - nil if the collection was already current or was updated successfully
// - error if the save fails
//
// SIDE EFFECTS: May ALTER the underlying table to add columns.
func (cm *Manager) addMissingFields(collection *core.Collection, want []core.Field) error {
	added := []string{}

	for _, field := range want {
		if collection.Fields.GetByName(field.GetName()) != nil {
			continue
		}
		collection.Fields.Add(field)
		added = append(added, field.GetName())
	}

	if len(added) == 0 {
		return nil
	}

	if err := cm.app.Save(collection); err != nil {
		return fmt.Errorf("failed to add fields %v to %s: %w", added, collection.Name, err)
	}

	return nil
}

// createCACollection creates the CA collection (admin only).
// This collection stores Nebula Certificate Authorities. Multiple CAs are
// supported — each CA roots its own mesh and can serve multiple networks.
//
// SECURITY MODEL:
// - No public access rules (only admin can access)
// - Contains root cryptographic keys
// - CA names are unique (the only cross-CA constraint)
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
	// An existing collection is migrated, not recreated
	existing, err := cm.app.FindCollectionByNameOrId(cm.options.CACollectionName)
	if err == nil {
		return cm.addMissingFields(existing, caFields())
	}

	collection := core.NewBaseCollection(cm.options.CACollectionName)

	// Admin only access - no public access
	collection.ListRule = nil
	collection.ViewRule = nil
	collection.CreateRule = nil
	collection.UpdateRule = nil
	collection.DeleteRule = nil

	collection.Fields.Add(caFields()...)

	// Create unique index on name (CA names distinguish meshes)
	collection.Indexes = types.JSONArray[string]{
		"CREATE UNIQUE INDEX idx_ca_name ON " + cm.options.CACollectionName + " (name)",
	}

	return cm.app.Save(collection)
}

// caFields returns the full non-relation field set for the CA collection.
//
// Both the create path and addMissingFields read this one declaration, so a
// field added here reaches fresh and existing databases alike. Fields are
// constructed fresh on every call because FieldsList.Add mutates them (it
// assigns an id), so a shared package-level slice would not be reusable.
func caFields() []core.Field {
	return []core.Field{
		&core.TextField{
			Name:     "name",
			Required: true,
			Max:      100,
		},
		&core.TextField{
			Name: "certificate",
			Max:  10000,
		},
		&core.TextField{
			Name:   "private_key",
			Hidden: true, // HIDDEN field - not exposed via API
			Max:    10000,
		},
		&core.NumberField{
			Name:    "validity_years",
			OnlyInt: true,
			Min:     types.Pointer(1.0),
			Max:     types.Pointer(50.0),
		},
		&core.DateField{
			Name: "expires_at",
		},
		&core.TextField{
			Name: "curve",
			Max:  50,
		},

		// Rotation state. Only one of next_certificate / previous_certificate
		// is ever set, and which one identifies the phase -- there is no
		// separate status column, because a stored copy of something the
		// certificate fields already say can only disagree with them.
		&core.TextField{
			Name: "next_certificate",
			Max:  10000,
		},
		&core.TextField{
			Name:   "next_private_key",
			Hidden: true, // HIDDEN, like private_key: it is a live CA key
			Max:    10000,
		},
		&core.TextField{
			Name: "previous_certificate",
			Max:  10000,
		},
		&core.DateField{
			Name: "rotated_at",
		},

		// Action field. Text rather than bool because rotation has three verbs
		// and a stuck `true` is dangerous. The hook resets it to "".
		&core.TextField{
			Name:    "rotate",
			Max:     10,
			Pattern: `^(prepare|commit|finish)$`,
		},

		&core.AutodateField{
			Name:     "created",
			OnCreate: true,
		},
		&core.AutodateField{
			Name:     "updated",
			OnCreate: true,
			OnUpdate: true,
		},
	}
}

// createNetworksCollection creates the networks collection for tenant isolation.
// Networks define CIDR ranges only - firewall rules are host-based in Nebula.
//
// SECURITY MODEL:
// - Authenticated users can list and view active networks
// - Only authenticated users can create/update/delete networks
// - Network isolation handled by Nebula, not PocketBase rules
//
// NEBULA FIREWALL DESIGN:
// - Firewall rules are HOST-BASED, not network-based
// - Rules use GROUPS assigned to host certificates
// - Default is DENY-ALL
// - Each host configures its own firewall based on its groups
//
// SCHEMA:
// - Identity: name, description
// - Network: cidr_range (IPv4 only for now)
// - Relation: ca_id (to nebula_ca)
// - Management: active (enable/disable)
// - Metadata: created, updated timestamps
//
// RETURNS:
// - nil if collection created successfully or already exists
// - error if collection creation fails
func (cm *Manager) createNetworksCollection() error {
	// An existing collection is migrated, not recreated
	existing, err := cm.app.FindCollectionByNameOrId(cm.options.NetworkCollectionName)
	if err == nil {
		return cm.addMissingFields(existing, networkFields())
	}

	collection := core.NewBaseCollection(cm.options.NetworkCollectionName)

	// Security rules - authenticated users can access
	collection.ListRule = types.Pointer("@request.auth.id != '' && active = true")
	collection.ViewRule = types.Pointer("@request.auth.id != '' && active = true")
	collection.CreateRule = types.Pointer("@request.auth.id != ''")
	collection.UpdateRule = types.Pointer("@request.auth.id != ''")
	collection.DeleteRule = types.Pointer("@request.auth.id != ''")

	collection.Fields.Add(networkFields()...)

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

	// Networks are unique per CA: the same name or CIDR can exist under
	// different CAs (separate meshes), but not twice under one CA
	collection.Indexes = types.JSONArray[string]{
		"CREATE UNIQUE INDEX idx_network_ca_name ON " + cm.options.NetworkCollectionName + " (ca_id, name)",
		"CREATE UNIQUE INDEX idx_network_ca_cidr ON " + cm.options.NetworkCollectionName + " (ca_id, cidr_range)",
	}

	return cm.app.Save(collection)
}

// networkFields returns the full non-relation field set for the networks
// collection. The ca_id relation is excluded deliberately — see caFields for why
// the declaration is shared, and addMissingFields for why relations are not.
func networkFields() []core.Field {
	return []core.Field{
		&core.TextField{
			Name:     "name",
			Required: true,
			Max:      100,
		},
		&core.TextField{
			Name: "description",
			Max:  500,
		},
		&core.TextField{
			Name:     "cidr_range",
			Required: true,
			Max:      50,
		},
		&core.BoolField{
			Name: "active",
		},
		&core.AutodateField{
			Name:     "created",
			OnCreate: true,
		},
		&core.AutodateField{
			Name:     "updated",
			OnCreate: true,
			OnUpdate: true,
		},
	}
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
// - Firewall: firewall_outbound, firewall_inbound (host-specific rules)
//
// FIREWALL RULES (HOST-BASED):
// - Each host defines its own firewall rules
// - Rules reference groups assigned to certificates
// - Deny-all by default
// - Rules stored as JSON in Nebula native format
//
// SPECIAL FIELDS:
// - groups: JSON array of group names (embedded in certificate)
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
	// An existing collection is migrated, not recreated
	existing, err := cm.app.FindCollectionByNameOrId(cm.options.HostCollectionName)
	if err == nil {
		return cm.addMissingFields(existing, hostFields())
	}

	collection := core.NewAuthCollection(cm.options.HostCollectionName)

	// Security rules - users can only access their own records
	collection.ListRule = types.Pointer("@request.auth.id = id")
	collection.ViewRule = types.Pointer("@request.auth.id = id")
	collection.CreateRule = types.Pointer("@request.auth.id != ''")
	collection.UpdateRule = types.Pointer("@request.auth.id = id")
	collection.DeleteRule = types.Pointer("@request.auth.id = id")

	collection.Fields.Add(hostFields()...)

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

	// Hosts are unique per network: overlay IPs and hostnames can repeat
	// across networks (separate meshes), but not within one network
	collection.Indexes = types.JSONArray[string]{
		"CREATE UNIQUE INDEX idx_host_network_ip ON " + cm.options.HostCollectionName + " (network_id, overlay_ip)",
		"CREATE UNIQUE INDEX idx_host_network_hostname ON " + cm.options.HostCollectionName + " (network_id, hostname)",
	}

	return cm.app.Save(collection)
}

// hostFields returns the full non-relation field set for the hosts collection.
//
// The network_id relation is excluded deliberately (see addMissingFields), as are
// the auth system fields (email, password, tokenKey, verified, created, updated)
// that core.NewAuthCollection provides — those are PocketBase's, not ours.
func hostFields() []core.Field {
	return []core.Field{
		// Nebula identity
		&core.TextField{
			Name:     "hostname",
			Required: true,
			Max:      100,
		},
		&core.TextField{
			Name:     "overlay_ip",
			Required: true,
			Max:      50,
		},
		&core.JSONField{
			Name:    "groups",
			MaxSize: 1000,
		},
		&core.BoolField{
			Name: "is_lighthouse",
		},
		&core.BoolField{
			Name: "is_relay",
		},
		&core.TextField{
			Name: "public_host_port",
			Max:  100,
		},

		// Per-host tun overrides. Both use the zero value to mean "inherit the
		// generator default" (mtu 1300, dev nebula1), which PocketBase supports
		// directly: NumberField short-circuits on 0 before checking Min, and
		// TextField short-circuits on "" before checking Pattern.
		&core.NumberField{
			Name:    "mtu",
			OnlyInt: true,
			Min:     types.Pointer(576.0),  // IPv4 minimum reassembly buffer
			Max:     types.Pointer(9216.0), // common jumbo-frame ceiling
		},
		&core.TextField{
			Name:    "tun_device",
			Max:     15, // kernel interface-name limit
			Pattern: `^[A-Za-z0-9_-]{1,15}$`,
		},

		// Generated credentials
		&core.TextField{
			Name: "certificate",
			Max:  10000,
		},
		&core.TextField{
			Name: "private_key",
			Max:  10000,
		},
		&core.TextField{
			Name: "ca_certificate",
			Max:  10000,
		},
		&core.TextField{
			Name: "config_yaml",
			Max:  50000,
		},

		// Host-specific firewall rules (Nebula native JSON format)
		&core.JSONField{
			Name:    "firewall_outbound",
			MaxSize: 10000,
		},
		&core.JSONField{
			Name:    "firewall_inbound",
			MaxSize: 10000,
		},

		// Gateway routing. unsafe_networks is cert-bound (the provider half);
		// unsafe_routes is config-only (the consumer half, on other hosts).
		&core.JSONField{
			Name:    "unsafe_networks",
			MaxSize: 1000,
		},
		&core.JSONField{
			Name:    "unsafe_routes",
			MaxSize: 2000,
		},

		// Certificate validity
		&core.NumberField{
			Name:    "validity_years",
			OnlyInt: true,
			Min:     types.Pointer(1.0),
			Max:     types.Pointer(10.0),
		},
		&core.DateField{
			Name: "expires_at",
		},

		// Management
		&core.BoolField{
			Name: "active",
		},

		// Action field: set true to force an immediate re-issue. The hook
		// performs the renewal and resets it to false in the same save.
		&core.BoolField{
			Name: "renew",
		},
	}
}
