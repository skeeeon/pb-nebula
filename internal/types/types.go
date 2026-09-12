// Package types defines all shared types used throughout the pb-nebula library
package types

import (
	"encoding/json"
	"time"
)

// CARecord represents a Nebula Certificate Authority (root of trust).
//
// MULTI-CA DESIGN:
// A deployment can hold multiple CAs. Each CA roots its own independent mesh
// and can serve multiple networks (nebula_networks.ca_id points at its CA).
// Networks are unique per CA; hosts are unique per network.
//
// CERTIFICATE HIERARCHY:
// CA (self-signed root) → Host Certificates (signed by CA)
//
// KEY STORAGE:
// Private key is stored as plaintext in a HIDDEN field (same philosophy as pb-nats).
// The field is not exposed via PocketBase API but is accessible internally.
type CARecord struct {
	ID            string    `json:"id"`             // Database primary key
	Name          string    `json:"name"`           // Human-readable CA name
	Certificate   string    `json:"certificate"`    // PEM encoded CA certificate (public)
	PrivateKey    string    `json:"private_key"`    // PEM encoded CA private key (HIDDEN field)
	ValidityYears int       `json:"validity_years"` // Certificate validity period
	ExpiresAt     time.Time `json:"expires_at"`     // Certificate expiration timestamp
	Curve         string    `json:"curve"`          // Always "CURVE25519" for now
	Created       time.Time `json:"created"`        // Creation timestamp
	Updated       time.Time `json:"updated"`        // Last update timestamp
}

// NetworkRecord represents a Nebula network providing isolation for hosts.
// Networks define CIDR ranges only - firewall rules are HOST-BASED in Nebula.
//
// NETWORK ISOLATION:
// Like accounts in pb-nats, networks provide natural isolation boundaries.
// Hosts in different networks cannot communicate directly (unless unsafe routes configured).
//
// FIREWALL DESIGN:
// Nebula firewalls are HOST-BASED, not network-based:
// - Each host defines its own firewall rules
// - Rules use GROUPS assigned to certificates
// - Default is DENY-ALL
// - See HostRecord for firewall rule fields
type NetworkRecord struct {
	ID          string    `json:"id"`          // Database primary key
	Name        string    `json:"name"`        // Human-readable network name
	CIDRRange   string    `json:"cidr_range"`  // IPv4 CIDR (e.g., "10.128.0.0/16")
	Description string    `json:"description"` // Network description
	CAID        string    `json:"ca_id"`       // Relation to nebula_ca
	Active      bool      `json:"active"`      // Network enable/disable flag
	Created     time.Time `json:"created"`     // Creation timestamp
	Updated     time.Time `json:"updated"`     // Last update timestamp
}

// HostRecord represents a Nebula host with PocketBase authentication integration.
// This is an auth collection (like nats_users) that combines PocketBase auth with Nebula credentials.
//
// DUAL AUTHENTICATION:
// - PocketBase API: Uses email/password for REST API access
// - Nebula Connection: Uses certificate/key for mesh VPN connectivity
//
// CERTIFICATE LIFECYCLE:
// Host certificates are signed by the CA and contain the overlay IP, groups, and validity period.
// Certificates cannot outlive the CA certificate that signed them.
//
// FIREWALL RULES (HOST-BASED):
// Each host defines its own firewall rules stored in firewall_outbound and firewall_inbound.
// Rules use Nebula's native format and reference GROUPS assigned to certificates.
// Default behavior is DENY-ALL if no rules are specified.
//
// CONFIG MANAGEMENT:
// Complete Nebula YAML config is generated and stored in config_yaml field.
// Hosts authenticate to PocketBase and download their config via standard API.
type HostRecord struct {
	// Standard PocketBase auth fields
	ID       string `json:"id"`       // Database primary key
	Email    string `json:"email"`    // PocketBase authentication email
	Password string `json:"password"` // PocketBase password (for API auth)
	Verified bool   `json:"verified"` // Email verification status

	// Nebula identity and network assignment
	Hostname  string `json:"hostname"`   // Nebula hostname (unique within its network)
	NetworkID string `json:"network_id"` // Foreign key to nebula_networks
	OverlayIP string `json:"overlay_ip"` // Overlay network IP (e.g., "10.128.0.100")
	Groups    string `json:"groups"`     // JSON array of group names for firewall rules

	// Lighthouse and relay configuration. Both roles need public_host_port:
	// peers reach a lighthouse through static_host_map and a relay at the
	// address they were handed, so neither can use an ephemeral port.
	IsLighthouse   bool   `json:"is_lighthouse"`    // True if this host is a lighthouse
	IsRelay        bool   `json:"is_relay"`         // True if this host relays for peers that cannot punch
	PublicHostPort string `json:"public_host_port"` // Public IP:PORT (required if lighthouse or relay)

	// Per-host tun overrides. The zero value means "inherit the generator
	// default" so an existing host renders exactly the config it always did.
	MTU       int    `json:"mtu"`        // Overrides tun.mtu when > 0
	TunDevice string `json:"tun_device"` // Overrides tun.dev when non-empty

	// Generated Nebula credentials
	Certificate   string `json:"certificate"`    // PEM encoded host certificate
	PrivateKey    string `json:"private_key"`    // PEM encoded host private key
	CACertificate string `json:"ca_certificate"` // PEM encoded CA cert (denormalized for convenience)
	ConfigYAML    string `json:"config_yaml"`    // Complete Nebula config ready to use

	// Host-specific firewall rules (Nebula native JSON format)
	FirewallOutbound string `json:"firewall_outbound"` // JSON array of outbound firewall rules
	FirewallInbound  string `json:"firewall_inbound"`  // JSON array of inbound firewall rules

	// Gateway routing to non-Nebula subnets. These two are the PROVIDER and
	// CONSUMER halves of the same feature and live on DIFFERENT hosts:
	//
	//   - UnsafeNetworks is signed INTO this host's certificate. Nebula
	//     authorizes routing on the certificate, not on config, so a gateway
	//     whose cert omits a prefix silently refuses to route it -- the packet
	//     is dropped before any firewall rule is consulted. Cert-bound.
	//   - UnsafeRoutes tells THIS host to send traffic for a prefix through
	//     some other host. Config-only.
	//
	// Both are required, on their respective hosts, for traffic to flow, and
	// neither derives the other. See the Phase 3 notes in CLAUDE.md.
	UnsafeNetworks string `json:"unsafe_networks"` // JSON array of CIDRs this host may route for
	UnsafeRoutes   string `json:"unsafe_routes"`   // JSON array of {route, via} this host sends into the tunnel

	// Certificate validity
	ValidityYears int       `json:"validity_years"` // Certificate validity period
	ExpiresAt     time.Time `json:"expires_at"`     // Certificate expiration timestamp

	// Management flags
	Active  bool      `json:"active"`  // Host enable/disable flag
	Created time.Time `json:"created"` // Creation timestamp
	Updated time.Time `json:"updated"` // Last update timestamp
}

// UnsafeRoute is one entry of Nebula's tun.unsafe_routes: traffic for Route is
// sent through the mesh host whose overlay IP is Via.
//
// This is the CONSUMER half of gateway routing. The PROVIDER half is
// HostRecord.UnsafeNetworks on the host named by Via, because Nebula authorizes
// routing on the certificate: a via node whose cert does not carry the prefix
// silently refuses to route it. Both halves are configured independently and
// both are required.
//
// Only route and via are supported. Nebula also accepts optional mtu and metric
// per route; they are omitted until someone needs them, rather than carried as
// fields nothing sets.
type UnsafeRoute struct {
	Route string `json:"route"` // CIDR to route through the mesh (e.g., "192.168.50.0/24")
	Via   string `json:"via"`   // Overlay IP of the gateway host (e.g., "10.128.0.5")
}

// LighthouseInfo contains the information needed to configure lighthouse discovery.
// This is a helper structure used during config generation to build static host maps.
//
// LIGHTHOUSE DISCOVERY:
// Non-lighthouse hosts need to know where lighthouses are located (public IP:PORT).
// This information is used to build the static_host_map section in Nebula configs.
type LighthouseInfo struct {
	OverlayIP      string `json:"overlay_ip"`       // Lighthouse overlay IP (e.g., "10.128.0.1")
	PublicHostPort string `json:"public_host_port"` // Lighthouse public IP:PORT (e.g., "1.2.3.4:4242")
}

// Options configures the behavior of Nebula certificate and config generation.
// This is the main configuration structure passed to Setup().
type Options struct {
	// Collection names (customizable for different deployments)
	CACollectionName      string // Default: "nebula_ca"
	NetworkCollectionName string // Default: "nebula_networks"
	HostCollectionName    string // Default: "nebula_hosts"

	// Certificate defaults
	DefaultCAValidityYears   int // Default: 10 years
	DefaultHostValidityYears int // Default: 1 year

	// Logging
	LogToConsole bool // Enable console logging

	// Event filtering (optional custom logic)
	// Return true to process event, false to ignore
	EventFilter func(collectionName, eventType string) bool

	// EncryptionKey enables AES-256-GCM at-rest encryption of the CA and host
	// private_key fields when set. Must be exactly 32 characters. Empty string
	// disables encryption (plaintext storage). Stored values are tagged with an
	// "enc::" prefix; legacy unencrypted values continue to read transparently.
	//
	// LIMITATION:
	// The generated config_yaml field contains the host's private key inline
	// (Nebula's PKI block requires it) and is stored plaintext. Encryption only
	// protects the standalone private_key column.
	EncryptionKey string

	// DisableHostCertRenewal turns OFF the background job that re-issues host
	// certificates before they expire. Renewal is on by default because the
	// failure mode of forgetting it is a host that silently drops off the mesh.
	//
	// The name is negative on purpose. applyDefaultOptions only fills zero
	// values, so a bool that defaults to true is indistinguishable from unset
	// (the same reason LogToConsole is not defaulted). A negative name keeps
	// the zero value meaningful without a *bool and nil checks at every read.
	DisableHostCertRenewal bool

	// HostRenewalThreshold is the fraction of remaining lifetime at or below
	// which a host certificate is re-issued. Default 0.20, i.e. renew once 80%
	// of the certificate's life has been used. Must be > 0 and < 1.
	HostRenewalThreshold float64

	// HostRenewalCron is the cron expression for the renewal sweep.
	// Default "0 3 * * *" (daily at 03:00).
	HostRenewalCron string

	// CAExpiryWarningDays is how far ahead of a CA's expiry to start warning.
	// Default 90.
	//
	// A CA cannot be renewed, only rotated, and rotation is a three-step
	// operator procedure with a deliberate wait in the middle -- Nebula's own
	// guide says to begin two to three months out. Nothing else surfaces an
	// aging CA in time: host renewal only notices once certificates are
	// already clamped to the CA's NotAfter, which is both late and indirect.
	//
	// Not gated by DisableHostCertRenewal. Turning off automatic re-issue is a
	// reason to want MORE warning about an expiring CA, not less.
	CAExpiryWarningDays int
}

// Collection names with nebula_ prefix for clear identification
const (
	DefaultCACollectionName      = "nebula_ca"       // CA certificate authority
	DefaultNetworkCollectionName = "nebula_networks" // Network definitions
	DefaultHostCollectionName    = "nebula_hosts"    // Host configurations (auth collection)
)

// Default validity periods
const (
	DefaultCAValidityYears   = 10 // 10 years for CA certificates
	DefaultHostValidityYears = 1  // 1 year for host certificates
)

// Host certificate renewal defaults
const (
	// DefaultHostRenewalThreshold re-issues once 80% of a certificate's
	// lifetime has been consumed. On the default 1-year host certificate that
	// leaves roughly 73 days of headroom.
	DefaultHostRenewalThreshold = 0.20

	// DefaultHostRenewalCron runs the sweep daily at 03:00. Renewal is not
	// urgent work -- the threshold leaves weeks of margin -- so once a day is
	// plenty and keeps the write burst off peak hours.
	DefaultHostRenewalCron = "0 3 * * *"

	// HostRenewalCronJobID namespaces the job so a host application registering
	// its own cron entries cannot collide with ours.
	HostRenewalCronJobID = "pbnebula_renew_host_certs"
)

// CA expiry warning defaults
const (
	// DefaultCAExpiryWarningDays starts warning 90 days out, matching the "two
	// to three months in advance" Nebula's CA rotation guide asks for. The wait
	// between prepare and commit is operator judgment and cannot be compressed,
	// so the warning has to arrive with room for it.
	DefaultCAExpiryWarningDays = 90

	// DefaultCAExpiryCron runs the check daily at 03:30, after the renewal
	// sweep rather than alongside it, so the two do not interleave their log
	// output on the one morning both have something to say.
	DefaultCAExpiryCron = "30 3 * * *"

	// CAExpiryCronJobID namespaces the job, like HostRenewalCronJobID.
	CAExpiryCronJobID = "pbnebula_warn_ca_expiry"
)

// Event types for logging and filtering
// These constants enable consistent event classification across components
const (
	EventTypeCACreate      = "ca_create"      // CA creation events
	EventTypeCAUpdate      = "ca_update"      // CA modification events
	EventTypeNetworkCreate = "network_create" // Network creation events
	EventTypeNetworkUpdate = "network_update" // Network modification events
	EventTypeNetworkDelete = "network_delete" // Network deletion events
	EventTypeHostCreate    = "host_create"    // Host creation events
	EventTypeHostUpdate    = "host_update"    // Host modification events
	EventTypeHostDelete    = "host_delete"    // Host deletion events
	EventTypeHostRenew     = "host_renew"     // Host certificate renewal (cron sweep and the renew action field)
	EventTypeCARotate      = "ca_rotate"      // CA rotation step (prepare, commit, finish)
)

// GetGroups extracts the groups array from the JSON field.
// Groups are stored as JSON to leverage PocketBase's native JSON handling.
//
// RETURNS:
// - []string containing group names
// - error if JSON parsing fails
//
// EMPTY HANDLING:
// Empty or null JSON returns empty slice (not error).
func (h *HostRecord) GetGroups() ([]string, error) {
	if h.Groups == "" {
		return []string{}, nil
	}

	var groups []string
	if err := json.Unmarshal([]byte(h.Groups), &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// SetGroups updates the groups field with a JSON-encoded array.
// This provides a convenient way to set groups programmatically.
//
// PARAMETERS:
//   - groups: Array of group names
//
// RETURNS:
// - error if JSON encoding fails
func (h *HostRecord) SetGroups(groups []string) error {
	if len(groups) == 0 {
		h.Groups = "[]"
		return nil
	}

	groupsJSON, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	h.Groups = string(groupsJSON)
	return nil
}

// GetFirewallRules extracts firewall rules from JSON fields.
// Nebula's native firewall format is stored directly without abstraction.
//
// NEBULA FIREWALL FORMAT:
// Rules are arrays of objects with: port, proto, host, groups, etc.
// Example: [{"port": "22", "proto": "tcp", "groups": ["admin"]}]
//
// HOST-BASED DESIGN:
// Each host defines its own firewall rules. Rules reference groups that are
// embedded in certificates. Default is DENY-ALL if no rules specified.
//
// RETURNS:
// - outbound: Array of outbound firewall rules
// - inbound: Array of inbound firewall rules
// - error if JSON parsing fails
func (h *HostRecord) GetFirewallRules() (outbound, inbound []map[string]interface{}, err error) {
	// Parse outbound rules
	if h.FirewallOutbound != "" && h.FirewallOutbound != "null" {
		if err := json.Unmarshal([]byte(h.FirewallOutbound), &outbound); err != nil {
			return nil, nil, err
		}
	}

	// Parse inbound rules
	if h.FirewallInbound != "" && h.FirewallInbound != "null" {
		if err := json.Unmarshal([]byte(h.FirewallInbound), &inbound); err != nil {
			return nil, nil, err
		}
	}

	return outbound, inbound, nil
}

// SetFirewallRules updates firewall rule fields with JSON-encoded arrays.
// This provides a convenient way to set rules programmatically.
//
// PARAMETERS:
//   - outbound: Array of outbound firewall rules
//   - inbound: Array of inbound firewall rules
//
// RETURNS:
// - error if JSON encoding fails
func (h *HostRecord) SetFirewallRules(outbound, inbound []map[string]interface{}) error {
	// Encode outbound rules
	if len(outbound) == 0 {
		h.FirewallOutbound = "[]"
	} else {
		outboundJSON, err := json.Marshal(outbound)
		if err != nil {
			return err
		}
		h.FirewallOutbound = string(outboundJSON)
	}

	// Encode inbound rules
	if len(inbound) == 0 {
		h.FirewallInbound = "[]"
	} else {
		inboundJSON, err := json.Marshal(inbound)
		if err != nil {
			return err
		}
		h.FirewallInbound = string(inboundJSON)
	}

	return nil
}

// GetUnsafeNetworks parses the JSON unsafe_networks array into a string slice.
// These are the non-overlay prefixes this host is authorized to route for, and
// they are signed into its certificate.
//
// RETURNS:
// - []string: CIDR strings, empty slice if none are configured
// - error if the JSON is malformed
func (h *HostRecord) GetUnsafeNetworks() ([]string, error) {
	if h.UnsafeNetworks == "" || h.UnsafeNetworks == "null" {
		return []string{}, nil
	}

	var networks []string
	if err := json.Unmarshal([]byte(h.UnsafeNetworks), &networks); err != nil {
		return nil, err
	}

	return networks, nil
}

// GetUnsafeRoutes parses the JSON unsafe_routes array into UnsafeRoute values.
// These tell this host to send traffic for a prefix through another mesh host.
//
// RETURNS:
// - []UnsafeRoute: Routes, empty slice if none are configured
// - error if the JSON is malformed
func (h *HostRecord) GetUnsafeRoutes() ([]UnsafeRoute, error) {
	if h.UnsafeRoutes == "" || h.UnsafeRoutes == "null" {
		return []UnsafeRoute{}, nil
	}

	var routes []UnsafeRoute
	if err := json.Unmarshal([]byte(h.UnsafeRoutes), &routes); err != nil {
		return nil, err
	}

	return routes, nil
}
