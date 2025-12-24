// Package types defines all shared types used throughout the pb-nebula library
package types

import (
	"encoding/json"
	"time"
)

// CARecord represents a Nebula Certificate Authority (root of trust).
// Each pb-nebula deployment has exactly one CA that signs all host certificates.
//
// SINGLE CA DESIGN:
// Like pb-nats with a single operator, pb-nebula uses a single CA per deployment.
// This simplifies key management and trust relationships.
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
// Networks define CIDR ranges, firewall rules, and lighthouse configurations.
//
// NETWORK ISOLATION:
// Like accounts in pb-nats, networks provide natural isolation boundaries.
// Hosts in different networks cannot communicate directly (unless unsafe routes configured).
//
// FIREWALL RULES:
// Stored in Nebula's native JSON format for simplicity - no abstraction layer.
// Rules are applied at the network level, affecting all hosts in the network.
type NetworkRecord struct {
	ID               string    `json:"id"`                 // Database primary key
	Name             string    `json:"name"`               // Human-readable network name
	CIDRRange        string    `json:"cidr_range"`         // IPv4 CIDR (e.g., "10.128.0.0/16")
	Description      string    `json:"description"`        // Network description
	CAID             string    `json:"ca_id"`              // Relation to nebula_ca
	FirewallOutbound string    `json:"firewall_outbound"`  // JSON array of Nebula firewall rules
	FirewallInbound  string    `json:"firewall_inbound"`   // JSON array of Nebula firewall rules
	Active           bool      `json:"active"`             // Network enable/disable flag
	Created          time.Time `json:"created"`            // Creation timestamp
	Updated          time.Time `json:"updated"`            // Last update timestamp
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
	Hostname  string `json:"hostname"`   // Nebula hostname (must be unique)
	NetworkID string `json:"network_id"` // Foreign key to nebula_networks
	OverlayIP string `json:"overlay_ip"` // Overlay network IP (e.g., "10.128.0.100")
	Groups    string `json:"groups"`     // JSON array of group names for firewall rules

	// Lighthouse configuration
	IsLighthouse   bool   `json:"is_lighthouse"`    // True if this host is a lighthouse
	PublicHostPort string `json:"public_host_port"` // Public IP:PORT (required if lighthouse)

	// Generated Nebula credentials
	Certificate   string `json:"certificate"`    // PEM encoded host certificate
	PrivateKey    string `json:"private_key"`    // PEM encoded host private key
	CACertificate string `json:"ca_certificate"` // PEM encoded CA cert (denormalized for convenience)
	ConfigYAML    string `json:"config_yaml"`    // Complete Nebula config ready to use

	// Certificate validity
	ValidityYears int       `json:"validity_years"` // Certificate validity period
	ExpiresAt     time.Time `json:"expires_at"`     // Certificate expiration timestamp

	// Management flags
	Active  bool      `json:"active"`  // Host enable/disable flag
	Created time.Time `json:"created"` // Creation timestamp
	Updated time.Time `json:"updated"` // Last update timestamp
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
}

// Collection names with nebula_ prefix for clear identification
const (
	DefaultCACollectionName      = "nebula_ca"      // CA certificate authority
	DefaultNetworkCollectionName = "nebula_networks" // Network definitions
	DefaultHostCollectionName    = "nebula_hosts"    // Host configurations (auth collection)
)

// Default validity periods
const (
	DefaultCAValidityYears   = 10 // 10 years for CA certificates
	DefaultHostValidityYears = 1  // 1 year for host certificates
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
// RETURNS:
// - outbound: Array of outbound firewall rules
// - inbound: Array of inbound firewall rules
// - error if JSON parsing fails
func (n *NetworkRecord) GetFirewallRules() (outbound, inbound []map[string]interface{}, err error) {
	// Parse outbound rules
	if n.FirewallOutbound != "" && n.FirewallOutbound != "null" {
		if err := json.Unmarshal([]byte(n.FirewallOutbound), &outbound); err != nil {
			return nil, nil, err
		}
	}

	// Parse inbound rules
	if n.FirewallInbound != "" && n.FirewallInbound != "null" {
		if err := json.Unmarshal([]byte(n.FirewallInbound), &inbound); err != nil {
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
func (n *NetworkRecord) SetFirewallRules(outbound, inbound []map[string]interface{}) error {
	// Encode outbound rules
	if len(outbound) == 0 {
		n.FirewallOutbound = "[]"
	} else {
		outboundJSON, err := json.Marshal(outbound)
		if err != nil {
			return err
		}
		n.FirewallOutbound = string(outboundJSON)
	}

	// Encode inbound rules
	if len(inbound) == 0 {
		n.FirewallInbound = "[]"
	} else {
		inboundJSON, err := json.Marshal(inbound)
		if err != nil {
			return err
		}
		n.FirewallInbound = string(inboundJSON)
	}

	return nil
}
