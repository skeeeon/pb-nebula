package types

import (
	"encoding/json"
	"time"
)

// Collection Names
const (
	DefaultAuthorityCollection = "nebula_authorities"
	DefaultNodeCollection      = "nebula_nodes"
	DefaultGroupCollection     = "nebula_groups"
	DefaultRuleCollection      = "nebula_rules"
)

// AuthorityRecord represents a Nebula Certificate Authority and Network.
type AuthorityRecord struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	CIDR         string    `json:"cidr"`           // e.g., "10.0.0.0/24"
	Port         int       `json:"port"`           // Default 4242
	CAPublicKey  string    `json:"ca_public_key"`  // PEM
	CAPrivateKey string    `json:"ca_private_key"` // PEM (Plaintext)
	Mask         int       `json:"mask"`           // Derived from CIDR, useful helper
	Created      time.Time `json:"created"`
	Updated      time.Time `json:"updated"`
}

// NodeRecord represents a Nebula Device/Host.
type NodeRecord struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"` // Hostname
	AuthorityID  string    `json:"authority_id"`
	IPAddress    string    `json:"ip_address"`
	IsLighthouse bool      `json:"is_lighthouse"`
	StaticIPs    []string  `json:"static_ips"` // Real IPs if lighthouse
	Subnets      []string  `json:"subnets"`    // Unsafe routes exposed
	Groups       []string  `json:"groups"`     // IDs of assigned groups
	
	// Crypto Assets
	PublicKey   string `json:"public_key"`   // Curve25519
	PrivateKey  string `json:"private_key"`  // Curve25519 (PEM)
	Certificate string `json:"certificate"`  // Signed Cert (PEM)
	
	// Generated Config
	Config string `json:"config"` // Full nebula config.yaml
	
	// Management
	Regenerate bool `json:"regenerate"` // Trigger to rotate keys/cert
	Active     bool `json:"active"`
}

// GroupRecord represents a logical grouping for firewall rules.
type GroupRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	AuthorityID string `json:"authority_id"`
}

// RuleRecord represents a firewall rule.
type RuleRecord struct {
	ID           string   `json:"id"`
	AuthorityID  string   `json:"authority_id"`
	Direction    string   `json:"direction"` // "inbound", "outbound"
	Port         string   `json:"port"`      // "80", "0-65535", "any"
	Proto        string   `json:"proto"`     // "tcp", "udp", "icmp", "any"
	SourceGroups []string `json:"source_groups"`
	DestGroups   []string `json:"dest_groups"`
	CAName       string   `json:"ca_name"` // For cross-signing trust
}

// Helper to parse static IPs from JSON raw message if needed
func (n *NodeRecord) GetStaticIPs(raw json.RawMessage) []string {
	var ips []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &ips)
	}
	return ips
}
