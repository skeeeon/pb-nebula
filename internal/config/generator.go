// Package config provides Nebula configuration generation
package config

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/skeeeon/pb-nebula/internal/types"
)

// Generator handles generating complete Nebula YAML configurations.
// This component builds production-ready Nebula configs with sensible defaults.
//
// CONFIGURATION STRATEGY:
// - Use Nebula recommended defaults for all optional settings
// - Build PKI section from certificates
// - Configure lighthouse discovery appropriately
// - Apply HOST-BASED firewall rules (deny-all by default)
// - Keep it simple - no clever optimizations
type Generator struct {
	// Stateless - no fields needed
}

// NewGenerator creates a new config generator.
//
// RETURNS:
// - Generator instance ready for config generation
func NewGenerator() *Generator {
	return &Generator{}
}

// GenerateHostConfig generates a complete Nebula YAML configuration for a host.
// The generated config includes PKI, lighthouse discovery, host-based firewall rules, and all
// necessary Nebula settings with recommended defaults.
//
// LIGHTHOUSE BEHAVIOR:
// - Lighthouse hosts: am_lighthouse=true, no static_host_map
// - Regular hosts: am_lighthouse=false, static_host_map with lighthouse IPs
//
// FIREWALL RULES (HOST-BASED):
// Each host defines its own firewall rules stored in the host record.
// Rules use Nebula's native format and reference GROUPS from certificates.
// Default behavior follows Nebula recommendations:
// - Outbound: Allow all
// - Inbound: Allow ICMP from any (essential for troubleshooting)
//
// PARAMETERS:
//   - host: Host record with certificates and firewall rules
//   - lighthouses: List of lighthouse hosts in this network
//
// RETURNS:
// - string: Complete Nebula YAML configuration ready to use
// - error if config generation fails
//
// SIDE EFFECTS: None (pure generation)
func (g *Generator) GenerateHostConfig(host *types.HostRecord, lighthouses []types.LighthouseInfo) (string, error) {
	// Parse host-specific firewall rules
	outbound, inbound, err := host.GetFirewallRules()
	if err != nil {
		return "", fmt.Errorf("failed to parse firewall rules: %w", err)
	}

	// If no rules specified, use Nebula recommended defaults
	if len(outbound) == 0 {
		outbound = []map[string]interface{}{
			{"port": "any", "proto": "any", "host": "any"},
		}
	}
	if len(inbound) == 0 {
		// Nebula recommended default: Allow ICMP for troubleshooting
		inbound = []map[string]interface{}{
			{"port": "any", "proto": "icmp", "host": "any"},
		}
	}

	// Build config structure
	config := map[string]interface{}{
		"pki": map[string]interface{}{
			"ca":   host.CACertificate,
			"cert": host.Certificate,
			"key":  host.PrivateKey,
		},
		"static_host_map": g.buildStaticHostMap(lighthouses, host.IsLighthouse),
		"lighthouse":      g.buildLighthouseConfig(lighthouses, host.IsLighthouse),
		"listen": map[string]interface{}{
			"host": "0.0.0.0",
			"port": g.extractPort(host.PublicHostPort, host.IsLighthouse),
		},
		"punchy": map[string]interface{}{
			"punch":   true,
			"respond": true,
		},
		"tun": map[string]interface{}{
			"disabled":              false,
			"dev":                   "nebula1",
			"drop_local_broadcast":  false,
			"drop_multicast":        false,
			"tx_queue":              500,
			"mtu":                   1300,
		},
		"logging": map[string]interface{}{
			"level":  "info",
			"format": "text",
		},
		"firewall": map[string]interface{}{
			"outbound": outbound,
			"inbound":  inbound,
		},
	}

	// Marshal to YAML
	yamlBytes, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	return string(yamlBytes), nil
}

// buildStaticHostMap creates the static_host_map section for lighthouse discovery.
// This tells Nebula where to find lighthouses via their public IPs.
//
// LIGHTHOUSE LOGIC:
// - Lighthouse hosts don't need static_host_map (they are the discovery points)
// - Regular hosts need static_host_map entries for all lighthouses
//
// PARAMETERS:
//   - lighthouses: List of lighthouses in the network
//   - isLighthouse: True if this host is a lighthouse
//
// RETURNS:
// - map[string][]string: Static host map (overlay IP -> public endpoints)
// - nil if this host is a lighthouse
func (g *Generator) buildStaticHostMap(lighthouses []types.LighthouseInfo, isLighthouse bool) map[string][]string {
	if isLighthouse {
		return nil // Lighthouses don't need static host map
	}

	hostMap := make(map[string][]string)
	for _, lh := range lighthouses {
		hostMap[lh.OverlayIP] = []string{lh.PublicHostPort}
	}
	return hostMap
}

// buildLighthouseConfig creates the lighthouse section for discovery configuration.
// This configures whether this host is a lighthouse and which lighthouses to use.
//
// LIGHTHOUSE CONFIGURATION:
// - Lighthouse hosts: am_lighthouse=true
// - Regular hosts: am_lighthouse=false, list of lighthouse overlay IPs, interval=60
//
// PARAMETERS:
//   - lighthouses: List of lighthouses in the network
//   - isLighthouse: True if this host is a lighthouse
//
// RETURNS:
// - map[string]interface{}: Lighthouse configuration section
func (g *Generator) buildLighthouseConfig(lighthouses []types.LighthouseInfo, isLighthouse bool) map[string]interface{} {
	if isLighthouse {
		return map[string]interface{}{
			"am_lighthouse": true,
		}
	}

	// Extract lighthouse overlay IPs
	hosts := make([]string, len(lighthouses))
	for i, lh := range lighthouses {
		hosts[i] = lh.OverlayIP
	}

	return map[string]interface{}{
		"am_lighthouse": false,
		"interval":      60,
		"hosts":         hosts,
	}
}

// extractPort extracts the port number from a "IP:PORT" string.
// Returns 0 if the host is not a lighthouse (no listening needed).
//
// LIGHTHOUSE PORT:
// Lighthouses listen on a specific port for discovery requests.
// Regular hosts typically use port 0 (random ephemeral port).
//
// PARAMETERS:
//   - publicHostPort: Public IP:PORT string (e.g., "1.2.3.4:4242")
//   - isLighthouse: True if this host is a lighthouse
//
// RETURNS:
// - int: Port number, or 0 if not a lighthouse
func (g *Generator) extractPort(publicHostPort string, isLighthouse bool) int {
	if !isLighthouse || publicHostPort == "" {
		return 0
	}

	// Split on last colon to handle IPv6 addresses
	parts := strings.Split(publicHostPort, ":")
	if len(parts) < 2 {
		return 0
	}

	// Get last part (port)
	portStr := parts[len(parts)-1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}

	return port
}
