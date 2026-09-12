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

// HostConfigInput is the render contract for one host's Nebula config.
//
// DESIGN:
// This is a struct rather than a positional parameter list because Relays and
// Blocklist are both []string and adjacent, which is a transposition waiting to
// happen -- and because every peer-derived section added later (relays today, a
// CA trust bundle next) would otherwise mean re-touching every call site.
//
// Everything here except Host is *network* state rather than host state: it is
// derived by the sync manager from the host's peers, which is why it arrives as
// input instead of living on HostRecord.
type HostConfigInput struct {
	Host        *types.HostRecord      // Host record with certificates and firewall rules
	Lighthouses []types.LighthouseInfo // Active lighthouses in this network
	Relays      []string               // Overlay IPs of active relays in this network (sorted)
	Blocklist   []string               // Certificate fingerprints to refuse (sorted)
}

// GenerateHostConfig generates a complete Nebula YAML configuration for a host.
// The generated config includes PKI, lighthouse discovery, relay paths, host-based
// firewall rules, and all necessary Nebula settings with recommended defaults.
//
// LIGHTHOUSE BEHAVIOR:
// - Lighthouse hosts: am_lighthouse=true, no static_host_map
// - Regular hosts: am_lighthouse=false, static_host_map with lighthouse IPs
//
// RELAY BEHAVIOR:
// - Relay hosts: relay.am_relay=true and nothing else
// - Other hosts: relay.relays listing the network's relays
// - Neither: the relay section is omitted entirely
//
// FIREWALL RULES (HOST-BASED):
// Each host defines its own firewall rules stored in the host record.
// Rules use Nebula's native format and reference GROUPS from certificates.
// Default behavior follows Nebula recommendations:
// - Outbound: Allow all
// - Inbound: Allow ICMP from any (essential for troubleshooting)
//
// REVOCATION (pki.blocklist):
// Nebula has no CRL and no OCSP. A revoked certificate is one whose fingerprint
// appears in `pki.blocklist` on every OTHER host that might handshake with it,
// loaded into the CA pool at startup and again on SIGHUP. So revocation is a
// property of the network that every member config has to carry, not a central
// record -- which is why blocklist arrives here as input and why deactivating a
// host fans out to its peers.
//
// PARAMETERS:
//   - in: Host record plus the peer-derived state for its network
//
// RETURNS:
// - string: Complete Nebula YAML configuration ready to use
// - error if config generation fails
//
// SIDE EFFECTS: None (pure generation)
func (g *Generator) GenerateHostConfig(in HostConfigInput) (string, error) {
	host := in.Host
	lighthouses := in.Lighthouses
	blocklist := in.Blocklist

	// Parse host-specific firewall rules
	outbound, inbound, err := host.GetFirewallRules()
	if err != nil {
		return "", fmt.Errorf("%w: %v", types.ErrInvalidFirewall, err)
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

	// pki.blocklist is omitted entirely when empty rather than written as an
	// empty list, so a network with nothing revoked produces the same config it
	// always did and no existing deployment sees a spurious diff.
	pki := map[string]interface{}{
		"ca":   host.CACertificate,
		"cert": host.Certificate,
		"key":  host.PrivateKey,
	}
	if len(blocklist) > 0 {
		pki["blocklist"] = blocklist
	}

	// Per-host tun overrides are applied on top of the defaults rather than
	// baked into them, and only when set, so a host that overrides nothing
	// renders exactly the tun section it always did
	tun := map[string]interface{}{
		"disabled":             false,
		"dev":                  "nebula1",
		"drop_local_broadcast": false,
		"drop_multicast":       false,
		"tx_queue":             500,
		"mtu":                  1300,
	}
	if host.MTU > 0 {
		tun["mtu"] = host.MTU
	}
	if host.TunDevice != "" {
		tun["dev"] = host.TunDevice
	}

	// Build config structure
	config := map[string]interface{}{
		"pki":        pki,
		"lighthouse": g.buildLighthouseConfig(lighthouses, host.IsLighthouse),
		"listen": map[string]interface{}{
			"host": "0.0.0.0",
			"port": g.extractPort(host.PublicHostPort, host.IsLighthouse, host.IsRelay),
		},
		"punchy": map[string]interface{}{
			"punch":   true,
			"respond": true,
		},
		"tun": tun,
		"logging": map[string]interface{}{
			"level":  "info",
			"format": "text",
		},
		"firewall": map[string]interface{}{
			"outbound": outbound,
			"inbound":  inbound,
		},
	}

	// Lighthouses don't need a static_host_map (they are the discovery
	// points), so the section is omitted entirely for them
	if staticHostMap := g.buildStaticHostMap(lighthouses, host.IsLighthouse); staticHostMap != nil {
		config["static_host_map"] = staticHostMap
	}

	// A network with no relays renders exactly the config it did before relay
	// support existed, so enabling this feature hands no existing deployment a
	// spurious diff -- the same discipline as blocklist and static_host_map
	if relay := g.buildRelayConfig(in.Relays, host.IsRelay); relay != nil {
		config["relay"] = relay
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

// buildRelayConfig creates the relay section, or nil to omit it entirely.
//
// RELAY LOGIC:
// - Relay hosts: am_relay only
// - Other hosts: the relay list, when the network has any
// - Neither: nil, and the caller omits the section
//
// A relay gets no relays of its own because Nebula would discard them anyway.
// It ignores relay.relays when am_relay is true (lighthouse.go) and forces
// useRelays = use_relays && !amRelay (relay_manager.go), so a relay can never
// route through another relay. Emitting just the one key says that plainly.
//
// use_relays is deliberately never emitted. Nebula already defaults it to true,
// so writing it would add a key to every config in every network purely to
// restate the default.
//
// Relays are not added to static_host_map. Unlike a lighthouse, a relay's
// address is learned through the lighthouse at runtime.
//
// PARAMETERS:
//   - relays: Overlay IPs of active relays in this network
//   - isRelay: True if this host is itself a relay
//
// RETURNS:
// - map[string]interface{}: Relay configuration section
// - nil if this host is not a relay and the network has none
func (g *Generator) buildRelayConfig(relays []string, isRelay bool) map[string]interface{} {
	if isRelay {
		return map[string]interface{}{
			"am_relay": true,
		}
	}

	if len(relays) == 0 {
		return nil
	}

	return map[string]interface{}{
		"relays": relays,
	}
}

// extractPort extracts the port number from a "IP:PORT" string.
// Returns 0 for a host that needs no stable listening port.
//
// WHY LIGHTHOUSES AND RELAYS BOTH NEED ONE:
// A lighthouse must listen on a known port because peers reach it through a
// static_host_map entry. A relay must listen on a stable port for the same
// practical reason -- peers are handed its overlay IP and have to reach it at a
// fixed address to use it as a path. An ordinary host gets 0 (ephemeral).
//
// PARAMETERS:
//   - publicHostPort: Public IP:PORT string (e.g., "1.2.3.4:4242")
//   - isLighthouse: True if this host is a lighthouse
//   - isRelay: True if this host is a relay
//
// RETURNS:
// - int: Port number, or 0 if the host needs no stable port
func (g *Generator) extractPort(publicHostPort string, isLighthouse, isRelay bool) int {
	if (!isLighthouse && !isRelay) || publicHostPort == "" {
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
