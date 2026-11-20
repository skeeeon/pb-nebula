// Package config provides Nebula configuration generation
package config

import (
	"fmt"
	"net"
	"strconv"

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

// DeviceHostKeyPath is pki.key in the config of a host whose device holds its
// own key: the path in Nebula's own example config. Not a setting. An agent
// overrides it before loading the config, and someone running Nebula by hand
// puts the key there or edits one line.
const DeviceHostKeyPath = "/etc/nebula/host.key"

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

	// CABundle is what goes into pki.ca. During a CA rotation it carries two
	// concatenated certificates so every host trusts the outgoing and incoming
	// CA at once; Nebula's NewCAPoolFromPEM reads a bundle natively.
	//
	// It is sourced from the CA record on every generation rather than from a
	// denormalized host column, which is what makes rotation self-healing: any
	// config regeneration, for any reason, hands out the current bundle. Empty
	// falls back to Host.CACertificate, so a caller that has no CA record
	// handy still produces a valid config.
	CABundle string
}

// GenerateHostConfig generates a complete Nebula YAML configuration for a host.
// The generated config includes PKI, lighthouse discovery, relay paths, host-based
// firewall rules, and all necessary Nebula settings with recommended defaults.
//
// LIGHTHOUSE BEHAVIOR:
// - Lighthouse hosts: am_lighthouse=true, no static_host_map
// - Regular hosts: am_lighthouse=false, static_host_map with lighthouse IPs
//
// Each static_host_map entry carries the lighthouse's whole address LIST, not
// one address, because Nebula's value is a list and a lighthouse can be
// dual-stack, sit behind two internet paths, or be reached at a LAN address by
// the peers in its own rack.
//
// REPORTING VERSUS BOOTSTRAPPING (advertise_addrs, local_allow_list):
// static_host_map is what every OTHER host carries about this one; it is the
// path peers dial before any handshake. These two are what this host says
// about ITSELF once it is talking to a lighthouse, and they apply to any host
// rather than only a lighthouse:
//
//   - advertise_addrs adds routable addresses Nebula cannot discover on its
//     own. Behind cloud 1:1 NAT it is the difference between reporting a
//     private 10.x address to every peer and reporting the public one, even
//     while static_host_map already points peers at the public address.
//   - local_allow_list filters which of this host's own interface addresses it
//     reports. Without it a container advertises docker0 and every bridge, and
//     peers then burn a handshake timeout per unreachable address.
//
// Both are omitted entirely when unset.
//
// PREFERRED RANGES:
// Underlay prefixes this host favours when a peer advertises several addresses
// -- typically the LAN it sits on, so two hosts in one rack use their private
// addresses rather than the public ones a lighthouse learned. Omitted entirely
// when the host expresses no preference.
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
	caBundle := in.CABundle
	if caBundle == "" {
		caBundle = host.CACertificate
	}

	// A device-held key never reaches the platform, so the config names where
	// the device keeps it. Nebula reads a path in pki.key as readily as an
	// inline key.
	key := host.PrivateKey
	if host.DeviceKey {
		key = DeviceHostKeyPath
	}

	pki := map[string]interface{}{
		"ca":   caBundle,
		"cert": host.Certificate,
		"key":  key,
		// Tear down live tunnels to a peer whose certificate has stopped being
		// valid, rather than waiting for the tunnel to die on its own.
		//
		// THIS IS THE ONE DEFAULT WORTH RESTATING, unlike use_relays:
		// Nebula's docs say this defaults to false while its code defaults it
		// to true (interface.go: c.GetBool("pki.disconnect_invalid", true), in
		// 1.10 and 1.11 alike) and its own example config shows it commented as
		// true. When the documented default and the real default disagree,
		// neither the operator reading the docs nor a future version bump can
		// be relied on, so the config says what it means.
		//
		// It matters most at the end of a rotation. `finish` drops the outgoing
		// CA, and without this a host still holding a certificate from it keeps
		// its existing tunnels open indefinitely -- trusted by nobody, still
		// connected to everybody. Revocation does not need it (a blocklisted
		// certificate skips this check and disconnects regardless,
		// connection_manager.go), but expiry and a finished rotation do.
		"disconnect_invalid": true,
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

	// Routes this host sends into the tunnel. Omitted when empty so a host that
	// gateways nothing renders the tun section it always did. Each entry needs
	// the gateway named by `via` to carry the prefix in its own certificate --
	// see HostRecord.UnsafeNetworks.
	unsafeRoutes, err := host.GetUnsafeRoutes()
	if err != nil {
		return "", fmt.Errorf("%w: %v", types.ErrInvalidUnsafeRoute, err)
	}
	if len(unsafeRoutes) > 0 {
		entries := make([]map[string]interface{}, len(unsafeRoutes))
		for i, r := range unsafeRoutes {
			entries[i] = map[string]interface{}{
				"route": r.Route,
				"via":   r.Via,
			}
		}
		tun["unsafe_routes"] = entries
	}

	// What this host reports about ITSELF, as opposed to what peers are told
	// about it in static_host_map. Both sections are needed behind NAT: one is
	// the bootstrap path peers dial, the other is the address this host names
	// when a lighthouse asks. Each is omitted when unset, so a host that sets
	// neither renders exactly the lighthouse section it always did.
	lighthouse := g.buildLighthouseConfig(lighthouses, host.IsLighthouse)

	advertiseAddrs, err := host.GetAdvertiseAddrs()
	if err != nil {
		return "", fmt.Errorf("%w: advertise_addrs: %v", types.ErrInvalidHostPort, err)
	}
	if len(advertiseAddrs) > 0 {
		lighthouse["advertise_addrs"] = advertiseAddrs
	}

	localAllowList, err := host.GetLocalAllowList()
	if err != nil {
		return "", fmt.Errorf("%w: local_allow_list: %v", types.ErrInvalidAllowList, err)
	}
	if len(localAllowList) > 0 {
		lighthouse["local_allow_list"] = localAllowList
	}

	// Build config structure
	config := map[string]interface{}{
		"pki":        pki,
		"lighthouse": lighthouse,
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

	// Underlay addresses this host favours when a peer advertises several.
	// Omitted when unset, so a host that expresses no preference renders the
	// config it always did -- the same discipline as blocklist and relay.
	preferredRanges, err := host.GetPreferredRanges()
	if err != nil {
		return "", fmt.Errorf("%w: %v", types.ErrInvalidPreferredRange, err)
	}
	if len(preferredRanges) > 0 {
		config["preferred_ranges"] = preferredRanges
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
// THE VALUE IS A LIST BECAUSE NEBULA'S IS:
// One lighthouse can legitimately be reachable at several addresses -- a
// dual-stack pair, two internet paths, or a LAN address for the peers in its
// own rack alongside the public one for everybody else. Nebula tries the
// entries, so the list is the feature rather than an accident of the format.
// A lighthouse with one address renders the one-element list it always did.
//
// RETURNS:
// - map[string][]string: Static host map (overlay IP -> public endpoints)
// - nil if this host is a lighthouse
func (g *Generator) buildStaticHostMap(lighthouses []types.LighthouseInfo, isLighthouse bool) map[string][]string {
	if isLighthouse {
		return nil // Lighthouses don't need static host map
	}

	hostMap := make(map[string][]string, len(lighthouses))
	for _, lh := range lighthouses {
		// A lighthouse with no address at all is skipped rather than rendered
		// as an empty entry. validateHostRecord refuses to save one, so this
		// only reaches a record written before that check existed -- and an
		// entry Nebula cannot parse would stop the peer starting.
		if len(lh.Addresses) == 0 {
			continue
		}
		hostMap[lh.OverlayIP] = lh.Addresses
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

// extractPort extracts the port number from a "HOST:PORT" string.
// Returns 0 for a host that needs no stable listening port.
//
// WHY LIGHTHOUSES AND RELAYS BOTH NEED ONE:
// A lighthouse must listen on a known port because peers reach it through a
// static_host_map entry. A relay must listen on a stable port for the same
// practical reason -- peers are handed its overlay IP and have to reach it at a
// fixed address to use it as a path. An ordinary host gets 0 (ephemeral).
//
// WHY net.SplitHostPort AND NOT A COLON SPLIT:
// The split this replaced took the last colon-separated element, which the
// comment claimed "handles IPv6". It handles the bracketed form and nothing
// else: a bare "2001:db8::1" yielded "1", so the config rendered listen.port 1
// while every peer was handed an entry Nebula could not parse. SplitHostPort
// accepts the bracketed form, and errors on the bare one and on a missing port
// -- the same function Nebula itself parses static_host_map values with
// (NewHostnameResults, remote_list.go), so the two agree on what is well-formed.
//
// A 0 FROM A LIGHTHOUSE OR RELAY MEANS THE RECORD BYPASSED VALIDATION:
// ipam.ValidatePublicHostPort refuses these shapes at the API now, so a
// well-formed port is the normal case. The generator still falls back to 0
// rather than erroring, because it also runs over records written before that
// check existed, and a regeneration sweep that failed on one stale row would
// take the whole network's configs with it.
//
// PARAMETERS:
//   - publicHostPort: Public HOST:PORT string (e.g., "1.2.3.4:4242")
//   - isLighthouse: True if this host is a lighthouse
//   - isRelay: True if this host is a relay
//
// RETURNS:
// - int: Port number, or 0 if the host needs no stable port or the value is malformed
func (g *Generator) extractPort(publicHostPort string, isLighthouse, isRelay bool) int {
	if (!isLighthouse && !isRelay) || publicHostPort == "" {
		return 0
	}

	_, portStr, err := net.SplitHostPort(publicHostPort)
	if err != nil {
		return 0
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}

	return port
}
