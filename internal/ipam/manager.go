// Package ipam provides IP address management and validation
package ipam

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/pocketbase/pocketbase"
	"github.com/skeeeon/pb-nebula/internal/types"
)

// Manager handles IP address validation for Nebula networks.
// This component ensures host IPs are within network CIDRs and prevents conflicts.
//
// VALIDATION STRATEGY:
// - Manual IP allocation (user specifies IP)
// - Validate CIDR format for networks
// - Validate host IP is within network CIDR
// - Uniqueness enforced by database composite index
//
// IPv4 ONLY:
// For simplicity, only IPv4 is supported initially.
// IPv6 support can be added later if needed.
type Manager struct {
	app     *pocketbase.PocketBase // PocketBase instance for database queries
	options types.Options          // Configuration options for collection names
}

// NewManager creates a new IPAM manager.
//
// PARAMETERS:
//   - app: PocketBase application instance
//   - options: Configuration options including collection names
//
// RETURNS:
// - Manager instance ready for IP validation
func NewManager(app *pocketbase.PocketBase, options types.Options) *Manager {
	return &Manager{
		app:     app,
		options: options,
	}
}

// ValidateNetworkCIDR validates a network CIDR format.
// Ensures the CIDR is valid IPv4 format with proper ranges.
//
// VALIDATION CHECKS:
// - CIDR format: X.X.X.X/Y
// - Each octet: 0-255
// - Mask: 0-32
// - IPv4 only (for now)
// - CIDR represents a network (not a host)
//
// PARAMETERS:
//   - cidr: Network CIDR string (e.g., "10.128.0.0/16")
//
// RETURNS:
// - error: nil if valid, descriptive error if invalid
//
// USAGE:
// Called during network creation/update to validate CIDR format.
func (m *Manager) ValidateNetworkCIDR(cidr string) error {
	// Use net.ParseCIDR for comprehensive validation
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrInvalidCIDR, err)
	}

	// Ensure IPv4 only
	if ip.To4() == nil {
		return fmt.Errorf("%w: got %s", types.ErrIPv6NotSupported, cidr)
	}

	// Verify the CIDR represents a network (not a host)
	// Network address should match the base address
	if !ip.Equal(network.IP) {
		return fmt.Errorf("%w: %s is not a valid network address (should be %s)", types.ErrInvalidCIDR, cidr, network.String())
	}

	return nil
}

// ValidateHostIP validates a host IP address is within the network CIDR.
// This ensures hosts are assigned IPs that belong to their network.
//
// VALIDATION CHECKS:
// - Host IP is valid IPv4
// - Host IP is within network CIDR
// - Uniqueness handled by database index
//
// PARAMETERS:
//   - hostIP: Host IP address (e.g., "10.128.0.100")
//   - networkID: Database ID of the network
//
// RETURNS:
// - error: nil if valid, descriptive error if invalid
//
// USAGE:
// Called during host creation/update to validate IP assignment.
func (m *Manager) ValidateHostIP(hostIP, networkID string) error {
	// Get network record using configured collection name
	network, err := m.app.FindRecordById(m.options.NetworkCollectionName, networkID)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrNetworkNotFound, err)
	}

	// Parse network CIDR
	_, networkCIDR, err := net.ParseCIDR(network.GetString("cidr_range"))
	if err != nil {
		return fmt.Errorf("%w: network has invalid CIDR: %v", types.ErrInvalidCIDR, err)
	}

	// Parse host IP
	ip := net.ParseIP(hostIP)
	if ip == nil {
		return fmt.Errorf("%w: %s", types.ErrInvalidIP, hostIP)
	}

	// Ensure IPv4
	if ip.To4() == nil {
		return fmt.Errorf("%w: only IPv4 addresses supported, got %s", types.ErrIPv6NotSupported, hostIP)
	}

	// Check if IP is within network
	if !networkCIDR.Contains(ip) {
		return fmt.Errorf("%w: IP %s not in %s", types.ErrIPNotInNetwork, hostIP, networkCIDR)
	}

	return nil
}

// ValidateCIDRFormat performs format validation on CIDR string.
// Uses net.ParseCIDR for comprehensive validation instead of regex.
//
// PARAMETERS:
//   - cidr: CIDR string to validate
//
// RETURNS:
// - error: nil if format valid, error if invalid
//
// NOTE: This is a lightweight check used in hooks before full validation.
func (m *Manager) ValidateCIDRFormat(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrInvalidCIDR, err)
	}
	return nil
}

// ValidateIPFormat performs format validation on IP address.
// Uses net.ParseIP for comprehensive validation instead of regex.
//
// PARAMETERS:
//   - ip: IP address string to validate
//
// RETURNS:
// - error: nil if format valid, error if invalid
//
// NOTE: This is a lightweight check used in hooks before full validation.
func (m *Manager) ValidateIPFormat(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("%w: %s", types.ErrInvalidIP, ip)
	}
	return nil
}

// MaxUnsafeNetworksPerHost bounds how many prefixes one host may route for.
// These ride inside the signed certificate, which is handed to every peer on
// every handshake, so an unbounded list inflates every handshake in the mesh.
const MaxUnsafeNetworksPerHost = 16

// MaxUnsafeRoutesPerHost bounds how many routes one host may consume. Config
// only, so the cost is local, but a bound keeps one host from bloating its own
// rendered config without limit.
const MaxUnsafeRoutesPerHost = 32

// ValidateUnsafeNetworks validates the prefixes a host is authorized to route for.
//
// WHAT IS CHECKED:
// - Each entry parses as a CIDR and is IPv4 (consistent with the rest of pb-nebula)
// - Canonical masked form: 192.168.1.0/24, never 192.168.1.5/24
// - No duplicates and no pairwise overlaps
// - No overlap with the network's own CIDR
// - At most MaxUnsafeNetworksPerHost entries
//
// WHY THE OVERLAY CHECK IS FOLDED IN RATHER THAN OFFERED SEPARATELY:
// No caller can then run half the validation. An unsafe network overlapping the
// overlay would shadow real mesh peers, because Nebula builds ONE routing table
// from the certificate's networks and unsafe networks together.
//
// WHAT IS DELIBERATELY NOT CHECKED:
// Containment within the parent network. An unsafe network is by definition
// outside the overlay - that is what makes it unsafe.
//
// PARAMETERS:
//   - cidrs: Prefixes this host claims to route for
//   - networkID: Network the host belongs to (for the overlay overlap check)
//
// RETURNS:
// - nil if every prefix is valid
// - error wrapping ErrInvalidUnsafeNetwork otherwise
func (m *Manager) ValidateUnsafeNetworks(cidrs []string, networkID string) error {
	if len(cidrs) == 0 {
		return nil
	}

	overlay, err := m.networkCIDR(networkID)
	if err != nil {
		return err
	}

	return validateUnsafeNetworks(cidrs, overlay)
}

// validateUnsafeNetworks is the DB-free half of ValidateUnsafeNetworks, split
// out so the rules can be tested without a live PocketBase app.
func validateUnsafeNetworks(cidrs []string, overlay *net.IPNet) error {
	if len(cidrs) > MaxUnsafeNetworksPerHost {
		return fmt.Errorf("%w: at most %d allowed, got %d",
			types.ErrInvalidUnsafeNetwork, MaxUnsafeNetworksPerHost, len(cidrs))
	}

	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		ip, prefix, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", types.ErrInvalidUnsafeNetwork, cidr, err)
		}
		if ip.To4() == nil {
			return fmt.Errorf("%w: only IPv4 supported, got %s", types.ErrInvalidUnsafeNetwork, cidr)
		}
		// Reject host bits so the stored value says what it means
		if !ip.Equal(prefix.IP) {
			return fmt.Errorf("%w: %s has host bits set, use %s",
				types.ErrInvalidUnsafeNetwork, cidr, prefix.String())
		}
		if networksOverlap(prefix, overlay) {
			return fmt.Errorf("%w: %s overlaps the network's own CIDR %s and would shadow mesh peers",
				types.ErrInvalidUnsafeNetwork, cidr, overlay.String())
		}
		for _, seen := range parsed {
			if networksOverlap(prefix, seen) {
				return fmt.Errorf("%w: %s overlaps %s", types.ErrInvalidUnsafeNetwork, cidr, seen.String())
			}
		}
		parsed = append(parsed, prefix)
	}

	return nil
}

// ValidateUnsafeRoutes validates the routes a host sends into the tunnel.
//
// WHAT IS CHECKED:
// - route parses as an IPv4 CIDR in canonical masked form
// - route does not overlap the network's own CIDR
// - via parses as an IPv4 address inside the network's own CIDR
// - At most MaxUnsafeRoutesPerHost entries
//
// via is required to be inside the network CIDR because it names a mesh peer by
// its overlay IP. A typo there is otherwise completely inert: Nebula finds no
// such peer and drops the traffic without complaint.
//
// WHAT IS NOT CHECKED HERE:
// Whether the host named by via actually declares the prefix in its own
// unsafe_networks. That is a cross-host question needing a DB lookup, and it is
// legitimately false while a gateway's certificate is being updated - so the
// sync manager warns about it rather than rejecting.
//
// PARAMETERS:
//   - routes: Routes this host wants to send through the mesh
//   - networkID: Network the host belongs to
//
// RETURNS:
// - nil if every route is valid
// - error wrapping ErrInvalidUnsafeRoute otherwise
func (m *Manager) ValidateUnsafeRoutes(routes []types.UnsafeRoute, networkID string) error {
	if len(routes) == 0 {
		return nil
	}

	overlay, err := m.networkCIDR(networkID)
	if err != nil {
		return err
	}

	return validateUnsafeRoutes(routes, overlay)
}

// validateUnsafeRoutes is the DB-free half of ValidateUnsafeRoutes, split out so
// the rules can be tested without a live PocketBase app.
func validateUnsafeRoutes(routes []types.UnsafeRoute, overlay *net.IPNet) error {
	if len(routes) > MaxUnsafeRoutesPerHost {
		return fmt.Errorf("%w: at most %d allowed, got %d",
			types.ErrInvalidUnsafeRoute, MaxUnsafeRoutesPerHost, len(routes))
	}

	for _, route := range routes {
		if route.Route == "" || route.Via == "" {
			return fmt.Errorf("%w: both route and via are required, got route=%q via=%q",
				types.ErrInvalidUnsafeRoute, route.Route, route.Via)
		}

		ip, prefix, err := net.ParseCIDR(route.Route)
		if err != nil {
			return fmt.Errorf("%w: route %s: %v", types.ErrInvalidUnsafeRoute, route.Route, err)
		}
		if ip.To4() == nil {
			return fmt.Errorf("%w: only IPv4 supported, got route %s", types.ErrInvalidUnsafeRoute, route.Route)
		}
		if !ip.Equal(prefix.IP) {
			return fmt.Errorf("%w: route %s has host bits set, use %s",
				types.ErrInvalidUnsafeRoute, route.Route, prefix.String())
		}
		if networksOverlap(prefix, overlay) {
			return fmt.Errorf("%w: route %s overlaps the network's own CIDR %s and would shadow mesh peers",
				types.ErrInvalidUnsafeRoute, route.Route, overlay.String())
		}

		via := net.ParseIP(route.Via)
		if via == nil {
			return fmt.Errorf("%w: via %s is not a valid IP", types.ErrInvalidUnsafeRoute, route.Via)
		}
		if via.To4() == nil {
			return fmt.Errorf("%w: only IPv4 supported, got via %s", types.ErrInvalidUnsafeRoute, route.Via)
		}
		// via names a mesh peer by overlay IP, so it has to be in this network
		if !overlay.Contains(via) {
			return fmt.Errorf("%w: via %s is not in the network CIDR %s; it must be a peer's overlay IP",
				types.ErrInvalidUnsafeRoute, route.Via, overlay.String())
		}
	}

	return nil
}

// networkCIDR loads a network record and parses its CIDR range.
func (m *Manager) networkCIDR(networkID string) (*net.IPNet, error) {
	network, err := m.app.FindRecordById(m.options.NetworkCollectionName, networkID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrNetworkNotFound, err)
	}

	_, cidr, err := net.ParseCIDR(network.GetString("cidr_range"))
	if err != nil {
		return nil, fmt.Errorf("%w: network has invalid CIDR: %v", types.ErrInvalidCIDR, err)
	}

	return cidr, nil
}

// networksOverlap reports whether two prefixes share any address. One contains
// the other's base address exactly when they overlap, so checking both
// directions covers every case regardless of which prefix is wider.
func networksOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// MaxPreferredRangesPerHost bounds how many underlay prefixes one host may
// prefer. Config only, so the cost is local -- but a bound keeps one host from
// bloating its own rendered config without limit, like MaxUnsafeRoutesPerHost.
const MaxPreferredRangesPerHost = 16

// ValidatePreferredRanges validates the UNDERLAY prefixes a host should favour
// when a peer advertises several addresses.
//
// WHY THIS IS VALIDATED AT ALL:
// Nebula parses these with netip.ParsePrefix and, on failure, logs a warning
// and skips the entry (hostmap.go, reload). A typo therefore costs the host its
// address preference silently -- the tunnel still forms, over the public path,
// and the only symptom is traffic taking the slow route. Rejecting on write is
// the only point at which that is visible.
//
// WHAT IS CHECKED:
// - Each entry parses as a CIDR
// - Canonical masked form: 172.16.0.0/24, never 172.16.0.5/24
// - No duplicates
// - At most MaxPreferredRangesPerHost entries
//
// IPv6 IS ALLOWED HERE, UNLIKE EVERYWHERE ELSE:
// The rest of pb-nebula is IPv4-only, but that is a constraint on the OVERLAY.
// These are underlay prefixes, and Nebula ranks "IPv6 in preferred_ranges" at
// the very top of its address priority list -- refusing them would rule out the
// case the feature is best at.
//
// NOT CHECKED, DELIBERATELY:
// Any relationship to the overlay CIDR. A preferred range is an underlay
// address space; overlapping the overlay is meaningless rather than wrong, and
// there is no correct assertion to make about a network this library cannot
// see. Overlaps BETWEEN entries are allowed too: Nebula treats the list as a
// set of prefixes to match against, so a broad range plus a narrow one inside
// it is a coherent thing to write.
//
// PARAMETERS:
//   - cidrs: Underlay prefixes this host prefers
//
// RETURNS:
// - nil if every prefix is valid
// - error wrapping ErrInvalidPreferredRange otherwise
//
// SIDE EFFECTS: None (pure -- no network lookup is needed or possible).
func ValidatePreferredRanges(cidrs []string) error {
	if len(cidrs) == 0 {
		return nil
	}

	if len(cidrs) > MaxPreferredRangesPerHost {
		return fmt.Errorf("%w: at most %d allowed, got %d",
			types.ErrInvalidPreferredRange, MaxPreferredRangesPerHost, len(cidrs))
	}

	seen := make(map[string]struct{}, len(cidrs))
	for _, cidr := range cidrs {
		ip, prefix, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", types.ErrInvalidPreferredRange, cidr, err)
		}

		// Host bits set means the operator was thinking of an address rather
		// than a range. Nebula would mask it silently; say so instead.
		if !ip.Equal(prefix.IP) {
			return fmt.Errorf("%w: %s has host bits set, did you mean %s?",
				types.ErrInvalidPreferredRange, cidr, prefix.String())
		}

		if _, dup := seen[prefix.String()]; dup {
			return fmt.Errorf("%w: %s appears more than once",
				types.ErrInvalidPreferredRange, prefix.String())
		}
		seen[prefix.String()] = struct{}{}
	}

	return nil
}

// ValidatePublicHostPort validates a host's public underlay endpoint -- the
// "HOST:PORT" string a lighthouse or a relay is reached at.
//
// WHY THE FORMAT MATTERS MORE THAN IT LOOKS:
// This one value lands in two places. Every OTHER host in the network carries
// it verbatim as a static_host_map entry, and the host itself listens on the
// port, because a peer handed a fixed address cannot chase an ephemeral one.
// A malformed value is therefore not cosmetic: the host is advertised to the
// whole network and reachable from none of it. Two shapes used to get through
// and fail silently -- an address with the port left off rendered listen.port
// 0, and an unbracketed IPv6 address rendered listen.port 1 (the last colon
// split read "1" out of "2001:db8::1").
//
// HOSTNAMES ARE ALLOWED, DELIBERATELY:
// Nebula v1.11.0 splits each static_host_map value with net.SplitHostPort and,
// when the host half does not parse as an IP, treats it as a DNS name and
// resolves it in a background goroutine, re-resolving on a cadence
// (NewHostnameResults, remote_list.go). So a lighthouse on a dynamic address
// can legitimately be addressed by name, and refusing names here would rule
// that out. What Nebula will not do is guess a port, which is why the port
// half is required of every value.
//
// AN EMPTY VALUE IS VALID:
// public_host_port is optional for an ordinary host, and most records have it
// blank. The separate requirement that a lighthouse or relay HAVE one lives in
// validateHostRecord (ErrLighthouseNoPublicIP / ErrRelayNoPublicIP), so an
// existing ordinary host keeps validating unchanged.
//
// PARAMETERS:
//   - hostPort: the stored public_host_port value, possibly empty
//
// RETURNS:
// - nil if the value is empty or well-formed
// - error wrapping ErrInvalidPublicHostPort otherwise
//
// SIDE EFFECTS: None (pure -- no name is resolved, see isPlausibleDNSName).
func ValidatePublicHostPort(hostPort string) error {
	if hostPort == "" {
		return nil
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return fmt.Errorf("%w: %q: expected HOST:PORT, with an IPv6 address bracketed as [2001:db8::1]:4242: %v",
			types.ErrInvalidPublicHostPort, hostPort, err)
	}

	if host == "" {
		return fmt.Errorf("%w: %q has no host part", types.ErrInvalidPublicHostPort, hostPort)
	}

	if net.ParseIP(host) == nil && !isPlausibleDNSName(host) {
		return fmt.Errorf("%w: %q is neither an IP address nor a DNS name",
			types.ErrInvalidPublicHostPort, host)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("%w: %q: port must be a number", types.ErrInvalidPublicHostPort, hostPort)
	}

	// 0 is what Nebula treats as "pick an ephemeral port", which is the exact
	// thing a lighthouse or relay must not do, so it is refused here rather
	// than accepted and rendered.
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: port %d is outside 1-65535", types.ErrInvalidPublicHostPort, port)
	}

	return nil
}

// isPlausibleDNSName reports whether host has the shape of a DNS name.
//
// This is a shape check and never a lookup. pb-nebula cannot know what an
// edge's resolver will answer, and a lighthouse named for a record that does
// not exist yet is a reasonable thing to write. So it refuses only what is
// certainly not a name: the wrong characters, an empty or over-long label, a
// hyphen on a label boundary -- plus an all-digit final label, which is the
// shape a mistyped IPv4 address takes ("1.2.3") and which no real TLD has.
//
// PARAMETERS:
//   - host: the host half of a HOST:PORT value, already known not to be an IP
//
// RETURNS:
// - true if host could be a DNS name
//
// SIDE EFFECTS: None.
func isPlausibleDNSName(host string) bool {
	if len(host) > 253 {
		return false
	}

	// An absolute name is still a name.
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}

	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum && c != '-' {
				return false
			}
		}
	}

	last := labels[len(labels)-1]
	return strings.TrimLeft(last, "0123456789") != ""
}

// MaxAdditionalHostPortsPerHost and MaxAdvertiseAddrsPerHost bound two lists
// that are cheap individually and unbounded in aggregate.
//
// Additional host ports are the costlier of the two: every entry is copied
// into the static_host_map of EVERY host in the network, so one lighthouse
// with a long list inflates every config. Advertise addrs are local to the
// host that sets them. Both are generous for the cases that motivated them --
// dual-stack is two, two internet paths plus a LAN address is three.
const (
	MaxAdditionalHostPortsPerHost = 8
	MaxAdvertiseAddrsPerHost      = 8
)

// MaxLocalAllowListEntries bounds the combined CIDR and interface rules of one
// host's local_allow_list. Nebula builds a prefix table and a regex list from
// them at startup, and this is config-only, so the bound exists to keep one
// record from bloating its own config rather than to protect anything.
const MaxLocalAllowListEntries = 32

// ValidateAdditionalHostPorts validates the FURTHER underlay endpoints a host
// can be reached at, beyond public_host_port.
//
// WHY THE SAME RULES AS public_host_port, AND WHY PORT 0 IS STILL REFUSED:
// These entries land in exactly the same place -- the list value of this
// host's static_host_map entry in every peer's config. A peer reads that list
// and dials the addresses in it, so a 0 is not a placeholder there the way it
// is in advertise_addrs: it is an address nothing can connect to, advertised
// to the whole network. ValidatePublicHostPort already refuses it, which is
// why this delegates rather than restating the checks.
//
// DUPLICATES ARE REFUSED:
// A repeated address is not harmful -- Nebula would simply try it twice -- but
// it is always a mistake, and saying so costs one map.
//
// PARAMETERS:
//   - addrs: the parsed additional_host_ports entries, possibly empty
//
// RETURNS:
// - nil if every entry is well-formed and distinct
// - error wrapping ErrInvalidHostPort otherwise
//
// SIDE EFFECTS: None (pure -- no name is resolved).
func ValidateAdditionalHostPorts(addrs []string) error {
	if len(addrs) == 0 {
		return nil
	}

	if len(addrs) > MaxAdditionalHostPortsPerHost {
		return fmt.Errorf("%w: additional_host_ports allows at most %d entries, got %d",
			types.ErrInvalidHostPort, MaxAdditionalHostPortsPerHost, len(addrs))
	}

	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		if addr == "" {
			return fmt.Errorf("%w: additional_host_ports contains an empty entry",
				types.ErrInvalidHostPort)
		}

		// Deliberately the same validator the primary uses, so the two halves
		// of one address list can never disagree about what is well-formed.
		if err := ValidatePublicHostPort(addr); err != nil {
			return fmt.Errorf("%w: additional_host_ports: %v", types.ErrInvalidHostPort, err)
		}

		if _, dup := seen[addr]; dup {
			return fmt.Errorf("%w: additional_host_ports lists %q more than once",
				types.ErrInvalidHostPort, addr)
		}
		seen[addr] = struct{}{}
	}

	return nil
}

// ValidateAdvertiseAddrs validates the routable addresses a host REPORTS to
// the lighthouses, on top of the ones Nebula discovers for itself.
//
// WHY THIS IS VALIDATED WHERE preferred_ranges IS ONLY WARNED ABOUT:
// Nebula skips an unparseable preferred range and carries on. It does NOT do
// that here: LightHouse.reload returns a contextual error for an entry it
// cannot split, resolve, or parse a port out of, and a config error at startup
// stops the process. So a typo in this column does not cost a host an
// optimisation, it costs the host its next restart -- which on an unattended
// edge is indistinguishable from the device being dead.
//
// PORT 0 IS ALLOWED HERE, UNLIKE EVERYWHERE ELSE:
// Nebula substitutes the real listening port for a 0 (lighthouse.go), which is
// the whole point of the setting on a host with listen.port 0 -- it can name
// the address it is reachable at without knowing the port it will get. That is
// the opposite of static_host_map, where a peer has to dial the value as
// written, so the two validators differ on exactly this one rule.
//
// A HOSTNAME IS ACCEPTED, BUT ITS FAILURE MODE IS THE OPPOSITE OF
// public_host_port's, SO DO NOT READ THE TWO DOC COMMENTS AS SAYING THE SAME
// THING. In static_host_map, NewHostnameResults resolves a name in a
// background goroutine and re-resolves on a cadence, so a lookup failure is
// logged and the entry simply does not work yet. Here, LightHouse.reload
// resolves synchronously with net.DefaultResolver.LookupNetIP, and BOTH a
// lookup error and an empty result return a contextual error -- which at
// startup reaches main.go and Nebula DOES NOT START. There is no background
// resolver and no retry. So an unresolvable name costs a static_host_map entry
// its usefulness, and costs an advertise_addrs host its next reboot.
//
// Note also that only addrs[0] is used (upstream has a TODO about it), so a
// name with several A records silently advertises one of them.
//
// It is accepted anyway, and deliberately: this validator is PURE, so it
// cannot tell a name that will resolve on the edge from one that will not, and
// refusing a shape Nebula itself accepts on the strength of a condition we
// cannot evaluate is not validation, it is a guess. An operator with a
// reliable internal resolver has a legitimate use for it. What this comment
// must not do is imply the name is as safe here as in public_host_port.
//
// PARAMETERS:
//   - addrs: the parsed advertise_addrs entries, possibly empty
//
// RETURNS:
// - nil if every entry is well-formed and distinct
// - error wrapping ErrInvalidHostPort otherwise
//
// SIDE EFFECTS: None (pure -- no name is resolved).
func ValidateAdvertiseAddrs(addrs []string) error {
	if len(addrs) == 0 {
		return nil
	}

	if len(addrs) > MaxAdvertiseAddrsPerHost {
		return fmt.Errorf("%w: advertise_addrs allows at most %d entries, got %d",
			types.ErrInvalidHostPort, MaxAdvertiseAddrsPerHost, len(addrs))
	}

	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("%w: advertise_addrs %q: expected ip:port, with an IPv6 address bracketed as [2001:db8::1]:4242: %v",
				types.ErrInvalidHostPort, addr, err)
		}

		if host == "" {
			return fmt.Errorf("%w: advertise_addrs %q has no host part", types.ErrInvalidHostPort, addr)
		}

		if net.ParseIP(host) == nil && !isPlausibleDNSName(host) {
			return fmt.Errorf("%w: advertise_addrs %q is neither an IP address nor a DNS name",
				types.ErrInvalidHostPort, host)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("%w: advertise_addrs %q: port must be a number", types.ErrInvalidHostPort, addr)
		}

		// 0 means "use the real listening port" and is the reason this
		// validator exists separately from ValidatePublicHostPort.
		if port < 0 || port > 65535 {
			return fmt.Errorf("%w: advertise_addrs port %d is outside 0-65535", types.ErrInvalidHostPort, port)
		}

		if _, dup := seen[addr]; dup {
			return fmt.Errorf("%w: advertise_addrs lists %q more than once", types.ErrInvalidHostPort, addr)
		}
		seen[addr] = struct{}{}
	}

	return nil
}

// ValidateLocalAllowList validates the filter deciding which of a host's own
// interface addresses it advertises to the lighthouses.
//
// WHY A HOST NEEDS ONE AT ALL:
// Nebula's default is to advertise every local address. On a containerised
// host that includes docker0 at 172.17.0.1, every VM bridge, and any other tun
// device -- addresses that are either unroutable from a peer or, worse,
// collide with the same private range on the peer's own machine. The peer
// tries them and waits out a handshake timeout each, so the symptom is slow
// tunnel establishment rather than an error anybody can see.
//
// WHY THE RULES ARE NEBULA'S AND NOT A SIMPLIFICATION:
// newAllowList (allow_list.go) REFUSES to start on a list it cannot make sense
// of, rather than warning and skipping. Restating its three constraints here
// is the only way an operator finds out at the API instead of on the next
// restart of an unattended device:
//
//   - every value is a bool, and every key that is not "interfaces" is a CIDR
//   - the interface rules must all carry the same true/false value
//   - if the CIDR rules of one address family mix true and false, that family
//     needs an explicit default: 0.0.0.0/0 for v4, ::/0 for v6
//
// The third is the one nobody expects. Nebula infers the default as the
// inverse of the rules when they agree and refuses when they do not, so
// blocking 172.17.0.0/16 alone is fine, allowing 10.0.0.0/8 alone is fine, and
// doing both at once without a default is a startup error.
//
// HOST BITS ARE ALLOWED, UNLIKE preferred_ranges:
// Nebula masks the prefix itself here (netip.PrefixFrom on the parsed value),
// and a single-address rule written as 172.17.0.1/32 is an ordinary thing to
// want. The preferred_ranges check refuses host bits because a masked value
// there silently means something broader than what was written.
//
// PARAMETERS:
//   - allowList: the parsed local_allow_list object, nil when unset
//
// RETURNS:
// - nil if the structure is one Nebula will accept
// - error wrapping ErrInvalidAllowList otherwise
//
// SIDE EFFECTS: None (pure).
func ValidateLocalAllowList(allowList map[string]interface{}) error {
	if len(allowList) == 0 {
		return nil
	}

	entries := 0

	// Tracks, per address family, whether the CIDR rules so far agree and
	// whether an explicit default was given. Mirrors allowListRules in
	// Nebula's allow_list.go, which is the code that has to accept this.
	type familyRules struct {
		seenAny    bool
		allValue   bool
		allAgree   bool
		defaultSet bool
	}
	v4 := &familyRules{allAgree: true}
	v6 := &familyRules{allAgree: true}

	for key, raw := range allowList {
		if key == "interfaces" {
			ifaces, ok := raw.(map[string]interface{})
			if !ok {
				return fmt.Errorf("%w: local_allow_list.interfaces must be an object mapping an interface-name pattern to true or false",
					types.ErrInvalidAllowList)
			}

			var firstValue bool
			first := true
			for name, rawAllow := range ifaces {
				entries++

				allow, ok := rawAllow.(bool)
				if !ok {
					return fmt.Errorf("%w: local_allow_list.interfaces[%q] must be true or false",
						types.ErrInvalidAllowList, name)
				}

				// Nebula anchors the pattern, so an operator writing
				// "docker.*" gets ^docker.*$ and a pattern that will not
				// compile is a startup error. Compile the anchored form it
				// will actually use, not the one that was typed.
				if _, err := regexp.Compile("^" + name + "$"); err != nil {
					return fmt.Errorf("%w: local_allow_list.interfaces[%q] is not a valid regular expression: %v",
						types.ErrInvalidAllowList, name, err)
				}

				if first {
					firstValue = allow
					first = false
				} else if allow != firstValue {
					return fmt.Errorf("%w: local_allow_list.interfaces rules must all be true or all be false; Nebula takes the default as the inverse and refuses a mix",
						types.ErrInvalidAllowList)
				}
			}
			continue
		}

		entries++

		allow, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("%w: local_allow_list[%q] must be true or false",
				types.ErrInvalidAllowList, key)
		}

		prefix, err := netip.ParsePrefix(key)
		if err != nil {
			return fmt.Errorf("%w: local_allow_list key %q is neither \"interfaces\" nor a CIDR: %v",
				types.ErrInvalidAllowList, key, err)
		}

		family := v6
		if prefix.Addr().Unmap().Is4() {
			family = v4
		}
		if !family.seenAny {
			family.allValue = allow
			family.seenAny = true
		} else if allow != family.allValue {
			family.allAgree = false
		}
		if prefix.Bits() == 0 {
			family.defaultSet = true
		}
	}

	if entries > MaxLocalAllowListEntries {
		return fmt.Errorf("%w: local_allow_list allows at most %d rules, got %d",
			types.ErrInvalidAllowList, MaxLocalAllowListEntries, entries)
	}

	if v4.seenAny && !v4.allAgree && !v4.defaultSet {
		return fmt.Errorf("%w: local_allow_list mixes allow and deny rules for IPv4 without a default; add \"0.0.0.0/0\"",
			types.ErrInvalidAllowList)
	}
	if v6.seenAny && !v6.allAgree && !v6.defaultSet {
		return fmt.Errorf("%w: local_allow_list mixes allow and deny rules for IPv6 without a default; add \"::/0\"",
			types.ErrInvalidAllowList)
	}

	return nil
}
