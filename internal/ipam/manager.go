// Package ipam provides IP address management and validation
package ipam

import (
	"fmt"
	"net"

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
