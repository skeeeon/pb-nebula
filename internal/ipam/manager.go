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
		return fmt.Errorf("invalid CIDR format: %w", err)
	}

	// Ensure IPv4 only
	if ip.To4() == nil {
		return fmt.Errorf("only IPv4 networks supported, got %s", cidr)
	}

	// Verify the CIDR represents a network (not a host)
	// Network address should match the base address
	if !ip.Equal(network.IP) {
		return fmt.Errorf("CIDR %s is not a valid network address (should be %s)", cidr, network.String())
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
		return fmt.Errorf("network not found: %w", err)
	}

	// Parse network CIDR
	_, networkCIDR, err := net.ParseCIDR(network.GetString("cidr_range"))
	if err != nil {
		return fmt.Errorf("invalid network CIDR: %w", err)
	}

	// Parse host IP
	ip := net.ParseIP(hostIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", hostIP)
	}

	// Ensure IPv4
	if ip.To4() == nil {
		return fmt.Errorf("only IPv4 addresses supported, got %s", hostIP)
	}

	// Check if IP is within network
	if !networkCIDR.Contains(ip) {
		return fmt.Errorf("IP %s is not within network CIDR %s", hostIP, networkCIDR)
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
		return fmt.Errorf("invalid CIDR format: %w", err)
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
		return fmt.Errorf("invalid IP format: %s", ip)
	}
	return nil
}
