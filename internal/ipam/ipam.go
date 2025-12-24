package ipam

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// NextAvailableIP finds the first IP in the cidr that is NOT in usedIPs.
// It skips the Network Address (first) and Broadcast Address (last) logic typically,
// though Nebula is P2P, sticking to usable IPs (x.x.x.1 to x.x.x.254) is safer convention.
func NextAvailableIP(cidrStr string, usedIPs []string) (string, error) {
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return "", fmt.Errorf("invalid cidr: %w", err)
	}

	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("ipv6 ipam not yet implemented")
	}

	// Convert used IPs to a map for O(1) lookups
	usedMap := make(map[uint32]bool)
	for _, ipStr := range usedIPs {
		if ip, err := netip.ParseAddr(ipStr); err == nil && ip.Is4() {
			usedMap[ipToUint32(ip)] = true
		} else if p, err := netip.ParsePrefix(ipStr); err == nil && p.Addr().Is4() {
			// Handle cases where used list contains CIDRs (e.g., "10.0.0.1/24")
			usedMap[ipToUint32(p.Addr())] = true
		}
	}

	// Calculate range
	// For 10.0.0.0/24:
	// Network: 10.0.0.0
	// Start:   10.0.0.1
	// End:     10.0.0.254
	
	startIP := ipToUint32(prefix.Addr())
	// Calculate size of subnet (2^(32-bits))
	size := uint32(1 << (32 - prefix.Bits()))
	
	// Start loop at 1 (skip network address)
	// Stop before size-1 (skip broadcast address - though Nebula doesn't technically use broadcast, it's safer)
	for i := uint32(1); i < size-1; i++ {
		candidate := startIP + i
		if !usedMap[candidate] {
			// Found unused
			res := uint32ToIP(candidate)
			// Return as CIDR string matching the parent mask
			return fmt.Sprintf("%s/%d", res.String(), prefix.Bits()), nil
		}
	}

	return "", fmt.Errorf("subnet %s is exhausted", cidrStr)
}

func ipToUint32(ip netip.Addr) uint32 {
	b := ip.As4()
	return binary.BigEndian.Uint32(b[:])
}

func uint32ToIP(nn uint32) netip.Addr {
	ip := [4]byte{}
	binary.BigEndian.PutUint32(ip[:], nn)
	return netip.AddrFrom4(ip)
}
