package ipam

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/skeeeon/pb-nebula/internal/types"
)

// The validation helpers below are pure functions (no database access), so a
// zero-value Manager is sufficient. ValidateHostIP needs a PocketBase app and
// is exercised via the example app / hooks instead.

func TestValidateNetworkCIDR(t *testing.T) {
	m := &Manager{}

	tests := []struct {
		name    string
		cidr    string
		wantErr error // nil means expect success
	}{
		{"valid /16", "10.128.0.0/16", nil},
		{"valid /24", "192.168.1.0/24", nil},
		{"valid /32", "10.0.0.1/32", nil},
		{"host address not network", "10.128.0.1/16", types.ErrInvalidCIDR},
		{"ipv6 rejected", "fd00::/8", types.ErrIPv6NotSupported},
		{"garbage", "not-a-cidr", types.ErrInvalidCIDR},
		{"missing mask", "10.128.0.0", types.ErrInvalidCIDR},
		{"empty", "", types.ErrInvalidCIDR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.ValidateNetworkCIDR(tt.cidr)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateNetworkCIDR(%q) = %v, want nil", tt.cidr, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateNetworkCIDR(%q) = %v, want errors.Is(%v)", tt.cidr, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCIDRFormat(t *testing.T) {
	m := &Manager{}

	if err := m.ValidateCIDRFormat("10.0.0.0/8"); err != nil {
		t.Errorf("expected valid CIDR, got %v", err)
	}
	if err := m.ValidateCIDRFormat("nope"); !errors.Is(err, types.ErrInvalidCIDR) {
		t.Errorf("expected ErrInvalidCIDR, got %v", err)
	}
}

func TestValidateIPFormat(t *testing.T) {
	m := &Manager{}

	if err := m.ValidateIPFormat("10.128.0.100"); err != nil {
		t.Errorf("expected valid IP, got %v", err)
	}
	if err := m.ValidateIPFormat("999.1.1.1"); !errors.Is(err, types.ErrInvalidIP) {
		t.Errorf("expected ErrInvalidIP, got %v", err)
	}
	if err := m.ValidateIPFormat(""); !errors.Is(err, types.ErrInvalidIP) {
		t.Errorf("expected ErrInvalidIP for empty string, got %v", err)
	}
}

// mustCIDR parses a network CIDR for the unsafe-network tests below.
func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("bad test CIDR %q: %v", cidr, err)
	}
	return network
}

func TestValidateUnsafeNetworks(t *testing.T) {
	overlay := mustCIDR(t, "10.128.0.0/16")

	tests := []struct {
		name    string
		cidrs   []string
		wantErr error
	}{
		{"none", nil, nil},
		{"single prefix", []string{"192.168.50.0/24"}, nil},
		{"several disjoint", []string{"192.168.50.0/24", "172.16.0.0/16"}, nil},
		{"host bits set", []string{"192.168.50.5/24"}, types.ErrInvalidUnsafeNetwork},
		{"not a CIDR", []string{"192.168.50.0"}, types.ErrInvalidUnsafeNetwork},
		{"IPv6", []string{"fd00::/64"}, types.ErrInvalidUnsafeNetwork},
		{"duplicate", []string{"192.168.50.0/24", "192.168.50.0/24"}, types.ErrInvalidUnsafeNetwork},
		{"overlapping pair", []string{"192.168.0.0/16", "192.168.50.0/24"}, types.ErrInvalidUnsafeNetwork},
		// Would shadow real mesh peers: Nebula builds one routing table from
		// the certificate's networks and unsafe networks together
		{"equals the overlay", []string{"10.128.0.0/16"}, types.ErrInvalidUnsafeNetwork},
		{"inside the overlay", []string{"10.128.5.0/24"}, types.ErrInvalidUnsafeNetwork},
		{"contains the overlay", []string{"10.0.0.0/8"}, types.ErrInvalidUnsafeNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUnsafeNetworks(tt.cidrs, overlay)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("validateUnsafeNetworks(%v) = %v, want %v", tt.cidrs, err, tt.wantErr)
			}
		})
	}
}

func TestValidateUnsafeNetworksRespectsTheCap(t *testing.T) {
	// The cap exists because these ride inside the signed certificate, which is
	// handed to every peer on every handshake.
	overlay := mustCIDR(t, "10.128.0.0/16")

	tooMany := make([]string, MaxUnsafeNetworksPerHost+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("192.168.%d.0/24", i)
	}

	if err := validateUnsafeNetworks(tooMany[:MaxUnsafeNetworksPerHost], overlay); err != nil {
		t.Errorf("exactly the cap should be allowed, got %v", err)
	}
	if err := validateUnsafeNetworks(tooMany, overlay); !errors.Is(err, types.ErrInvalidUnsafeNetwork) {
		t.Errorf("one over the cap should be rejected, got %v", err)
	}
}

func TestValidateUnsafeRoutes(t *testing.T) {
	overlay := mustCIDR(t, "10.128.0.0/16")

	route := func(r, v string) []types.UnsafeRoute {
		return []types.UnsafeRoute{{Route: r, Via: v}}
	}

	tests := []struct {
		name    string
		routes  []types.UnsafeRoute
		wantErr error
	}{
		{"none", nil, nil},
		{"valid", route("192.168.50.0/24", "10.128.0.5"), nil},
		{"missing route", route("", "10.128.0.5"), types.ErrInvalidUnsafeRoute},
		{"missing via", route("192.168.50.0/24", ""), types.ErrInvalidUnsafeRoute},
		{"route host bits", route("192.168.50.5/24", "10.128.0.5"), types.ErrInvalidUnsafeRoute},
		{"route not a CIDR", route("192.168.50.0", "10.128.0.5"), types.ErrInvalidUnsafeRoute},
		{"route overlaps overlay", route("10.128.5.0/24", "10.128.0.5"), types.ErrInvalidUnsafeRoute},
		{"via not an IP", route("192.168.50.0/24", "not-an-ip"), types.ErrInvalidUnsafeRoute},
		// via names a mesh peer by overlay IP, so an address outside the
		// network is a typo that would otherwise be silently inert
		{"via outside the network", route("192.168.50.0/24", "192.168.50.1"), types.ErrInvalidUnsafeRoute},
		{"via IPv6", route("192.168.50.0/24", "fd00::1"), types.ErrInvalidUnsafeRoute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUnsafeRoutes(tt.routes, overlay)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("validateUnsafeRoutes(%v) = %v, want %v", tt.routes, err, tt.wantErr)
			}
		})
	}
}
