package ipam

import (
	"errors"
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
