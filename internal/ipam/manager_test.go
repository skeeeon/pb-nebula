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

// TestValidatePreferredRanges guards a setting whose failure mode is silence.
//
// Nebula parses preferred_ranges with netip.ParsePrefix and, on failure, logs a
// warning and skips the entry (hostmap.go, reload). A typo therefore costs the
// host its address preference without breaking anything: the tunnel still
// forms, over the public path, and the only symptom is traffic taking the slow
// route. Rejecting on write is the one point at which that is visible.
func TestValidatePreferredRanges(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
	}{
		{name: "empty is fine", cidrs: nil},
		{name: "a private LAN", cidrs: []string{"10.0.0.0/8"}},
		{name: "several", cidrs: []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"}},
		// A broad range plus a narrower one inside it is coherent: Nebula
		// matches an address against the set, so overlaps are not an error.
		{name: "overlapping entries are allowed", cidrs: []string{"10.0.0.0/8", "10.1.2.0/24"}},
		// The underlay may be IPv6 even though this library's overlay is not,
		// and Nebula ranks IPv6 in preferred_ranges highest of all.
		{name: "IPv6 underlay", cidrs: []string{"fd00::/8"}},
		{name: "a single host", cidrs: []string{"1.1.1.1/32"}},

		{name: "not a CIDR", cidrs: []string{"10.0.0.0"}, wantErr: true},
		{name: "nonsense", cidrs: []string{"not-a-range"}, wantErr: true},
		// Nebula would mask this silently; the operator meant an address.
		{name: "host bits set", cidrs: []string{"172.16.0.5/24"}, wantErr: true},
		{name: "duplicate", cidrs: []string{"10.0.0.0/8", "10.0.0.0/8"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePreferredRanges(tt.cidrs)
			if tt.wantErr && err == nil {
				t.Error("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidatePreferredRangesRespectsTheCap keeps one host from bloating its
// own rendered config without limit, like the unsafe_routes cap.
func TestValidatePreferredRangesRespectsTheCap(t *testing.T) {
	tooMany := make([]string, MaxPreferredRangesPerHost+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}

	if err := ValidatePreferredRanges(tooMany); err == nil {
		t.Errorf("expected an error for %d preferred ranges, got nil", len(tooMany))
	}

	if err := ValidatePreferredRanges(tooMany[:MaxPreferredRangesPerHost]); err != nil {
		t.Errorf("expected %d preferred ranges to be accepted: %v", MaxPreferredRangesPerHost, err)
	}
}

func TestValidatePublicHostPort(t *testing.T) {
	tests := []struct {
		name     string
		hostPort string
		wantErr  bool
	}{
		// An ordinary host leaves this blank. Whether a lighthouse or relay is
		// allowed to is a separate check, in validateHostRecord.
		{name: "empty is fine", hostPort: ""},

		{name: "IPv4", hostPort: "1.2.3.4:4242"},
		{name: "bracketed IPv6", hostPort: "[2001:db8::1]:4242"},
		{name: "bracketed IPv6, short form", hostPort: "[fd00::1]:4242"},
		{name: "the lowest port", hostPort: "1.2.3.4:1"},
		{name: "the highest port", hostPort: "1.2.3.4:65535"},

		// Nebula resolves a non-IP host half as a DNS name and re-resolves it
		// on a cadence, so a lighthouse on a dynamic address can be named.
		{name: "a DNS name", hostPort: "lighthouse.example.com:4242"},
		{name: "a single label", hostPort: "lighthouse:4242"},
		{name: "an absolute name", hostPort: "lighthouse.example.com.:4242"},
		{name: "a hyphen inside a label", hostPort: "lh-01.example.com:4242"},

		// The two that used to render a broken listen.port.
		{name: "IPv4 with the port left off", hostPort: "1.2.3.4", wantErr: true},
		{name: "unbracketed IPv6", hostPort: "2001:db8::1", wantErr: true},

		{name: "a name with no port", hostPort: "lighthouse.example.com", wantErr: true},
		{name: "a trailing colon and no port", hostPort: "1.2.3.4:", wantErr: true},
		{name: "a port and no host", hostPort: ":4242", wantErr: true},
		{name: "port 0 is the ephemeral request", hostPort: "1.2.3.4:0", wantErr: true},
		{name: "port above the range", hostPort: "1.2.3.4:65536", wantErr: true},
		{name: "a negative port", hostPort: "1.2.3.4:-1", wantErr: true},
		{name: "a named port", hostPort: "1.2.3.4:http", wantErr: true},
		{name: "a URL, not an endpoint", hostPort: "https://1.2.3.4:4242", wantErr: true},
		{name: "an underscore is not a hostname character", hostPort: "light_house:4242", wantErr: true},
		{name: "a leading hyphen", hostPort: "-lighthouse.example.com:4242", wantErr: true},
		{name: "an empty label", hostPort: "lighthouse..example.com:4242", wantErr: true},
		// A mistyped IPv4 address passes the label rules; an all-digit final
		// label is what gives it away.
		{name: "a truncated IPv4 address", hostPort: "1.2.3:4242", wantErr: true},
		{name: "only digits", hostPort: "4242:4242", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePublicHostPort(tt.hostPort)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !errors.Is(err, types.ErrInvalidPublicHostPort) {
					t.Errorf("expected ErrInvalidPublicHostPort, got %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateAdditionalHostPorts pins the rule that separates this column
// from advertise_addrs: a peer DIALS these, so none of them may be port 0.
func TestValidateAdditionalHostPorts(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []string
		wantErr bool
	}{
		{"unset", nil, false},
		{"empty slice", []string{}, false},
		{"one address", []string{"1.2.3.4:4242"}, false},
		{"dual stack", []string{"1.2.3.4:4242", "[2001:db8::1]:4242"}, false},
		{"a DNS name, which Nebula re-resolves for static_host_map", []string{"lh.example.com:4242"}, false},

		// Port 0 is the whole difference from advertise_addrs. A peer handed
		// one has nothing to connect to.
		{"port 0", []string{"1.2.3.4:0"}, true},

		{"no port", []string{"1.2.3.4"}, true},
		{"unbracketed IPv6", []string{"2001:db8::1:4242"}, true},
		{"empty entry", []string{""}, true},
		{"duplicate", []string{"1.2.3.4:4242", "1.2.3.4:4242"}, true},
		{"over the bound", []string{
			"1.2.3.4:1", "1.2.3.4:2", "1.2.3.4:3", "1.2.3.4:4", "1.2.3.4:5",
			"1.2.3.4:6", "1.2.3.4:7", "1.2.3.4:8", "1.2.3.4:9",
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdditionalHostPorts(tt.addrs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAdditionalHostPorts(%v) error = %v, wantErr %v", tt.addrs, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, types.ErrInvalidHostPort) {
				t.Errorf("error does not wrap ErrInvalidHostPort: %v", err)
			}
		})
	}
}

// TestValidateAdvertiseAddrs pins the inverse rule: port 0 is MEANINGFUL here,
// because Nebula substitutes the real listening port for it. Refusing it would
// rule out the host this setting is best on -- one with listen.port 0.
func TestValidateAdvertiseAddrs(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []string
		wantErr bool
	}{
		{"unset", nil, false},
		{"one address", []string{"203.0.113.9:4242"}, false},
		{"port 0 means the real listening port", []string{"203.0.113.9:0"}, false},
		{"bracketed IPv6", []string{"[2001:db8::1]:4242"}, false},
		{"a DNS name", []string{"edge.example.com:4242"}, false},

		{"no port", []string{"203.0.113.9"}, true},
		{"unbracketed IPv6", []string{"2001:db8::1:4242"}, true},
		{"non-numeric port", []string{"203.0.113.9:http"}, true},
		{"port out of range", []string{"203.0.113.9:70000"}, true},
		{"duplicate", []string{"203.0.113.9:0", "203.0.113.9:0"}, true},
		{"over the bound", []string{
			"1.2.3.4:1", "1.2.3.4:2", "1.2.3.4:3", "1.2.3.4:4", "1.2.3.4:5",
			"1.2.3.4:6", "1.2.3.4:7", "1.2.3.4:8", "1.2.3.4:9",
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdvertiseAddrs(tt.addrs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAdvertiseAddrs(%v) error = %v, wantErr %v", tt.addrs, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, types.ErrInvalidHostPort) {
				t.Errorf("error does not wrap ErrInvalidHostPort: %v", err)
			}
		})
	}
}

// TestValidateLocalAllowList restates Nebula's own acceptance rules, because
// Nebula REFUSES TO START on a list it cannot make sense of rather than
// skipping the bad entry. Every case below is the difference between a 400 at
// the API and an unattended edge that does not come back from its next restart.
func TestValidateLocalAllowList(t *testing.T) {
	tests := []struct {
		name      string
		allowList map[string]interface{}
		wantErr   bool
	}{
		{"unset", nil, false},
		{"empty", map[string]interface{}{}, false},

		{
			// Nebula's own example from examples/config.yml.
			name: "block tun0 and docker",
			allowList: map[string]interface{}{
				"interfaces": map[string]interface{}{"tun0": false, "docker.*": false},
			},
		},
		{
			name:      "a single deny rule, default inferred as allow",
			allowList: map[string]interface{}{"172.17.0.0/16": false},
		},
		{
			name:      "a single allow rule, default inferred as deny",
			allowList: map[string]interface{}{"10.0.0.0/8": true},
		},
		{
			name: "mixed rules WITH the required default",
			allowList: map[string]interface{}{
				"0.0.0.0/0": true, "10.0.0.0/8": false, "10.42.42.0/24": true,
			},
		},
		{
			// Each family is judged on its own, so v4 rules that agree are
			// fine alongside v6 rules that agree differently.
			name: "families are independent",
			allowList: map[string]interface{}{
				"172.17.0.0/16": false, "2001:db8::/32": true,
			},
		},
		{
			name:      "host bits are fine here, unlike preferred_ranges",
			allowList: map[string]interface{}{"172.17.0.1/32": false},
		},

		{
			// The constraint nobody expects: Nebula infers the default as the
			// inverse when the rules agree and refuses outright when they do
			// not.
			name:      "mixed IPv4 rules with no default",
			allowList: map[string]interface{}{"10.0.0.0/8": true, "172.17.0.0/16": false},
			wantErr:   true,
		},
		{
			name:      "mixed IPv6 rules with no default",
			allowList: map[string]interface{}{"2001:db8::/32": true, "fd00::/8": false},
			wantErr:   true,
		},
		{
			name: "interface rules that disagree",
			allowList: map[string]interface{}{
				"interfaces": map[string]interface{}{"tun0": false, "eth0": true},
			},
			wantErr: true,
		},
		{
			name: "an interface pattern that will not compile",
			allowList: map[string]interface{}{
				"interfaces": map[string]interface{}{"docker(": false},
			},
			wantErr: true,
		},
		{
			name:      "a key that is neither interfaces nor a CIDR",
			allowList: map[string]interface{}{"eth0": false},
			wantErr:   true,
		},
		{
			name:      "a non-bool value",
			allowList: map[string]interface{}{"10.0.0.0/8": "yes"},
			wantErr:   true,
		},
		{
			name:      "interfaces that is not an object",
			allowList: map[string]interface{}{"interfaces": "tun0"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLocalAllowList(tt.allowList)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateLocalAllowList(%v) error = %v, wantErr %v", tt.allowList, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, types.ErrInvalidAllowList) {
				t.Errorf("error does not wrap ErrInvalidAllowList: %v", err)
			}
		})
	}
}
