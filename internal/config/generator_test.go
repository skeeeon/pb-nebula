package config

import (
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/skeeeon/pb-nebula/internal/types"
)

func testHost() *types.HostRecord {
	return &types.HostRecord{
		ID:            "host1",
		Hostname:      "web-01",
		OverlayIP:     "10.128.0.100",
		Certificate:   "CERT-PEM",
		PrivateKey:    "KEY-PEM",
		CACertificate: "CA-PEM",
	}
}

func testLighthouses() []types.LighthouseInfo {
	return []types.LighthouseInfo{
		{OverlayIP: "10.128.0.1", Addresses: []string{"1.2.3.4:4242"}},
	}
}

// parseConfig unmarshals generated YAML for structural assertions.
func parseConfig(t *testing.T, yamlStr string) map[string]interface{} {
	t.Helper()
	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlStr), &cfg); err != nil {
		t.Fatalf("generated config is not valid YAML: %v", err)
	}
	return cfg
}

func TestGenerateHostConfigRegularHost(t *testing.T) {
	g := NewGenerator()

	out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: testLighthouses(), Blocklist: nil})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	// PKI block embeds the credentials
	pki := cfg["pki"].(map[string]interface{})
	if pki["ca"] != "CA-PEM" || pki["cert"] != "CERT-PEM" || pki["key"] != "KEY-PEM" {
		t.Errorf("unexpected pki block: %v", pki)
	}

	// Regular host points at the lighthouse
	lh := cfg["lighthouse"].(map[string]interface{})
	if lh["am_lighthouse"] != false {
		t.Error("expected am_lighthouse false for regular host")
	}
	hosts := lh["hosts"].([]interface{})
	if len(hosts) != 1 || hosts[0] != "10.128.0.1" {
		t.Errorf("expected lighthouse hosts [10.128.0.1], got %v", hosts)
	}

	shm := cfg["static_host_map"].(map[string]interface{})
	endpoints := shm["10.128.0.1"].([]interface{})
	if len(endpoints) != 1 || endpoints[0] != "1.2.3.4:4242" {
		t.Errorf("expected static_host_map endpoint 1.2.3.4:4242, got %v", endpoints)
	}

	// Regular hosts listen on an ephemeral port
	listen := cfg["listen"].(map[string]interface{})
	if listen["port"] != 0 {
		t.Errorf("expected listen port 0 for regular host, got %v", listen["port"])
	}
}

func TestGenerateHostConfigLighthouse(t *testing.T) {
	g := NewGenerator()

	host := testHost()
	host.IsLighthouse = true
	host.PublicHostPort = "1.2.3.4:4242"

	out, err := g.GenerateHostConfig(HostConfigInput{Host: host, Lighthouses: testLighthouses(), Blocklist: nil})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	lh := cfg["lighthouse"].(map[string]interface{})
	if lh["am_lighthouse"] != true {
		t.Error("expected am_lighthouse true")
	}

	// Lighthouses have no static_host_map and listen on their public port
	if shm, ok := cfg["static_host_map"]; ok {
		t.Errorf("expected static_host_map omitted for lighthouse, got %v", shm)
	}
	listen := cfg["listen"].(map[string]interface{})
	if listen["port"] != 4242 {
		t.Errorf("expected listen port 4242, got %v", listen["port"])
	}
}

func TestGenerateHostConfigDefaultFirewall(t *testing.T) {
	g := NewGenerator()

	out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: nil, Blocklist: nil})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	fw := cfg["firewall"].(map[string]interface{})
	outbound := fw["outbound"].([]interface{})
	inbound := fw["inbound"].([]interface{})

	// Nebula recommended defaults: allow-all outbound, ICMP-only inbound
	if len(outbound) != 1 {
		t.Fatalf("expected 1 default outbound rule, got %d", len(outbound))
	}
	if rule := outbound[0].(map[string]interface{}); rule["proto"] != "any" {
		t.Errorf("expected default outbound proto any, got %v", rule["proto"])
	}
	if len(inbound) != 1 {
		t.Fatalf("expected 1 default inbound rule, got %d", len(inbound))
	}
	if rule := inbound[0].(map[string]interface{}); rule["proto"] != "icmp" {
		t.Errorf("expected default inbound proto icmp, got %v", rule["proto"])
	}
}

func TestGenerateHostConfigCustomFirewall(t *testing.T) {
	g := NewGenerator()

	host := testHost()
	host.FirewallInbound = `[{"port": "22", "proto": "tcp", "groups": ["admin"]}]`

	out, err := g.GenerateHostConfig(HostConfigInput{Host: host, Lighthouses: testLighthouses(), Blocklist: nil})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	fw := cfg["firewall"].(map[string]interface{})
	inbound := fw["inbound"].([]interface{})
	if len(inbound) != 1 {
		t.Fatalf("expected 1 inbound rule, got %d", len(inbound))
	}
	rule := inbound[0].(map[string]interface{})
	if rule["port"] != "22" || rule["proto"] != "tcp" {
		t.Errorf("custom inbound rule not preserved: %v", rule)
	}
}

func TestGenerateHostConfigInvalidFirewall(t *testing.T) {
	g := NewGenerator()

	host := testHost()
	host.FirewallInbound = `{not json`

	_, err := g.GenerateHostConfig(HostConfigInput{Host: host, Lighthouses: nil, Blocklist: nil})
	if !errors.Is(err, types.ErrInvalidFirewall) {
		t.Errorf("expected ErrInvalidFirewall, got %v", err)
	}
}

func TestExtractPort(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		name         string
		hostPort     string
		isLighthouse bool
		isRelay      bool
		want         int
	}{
		{name: "IPv4 with a port", hostPort: "1.2.3.4:4242", isLighthouse: true, want: 4242},
		{name: "a relay gets the same port", hostPort: "1.2.3.4:4242", isRelay: true, want: 4242},
		{name: "lighthouse that also relays", hostPort: "1.2.3.4:4242", isLighthouse: true, isRelay: true, want: 4242},
		{name: "bracketed IPv6 with a port", hostPort: "[fd00::1]:4242", isLighthouse: true, want: 4242},
		{name: "bracketed IPv6, longer form", hostPort: "[2001:db8::1]:4242", isLighthouse: true, want: 4242},
		{name: "a DNS name with a port", hostPort: "lighthouse.example.com:4242", isLighthouse: true, want: 4242},

		// An ordinary host listens on an ephemeral port whatever it carries.
		{name: "neither lighthouse nor relay", hostPort: "1.2.3.4:4242", want: 0},
		{name: "neither, and no endpoint", hostPort: "", want: 0},

		{name: "empty on a lighthouse", hostPort: "", isLighthouse: true, want: 0},
		{name: "empty on a relay", hostPort: "", isRelay: true, want: 0},

		// The two shapes validation now refuses. Both reached the generator
		// before, and both rendered a listen.port that cannot work.
		{name: "IPv4 with the port left off", hostPort: "1.2.3.4", isLighthouse: true, want: 0},
		{name: "unbracketed IPv6, no port, used to yield 1", hostPort: "2001:db8::1", isLighthouse: true, want: 0},
		{name: "unbracketed IPv6, link-local shape", hostPort: "fd00::1", isLighthouse: true, want: 0},
		{name: "not an endpoint at all", hostPort: "no-port", isLighthouse: true, want: 0},
		{name: "a port that is not a number", hostPort: "1.2.3.4:http", isLighthouse: true, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := g.extractPort(tt.hostPort, tt.isLighthouse, tt.isRelay); got != tt.want {
				t.Errorf("extractPort(%q, lighthouse=%v, relay=%v) = %d, want %d",
					tt.hostPort, tt.isLighthouse, tt.isRelay, got, tt.want)
			}
		})
	}
}

func TestGenerateHostConfigEmbedsPrivateKeyInline(t *testing.T) {
	// Documents the known limitation: config_yaml carries the private key
	// inline (Nebula's PKI block requires it), so it is plaintext at rest.
	g := NewGenerator()

	out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: nil, Blocklist: nil})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	if !strings.Contains(out, "KEY-PEM") {
		t.Error("expected private key embedded in config YAML")
	}
}

// The blocklist has to land under `pki` with the exact key Nebula reads
// (`pki.blocklist`), or it is inert YAML that looks like it works. Nothing
// validates a Nebula config against Nebula's own schema, and a misplaced or
// misspelled key produces no error at any layer -- the host simply keeps
// trusting a certificate you believe you revoked.
func TestGenerateHostConfigWritesTheBlocklistUnderPKI(t *testing.T) {
	g := NewGenerator()

	fingerprints := []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
	}

	out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: testLighthouses(), Blocklist: fingerprints})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}

	cfg := parseConfig(t, out)
	pki, ok := cfg["pki"].(map[string]interface{})
	if !ok {
		t.Fatalf("pki section missing or not a map: %T", cfg["pki"])
	}

	raw, ok := pki["blocklist"]
	if !ok {
		t.Fatal("pki.blocklist is absent; the revocation list never reached the config")
	}
	list, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("pki.blocklist is %T, want a list", raw)
	}
	if len(list) != len(fingerprints) {
		t.Fatalf("pki.blocklist has %d entries, want %d", len(list), len(fingerprints))
	}
	for i, want := range fingerprints {
		if got, _ := list[i].(string); got != want {
			t.Errorf("pki.blocklist[%d] = %q, want %q", i, got, want)
		}
	}

	// The keys Nebula needs alongside it must survive.
	for _, k := range []string{"ca", "cert", "key"} {
		if _, ok := pki[k]; !ok {
			t.Errorf("pki.%s went missing when the blocklist was added", k)
		}
	}
}

// An empty blocklist must be omitted, not written as an empty list. A network
// with nothing revoked should render the config it always did, so upgrading the
// library does not show every host a spurious diff.
func TestGenerateHostConfigOmitsAnEmptyBlocklist(t *testing.T) {
	g := NewGenerator()

	for name, blocklist := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: testLighthouses(), Blocklist: blocklist})
			if err != nil {
				t.Fatalf("GenerateHostConfig failed: %v", err)
			}
			pki, ok := parseConfig(t, out)["pki"].(map[string]interface{})
			if !ok {
				t.Fatal("pki section missing")
			}
			if _, present := pki["blocklist"]; present {
				t.Error("pki.blocklist was written for an empty revocation list")
			}
			if strings.Contains(out, "blocklist") {
				t.Error("the rendered config mentions blocklist despite there being nothing to revoke")
			}
		})
	}
}

// TestGenerateHostConfigAppliesTunOverrides checks that a host's mtu and
// tun_device reach the rendered tun section. Nebula silently ignores config it
// does not recognise, so a value written under the wrong key would look like a
// working override and quietly do nothing.
func TestGenerateHostConfigAppliesTunOverrides(t *testing.T) {
	g := NewGenerator()

	host := testHost()
	host.MTU = 1200
	host.TunDevice = "neb0"

	out, err := g.GenerateHostConfig(HostConfigInput{Host: host, Lighthouses: testLighthouses(), Blocklist: nil})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	tun := cfg["tun"].(map[string]interface{})
	if tun["mtu"] != 1200 {
		t.Errorf("expected tun.mtu 1200, got %v", tun["mtu"])
	}
	if tun["dev"] != "neb0" {
		t.Errorf("expected tun.dev neb0, got %v", tun["dev"])
	}

	// Untouched keys keep their defaults
	if tun["tx_queue"] != 500 {
		t.Errorf("expected tun.tx_queue to stay 500, got %v", tun["tx_queue"])
	}
}

// TestGenerateHostConfigKeepsTunDefaultsWhenUnset is the guarantee that earns
// the zero-value-means-inherit convention: a host that overrides nothing must
// render byte-identical config to what it rendered before the fields existed,
// so enabling this feature does not hand every existing deployment a diff.
func TestGenerateHostConfigKeepsTunDefaultsWhenUnset(t *testing.T) {
	g := NewGenerator()

	out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: testLighthouses(), Blocklist: nil})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	tun := cfg["tun"].(map[string]interface{})
	if tun["mtu"] != 1300 {
		t.Errorf("expected default tun.mtu 1300, got %v", tun["mtu"])
	}
	if tun["dev"] != "nebula1" {
		t.Errorf("expected default tun.dev nebula1, got %v", tun["dev"])
	}
}

// TestGenerateHostConfigRelayHost checks that a relay advertises itself and
// nothing else. Nebula ignores relay.relays when am_relay is true and forces
// useRelays off for a relay, so emitting a list here would be config that reads
// as meaningful and is silently discarded.
func TestGenerateHostConfigRelayHost(t *testing.T) {
	g := NewGenerator()

	host := testHost()
	host.IsRelay = true
	host.PublicHostPort = "203.0.113.7:4242"

	out, err := g.GenerateHostConfig(HostConfigInput{
		Host:        host,
		Lighthouses: testLighthouses(),
		Relays:      []string{"10.128.0.9"},
	})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	relay := cfg["relay"].(map[string]interface{})
	if relay["am_relay"] != true {
		t.Errorf("expected am_relay true, got %v", relay["am_relay"])
	}
	if _, ok := relay["relays"]; ok {
		t.Error("a relay must not be given relays of its own")
	}
	if _, ok := relay["use_relays"]; ok {
		t.Error("use_relays should never be emitted; Nebula's default already handles it")
	}

	// A relay needs a stable listening port, like a lighthouse
	listen := cfg["listen"].(map[string]interface{})
	if listen["port"] != 4242 {
		t.Errorf("expected relay to listen on 4242, got %v", listen["port"])
	}
}

// TestGenerateHostConfigPeerGetsRelayList checks the other half: an ordinary
// host is handed the network's relays as paths it may use.
func TestGenerateHostConfigPeerGetsRelayList(t *testing.T) {
	g := NewGenerator()

	out, err := g.GenerateHostConfig(HostConfigInput{
		Host:        testHost(),
		Lighthouses: testLighthouses(),
		Relays:      []string{"10.128.0.7", "10.128.0.9"},
	})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	relay := cfg["relay"].(map[string]interface{})
	relays := relay["relays"].([]interface{})
	if len(relays) != 2 || relays[0] != "10.128.0.7" || relays[1] != "10.128.0.9" {
		t.Errorf("unexpected relays list: %v", relays)
	}
	if _, ok := relay["am_relay"]; ok {
		t.Error("a non-relay host should not carry am_relay")
	}

	// Relays are reached via the lighthouse, not a static_host_map entry
	shm := cfg["static_host_map"].(map[string]interface{})
	if _, ok := shm["10.128.0.7"]; ok {
		t.Error("relays must not be added to static_host_map")
	}
}

// TestGenerateHostConfigOmitsRelaySectionWhenNoRelays is the no-spurious-diff
// guarantee: a network that uses no relays must render exactly the config it
// rendered before relay support existed, key for key.
func TestGenerateHostConfigOmitsRelaySectionWhenNoRelays(t *testing.T) {
	g := NewGenerator()

	out, err := g.GenerateHostConfig(HostConfigInput{
		Host:        testHost(),
		Lighthouses: testLighthouses(),
		Relays:      nil,
	})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	if relay, ok := cfg["relay"]; ok {
		t.Errorf("expected relay section omitted entirely, got %v", relay)
	}
	if strings.Contains(out, "relay") {
		t.Errorf("config mentions relay despite the network having none:\n%s", out)
	}
}

// TestGenerateHostConfigWritesUnsafeRoutes checks the consumer half lands under
// tun.unsafe_routes with the exact keys Nebula's overlay/route.go reads. A
// misspelled key here is inert YAML that looks like a working route.
func TestGenerateHostConfigWritesUnsafeRoutes(t *testing.T) {
	g := NewGenerator()

	host := testHost()
	host.UnsafeRoutes = `[{"route":"192.168.50.0/24","via":"10.128.0.5"},{"route":"172.16.0.0/16","via":"10.128.0.6"}]`

	out, err := g.GenerateHostConfig(HostConfigInput{Host: host, Lighthouses: testLighthouses()})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	tun := cfg["tun"].(map[string]interface{})
	raw, ok := tun["unsafe_routes"]
	if !ok {
		t.Fatalf("tun.unsafe_routes missing; tun section was %v", tun)
	}
	routes := raw.([]interface{})
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}

	first := routes[0].(map[string]interface{})
	if first["route"] != "192.168.50.0/24" || first["via"] != "10.128.0.5" {
		t.Errorf("unexpected first route: %v", first)
	}
	// Only route and via are emitted; Nebula treats mtu/metric as optional and
	// we do not carry fields nothing sets
	if len(first) != 2 {
		t.Errorf("expected exactly route and via, got %v", first)
	}
}

// TestGenerateHostConfigOmitsUnsafeRoutesWhenUnset is the no-spurious-diff
// guarantee for the consumer half.
func TestGenerateHostConfigOmitsUnsafeRoutesWhenUnset(t *testing.T) {
	g := NewGenerator()

	out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: testLighthouses()})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}
	cfg := parseConfig(t, out)

	tun := cfg["tun"].(map[string]interface{})
	if v, ok := tun["unsafe_routes"]; ok {
		t.Errorf("expected tun.unsafe_routes omitted for a host with no routes, got %v", v)
	}
}

// TestGenerateHostConfigInvalidUnsafeRoutes checks malformed stored JSON
// surfaces as the matching sentinel rather than a bare marshal error.
func TestGenerateHostConfigInvalidUnsafeRoutes(t *testing.T) {
	g := NewGenerator()

	host := testHost()
	host.UnsafeRoutes = `{not json`

	_, err := g.GenerateHostConfig(HostConfigInput{Host: host})
	if !errors.Is(err, types.ErrInvalidUnsafeRoute) {
		t.Errorf("expected ErrInvalidUnsafeRoute, got %v", err)
	}
}

// TestGenerateHostConfigSetsDisconnectInvalid pins the one Nebula default this
// generator restates rather than omits.
//
// The omit-the-default discipline everywhere else (use_relays, an empty
// blocklist, the relay section) rests on the default being knowable. This one
// is not: Nebula's docs say pki.disconnect_invalid defaults to false, its code
// defaults it to true, and its own example config shows it commented as true.
//
// It is what closes the last gap at the end of a CA rotation. `finish` drops
// the outgoing CA, and a host still holding a certificate signed by it would
// otherwise keep its established tunnels open indefinitely -- trusted by
// nobody, still connected to everybody.
func TestGenerateHostConfigSetsDisconnectInvalid(t *testing.T) {
	g := NewGenerator()

	out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: testLighthouses()})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}

	pki := parseConfig(t, out)["pki"].(map[string]interface{})
	if pki["disconnect_invalid"] != true {
		t.Errorf("expected pki.disconnect_invalid true, got %v", pki["disconnect_invalid"])
	}
}

// TestGenerateHostConfigPreferredRanges covers both directions of a setting
// that is emitted only when the operator asks for it.
//
// The omission matters as much as the emission: every existing deployment has
// no preference set, and a host that expresses none must render exactly the
// config it always did rather than acquiring an empty key that shows up as a
// diff in whatever ships these files.
func TestGenerateHostConfigPreferredRanges(t *testing.T) {
	g := NewGenerator()

	t.Run("omitted when unset", func(t *testing.T) {
		out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: testLighthouses()})
		if err != nil {
			t.Fatalf("GenerateHostConfig failed: %v", err)
		}
		if _, present := parseConfig(t, out)["preferred_ranges"]; present {
			t.Error("expected preferred_ranges to be omitted when the host sets none")
		}
	})

	t.Run("rendered in order when set", func(t *testing.T) {
		host := testHost()
		host.PreferredRanges = `["10.0.0.0/8","192.168.0.0/16"]`

		out, err := g.GenerateHostConfig(HostConfigInput{Host: host, Lighthouses: testLighthouses()})
		if err != nil {
			t.Fatalf("GenerateHostConfig failed: %v", err)
		}

		raw, present := parseConfig(t, out)["preferred_ranges"]
		if !present {
			t.Fatal("expected preferred_ranges in the config")
		}

		got := raw.([]interface{})
		want := []string{"10.0.0.0/8", "192.168.0.0/16"}
		if len(got) != len(want) {
			t.Fatalf("expected %d preferred ranges, got %v", len(want), got)
		}
		// Preserved as the operator wrote it. Nebula treats the list as a SET
		// -- remote_list.go sorts on isPreferred(), a boolean membership test,
		// not on position -- so order changes nothing at runtime. It is kept
		// anyway because the value arrives as stored JSON rather than from an
		// unordered query, so there is nothing to sort for and re-ordering it
		// would only manufacture diffs. That is the opposite of getBlocklist
		// and getRelays, which must sort precisely because their order is not
		// guaranteed.
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("preferred_ranges[%d] = %v, want %s", i, got[i], want[i])
			}
		}
	})

	t.Run("malformed JSON is an error", func(t *testing.T) {
		host := testHost()
		host.PreferredRanges = `{"not":"an array"}`

		if _, err := g.GenerateHostConfig(HostConfigInput{Host: host, Lighthouses: testLighthouses()}); err == nil {
			t.Error("expected an error for malformed preferred_ranges, got nil")
		}
	})
}

// TestGenerateHostConfigIsByteIdenticalForASingleAddressLighthouse is the
// regression test that makes this whole feature safe to ship.
//
// Every existing deployment has exactly one lighthouse address, no
// advertise_addrs and no local_allow_list. For those -- which is all of them on
// the day this lands -- the generator must emit the same bytes it emitted
// before any of this existed, because config_yaml is pulled by devices and
// shipped by whatever puts files on them: a config that differs only in
// whitespace or key order still reads as "every host changed" and still earns a
// restart of the entire fleet.
//
// The expected value is the literal output of the generator at the commit
// before the lighthouse address list, advertise_addrs and local_allow_list were
// added. It is deliberately a whole-document comparison and not a set of key
// assertions: key assertions pass while a marshalling change reorders
// everything, which is the diff this is here to catch.
func TestGenerateHostConfigIsByteIdenticalForASingleAddressLighthouse(t *testing.T) {
	g := NewGenerator()

	out, err := g.GenerateHostConfig(HostConfigInput{
		Host:        testHost(),
		Lighthouses: testLighthouses(),
	})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}

	const want = `firewall:
    inbound:
        - host: any
          port: any
          proto: icmp
    outbound:
        - host: any
          port: any
          proto: any
lighthouse:
    am_lighthouse: false
    hosts:
        - 10.128.0.1
    interval: 60
listen:
    host: 0.0.0.0
    port: 0
logging:
    format: text
    level: info
pki:
    ca: CA-PEM
    cert: CERT-PEM
    disconnect_invalid: true
    key: KEY-PEM
punchy:
    punch: true
    respond: true
static_host_map:
    10.128.0.1:
        - 1.2.3.4:4242
tun:
    dev: nebula1
    disabled: false
    drop_local_broadcast: false
    drop_multicast: false
    mtu: 1300
    tx_queue: 500
`

	if out != want {
		t.Errorf("config for a one-address lighthouse changed.\n got:\n%s\nwant:\n%s", out, want)
	}
}

// TestGenerateHostConfigRendersEveryLighthouseAddress covers the case a single
// public_host_port could not express.
//
// Nebula's static_host_map value is a list, and a lighthouse can legitimately
// be reachable at more than one address: dual-stack, two internet paths, or a
// LAN address for the peers in its own rack and a public one for everybody
// else. All of those are one lighthouse with several endpoints, not several
// lighthouses, so the overlay IP stays the single key.
func TestGenerateHostConfigRendersEveryLighthouseAddress(t *testing.T) {
	g := NewGenerator()

	lighthouses := []types.LighthouseInfo{
		{
			OverlayIP: "10.128.0.1",
			Addresses: []string{"1.2.3.4:4242", "[2001:db8::1]:4242", "192.168.10.5:4242"},
		},
	}

	out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: lighthouses})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}

	shm := parseConfig(t, out)["static_host_map"].(map[string]interface{})
	if len(shm) != 1 {
		t.Fatalf("expected one static_host_map entry, got %v", shm)
	}

	got := shm["10.128.0.1"].([]interface{})
	want := []string{"1.2.3.4:4242", "[2001:db8::1]:4242", "192.168.10.5:4242"}
	if len(got) != len(want) {
		t.Fatalf("expected %d endpoints, got %v", len(want), got)
	}
	// Order is the operator's: public_host_port leads, then additional_host_ports
	// as stored. Nebula tries the entries, so the order is a preference the
	// operator expressed, not an artifact to normalise away.
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("static_host_map endpoint %d = %v, want %s", i, got[i], want[i])
		}
	}
}

// TestGenerateHostConfigSkipsALighthouseWithNoAddress pins the degenerate case
// the API refuses but an old record can still hold.
//
// Rendering it would put an entry Nebula cannot parse into every peer's config,
// and a config error stops Nebula starting -- so one unsaveable row would take
// out every host in the network on its next restart. Skipping costs that one
// lighthouse its static entry and nothing else.
func TestGenerateHostConfigSkipsALighthouseWithNoAddress(t *testing.T) {
	g := NewGenerator()

	lighthouses := []types.LighthouseInfo{
		{OverlayIP: "10.128.0.1", Addresses: nil},
		{OverlayIP: "10.128.0.2", Addresses: []string{"1.2.3.4:4242"}},
	}

	out, err := g.GenerateHostConfig(HostConfigInput{Host: testHost(), Lighthouses: lighthouses})
	if err != nil {
		t.Fatalf("GenerateHostConfig failed: %v", err)
	}

	shm := parseConfig(t, out)["static_host_map"].(map[string]interface{})
	if _, present := shm["10.128.0.1"]; present {
		t.Error("expected the addressless lighthouse to be left out of static_host_map")
	}
	if _, present := shm["10.128.0.2"]; !present {
		t.Error("expected the addressed lighthouse to still be in static_host_map")
	}

	// It is still a discovery target: the overlay IP is what lighthouse.hosts
	// carries, and that half does not depend on knowing an endpoint.
	hosts := parseConfig(t, out)["lighthouse"].(map[string]interface{})["hosts"].([]interface{})
	if len(hosts) != 2 {
		t.Errorf("expected both lighthouses in lighthouse.hosts, got %v", hosts)
	}
}
