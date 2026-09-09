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
		{OverlayIP: "10.128.0.1", PublicHostPort: "1.2.3.4:4242"},
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

	out, err := g.GenerateHostConfig(testHost(), testLighthouses(), nil)
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

	out, err := g.GenerateHostConfig(host, testLighthouses(), nil)
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

	out, err := g.GenerateHostConfig(testHost(), nil, nil)
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

	out, err := g.GenerateHostConfig(host, testLighthouses(), nil)
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

	_, err := g.GenerateHostConfig(host, nil, nil)
	if !errors.Is(err, types.ErrInvalidFirewall) {
		t.Errorf("expected ErrInvalidFirewall, got %v", err)
	}
}

func TestExtractPort(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		hostPort     string
		isLighthouse bool
		want         int
	}{
		{"1.2.3.4:4242", true, 4242},
		{"1.2.3.4:4242", false, 0}, // regular hosts use ephemeral port
		{"", true, 0},
		{"no-port", true, 0},
		{"[fd00::1]:4242", true, 4242}, // IPv6 public endpoint
	}

	for _, tt := range tests {
		if got := g.extractPort(tt.hostPort, tt.isLighthouse); got != tt.want {
			t.Errorf("extractPort(%q, %v) = %d, want %d", tt.hostPort, tt.isLighthouse, got, tt.want)
		}
	}
}

func TestGenerateHostConfigEmbedsPrivateKeyInline(t *testing.T) {
	// Documents the known limitation: config_yaml carries the private key
	// inline (Nebula's PKI block requires it), so it is plaintext at rest.
	g := NewGenerator()

	out, err := g.GenerateHostConfig(testHost(), nil, nil)
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

	out, err := g.GenerateHostConfig(testHost(), testLighthouses(), fingerprints)
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
			out, err := g.GenerateHostConfig(testHost(), testLighthouses(), blocklist)
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
