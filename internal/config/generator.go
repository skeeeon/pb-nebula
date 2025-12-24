package config

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	pbtypes "github.com/skeeeon/pb-nebula/internal/types"
)

// GenerateConfig creates the Nebula YAML config string
func GenerateConfig(
	node *pbtypes.NodeRecord,
	authority *pbtypes.AuthorityRecord,
	lighthouses []*pbtypes.NodeRecord,
	rules []*pbtypes.RuleRecord,
	groupMap map[string]string, // ID -> Name map
) (string, error) {

	type tplData struct {
		IsLighthouse bool
		Port         int
		Lighthouses  []string
		StaticMap    map[string][]string
		Rules        []*pbtypes.RuleRecord
		GroupMap     map[string]string
		TunName      string
	}

	// 1. Prepare Static Host Map
	staticMap := make(map[string][]string)
	var lhIPs []string

	for _, lh := range lighthouses {
		// Skip self if we are a lighthouse
		if lh.ID == node.ID {
			continue
		}
		// If lighthouse has static IPs (public internet IPs), map them to its Overlay IP
		if len(lh.StaticIPs) > 0 {
			staticMap[lh.IPAddress] = lh.StaticIPs
			lhIPs = append(lhIPs, lh.IPAddress)
		}
	}

	data := tplData{
		IsLighthouse: node.IsLighthouse,
		Port:         authority.Port,
		Lighthouses:  lhIPs,
		StaticMap:    staticMap,
		Rules:        rules,
		GroupMap:     groupMap,
		TunName:      "nebula0",
	}

	// 2. Parse Template
	tmpl, err := template.New("nebula").Parse(configTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// Basic template - can be expanded later
const configTemplate = `
pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key: /etc/nebula/host.key

static_host_map:
{{- range $overlay, $publics := .StaticMap }}
  "{{ $overlay }}": {{ range $publics }}["{{ . }}"]{{ end }}
{{- end }}

lighthouse:
  am_lighthouse: {{ .IsLighthouse }}
  interval: 60
  hosts:
    {{- range .Lighthouses }}
    - "{{ . }}"
    {{- end }}

listen:
  host: 0.0.0.0
  port: {{ .Port }}

tun:
  disabled: false
  dev: {{ .TunName }}
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300

logging:
  level: info
  format: text

firewall:
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m

  {{- if .Rules }}
  outbound:
    {{- range .Rules }}
    {{- if eq .Direction "outbound" }}
    - port: {{ .Port }}
      proto: {{ .Proto }}
      {{- if .DestGroups }}
      groups:
        {{- range .DestGroups }}
        - "{{ index $.GroupMap . }}"
        {{- end }}
      {{- else }}
      host: any
      {{- end }}
    {{- end }}
    {{- end }}

  inbound:
    {{- range .Rules }}
    {{- if eq .Direction "inbound" }}
    - port: {{ .Port }}
      proto: {{ .Proto }}
      {{- if .SourceGroups }}
      groups:
        {{- range .SourceGroups }}
        - "{{ index $.GroupMap . }}"
        {{- end }}
      {{- else }}
      host: any
      {{- end }}
    {{- end }}
    {{- end }}
  {{- else }}
  # Default permissive if no rules (Dev mode)
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
  {{- end }}
`
