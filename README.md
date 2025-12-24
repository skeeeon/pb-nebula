# 🦴 pb-nebula

**Nebula mesh VPN certificate and configuration management for PocketBase**

pb-nebula transforms PocketBase into a complete Nebula overlay network management system. It automatically handles CA generation, host certificate signing, and full Nebula configuration generation with zero manual intervention.

## Features

- ✅ **Automatic CA Generation** - Create self-signed CA certificates on record creation
- ✅ **Host Certificate Signing** - Generate and sign host certificates automatically
- ✅ **Config Generation** - Complete Nebula YAML configs with lighthouse discovery
- ✅ **Real-time Updates** - Automatic config regeneration on network/host changes
- ✅ **IP Validation** - Ensure hosts are within network CIDR ranges
- ✅ **Firewall Management** - Network-level firewall rules in Nebula native format
- ✅ **PocketBase Auth** - Hosts authenticate via email/password to download configs
- ✅ **Tenant Isolation** - Networks provide natural isolation boundaries

## Installation

```bash
go get github.com/skeeeon/pb-nebula
```

## Quick Start

```go
package main

import (
    "log"
    "github.com/pocketbase/pocketbase"
    "github.com/skeeeon/pb-nebula"
)

func main() {
    app := pocketbase.New()

    // Setup pb-nebula with defaults
    if err := pbnebula.Setup(app, pbnebula.DefaultOptions()); err != nil {
        log.Fatal(err)
    }

    if err := app.Start(); err != nil {
        log.Fatal(err)
    }
}
```

Run your application:

```bash
go run main.go serve
```

Access the admin UI at `http://127.0.0.1:8090/_/`

## How It Works

### Architecture

```
PocketBase Collections
├── nebula_ca           (Root CA - Single record)
├── nebula_networks     (Network definitions with CIDR ranges)
└── nebula_hosts        (Auth collection - Hosts with certificates)

Automatic Workflow
├── Create CA → Certificate generated automatically
├── Create Network → CIDR validated
├── Create Host → Certificate + Config generated
└── Update Network → All host configs regenerated
```

### Collections

#### `nebula_ca` (Base Collection)
- Single CA per deployment (like pb-nats operator)
- Contains root certificate and private key
- Admin-only access
- Private key stored in HIDDEN field

#### `nebula_networks` (Base Collection)
- Network definitions with CIDR ranges (e.g., `10.128.0.0/16`)
- Firewall rules (Nebula native JSON format)
- Links to CA via `ca_id` relation
- Active/inactive flag

#### `nebula_hosts` (Auth Collection)
- PocketBase authentication (email/password)
- Nebula identity (hostname, overlay IP)
- Certificate and private key (auto-generated)
- Complete Nebula config YAML
- Lighthouse configuration
- Group membership for firewall rules

## Usage Guide

### 1. Create Certificate Authority

Via Admin UI or API:

```bash
curl -X POST http://127.0.0.1:8090/api/collections/nebula_ca/records \
  -H "Content-Type: application/json" \
  -u "admin@example.com:password" \
  -d '{
    "name": "my-org-ca",
    "validity_years": 10
  }'
```

**Result**: CA certificate and private key automatically generated.

### 2. Create Network

```bash
curl -X POST http://127.0.0.1:8090/api/collections/nebula_networks/records \
  -H "Content-Type: application/json" \
  -u "admin@example.com:password" \
  -d '{
    "name": "production",
    "cidr_range": "10.128.0.0/16",
    "ca_id": "<ca_record_id>",
    "firewall_outbound": [{"port": "any", "proto": "any", "host": "any"}],
    "firewall_inbound": [{"port": "22", "proto": "tcp", "groups": ["admin"]}],
    "active": true
  }'
```

### 3. Create Lighthouse Host

```bash
curl -X POST http://127.0.0.1:8090/api/collections/nebula_hosts/records \
  -H "Content-Type: application/json" \
  -u "admin@example.com:password" \
  -d '{
    "email": "lighthouse@example.com",
    "password": "secure-password",
    "hostname": "lighthouse-01",
    "network_id": "<network_record_id>",
    "overlay_ip": "10.128.0.1",
    "groups": ["lighthouse"],
    "is_lighthouse": true,
    "public_host_port": "203.0.113.10:4242",
    "validity_years": 1,
    "active": true
  }'
```

**Result**: 
- Certificate generated and signed by CA
- Complete Nebula config with `am_lighthouse: true`
- Config stored in `config_yaml` field

### 4. Create Regular Host

```bash
curl -X POST http://127.0.0.1:8090/api/collections/nebula_hosts/records \
  -H "Content-Type: application/json" \
  -u "admin@example.com:password" \
  -d '{
    "email": "web01@example.com",
    "password": "secure-password",
    "hostname": "web-01",
    "network_id": "<network_record_id>",
    "overlay_ip": "10.128.0.100",
    "groups": ["web"],
    "is_lighthouse": false,
    "validity_years": 1,
    "active": true
  }'
```

**Result**:
- Certificate generated and signed by CA
- Config includes lighthouse discovery via `static_host_map`
- Config stored in `config_yaml` field

### 5. Host Downloads Config

Hosts authenticate and download their configuration:

```bash
# Authenticate
curl -X POST http://127.0.0.1:8090/api/collections/nebula_hosts/auth-with-password \
  -H "Content-Type: application/json" \
  -d '{
    "identity": "web01@example.com",
    "password": "secure-password"
  }'

# Download config
curl http://127.0.0.1:8090/api/collections/nebula_hosts/records/<host_id> \
  -H "Authorization: Bearer <token>" \
  | jq -r '.config_yaml' > /etc/nebula/config.yml
```

### 6. Deploy and Run Nebula

```bash
# Download Nebula binary
curl -LO https://github.com/slackhq/nebula/releases/download/v1.9.5/nebula-linux-amd64.tar.gz
tar xzf nebula-linux-amd64.tar.gz

# Start Nebula with downloaded config
sudo ./nebula -config /etc/nebula/config.yml
```

## Configuration Options

```go
type Options struct {
    // Collection names (customizable)
    CACollectionName      string // Default: "nebula_ca"
    NetworkCollectionName string // Default: "nebula_networks"
    HostCollectionName    string // Default: "nebula_hosts"

    // Certificate defaults
    DefaultCAValidityYears   int  // Default: 10 years
    DefaultHostValidityYears int  // Default: 1 year

    // Logging
    LogToConsole bool // Default: true

    // Optional event filter
    EventFilter func(collectionName, eventType string) bool
}
```

### Custom Options Example

```go
options := pbnebula.DefaultOptions()

// Customize collection names
options.CACollectionName = "my_ca"
options.NetworkCollectionName = "my_networks"
options.HostCollectionName = "my_hosts"

// Customize validity periods
options.DefaultCAValidityYears = 20
options.DefaultHostValidityYears = 2

// Disable logging
options.LogToConsole = false

// Custom event filter (disable network update regeneration)
options.EventFilter = func(collectionName, eventType string) bool {
    if eventType == "network_update" {
        return false // Don't regenerate all host configs on network updates
    }
    return true
}

pbnebula.Setup(app, options)
```

## Firewall Rules

Firewall rules are stored in Nebula's native JSON format:

```json
{
  "firewall_outbound": [
    {
      "port": "any",
      "proto": "any",
      "host": "any"
    }
  ],
  "firewall_inbound": [
    {
      "port": "22",
      "proto": "tcp",
      "groups": ["admin"]
    },
    {
      "port": "80,443",
      "proto": "tcp",
      "groups": ["web"]
    }
  ]
}
```

Rules apply to all hosts in the network. Groups are matched against host's `groups` field.

## Multi-Tenant Setup

Use custom collection names to run multiple isolated Nebula instances:

```go
// Tenant 1
options1 := pbnebula.DefaultOptions()
options1.CACollectionName = "tenant1_ca"
options1.NetworkCollectionName = "tenant1_networks"
options1.HostCollectionName = "tenant1_hosts"
pbnebula.Setup(app, options1)

// Tenant 2
options2 := pbnebula.DefaultOptions()
options2.CACollectionName = "tenant2_ca"
options2.NetworkCollectionName = "tenant2_networks"
options2.HostCollectionName = "tenant2_hosts"
pbnebula.Setup(app, options2)
```

## API Reference

### Setup

```go
func Setup(app *pocketbase.PocketBase, options Options) error
```

Main entry point. Initializes pb-nebula with PocketBase application.

### DefaultOptions

```go
func DefaultOptions() Options
```

Returns sensible defaults:
- CA validity: 10 years
- Host validity: 1 year
- Console logging: enabled
- Standard collection names

### Event Types

```go
const (
    EventTypeCACreate      = "ca_create"
    EventTypeNetworkCreate = "network_create"
    EventTypeNetworkUpdate = "network_update"
    EventTypeHostCreate    = "host_create"
    EventTypeHostUpdate    = "host_update"
)
```

Used with `EventFilter` for custom event handling.

## Development

### Project Structure

```
pb-nebula/
├── nebula.go                    # Main Setup() function
├── options.go                   # DefaultOptions() and validation
├── errors.go                    # Error definitions
├── go.mod                       # Dependencies
├── README.md                    # This file
├── examples/
│   └── basic/main.go           # Working example
└── internal/
    ├── collections/
    │   └── manager.go          # Collection creation
    ├── cert/
    │   └── manager.go          # Certificate operations
    ├── config/
    │   └── generator.go        # YAML config generation
    ├── ipam/
    │   └── manager.go          # IP validation
    ├── sync/
    │   └── manager.go          # PocketBase hooks
    ├── types/
    │   └── types.go            # Data structures
    └── utils/
        └── logger.go           # Logging utilities
```

### Dependencies

- **PocketBase** `v0.31.0+` - Application framework
- **Nebula cert** `v1.9.5` - Certificate generation (crypto operations)
- **yaml.v3** - YAML config generation

### Build from Source

```bash
git clone https://github.com/skeeeon/pb-nebula
cd pb-nebula
go mod download
go build ./examples/basic
./basic serve
```

## License

MIT License - See LICENSE file for details

