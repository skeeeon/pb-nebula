# 🦴 pb-nebula

**Nebula mesh VPN certificate authority and configuration management for PocketBase**

pb-nebula transforms PocketBase into a complete Nebula overlay network management system with automatic certificate generation, intelligent regeneration, and zero-configuration deployment.

## Features

### 🔐 Certificate Management
- ✅ **Automatic CA Generation** - Self-signed root CA created on first record
- ✅ **Host Certificate Signing** - Certificates signed by CA with embedded groups
- ✅ **Smart Regeneration** - Automatically regenerates certificates when groups or validity change
- ✅ **Expiration Management** - Host certificates capped by CA expiration
- ✅ **CURVE25519** - Uses Nebula's recommended Ed25519/X25519 curve

### 📝 Configuration Generation
- ✅ **Complete Nebula Configs** - Ready-to-use YAML with PKI, lighthouse, and firewall
- ✅ **Lighthouse Discovery** - Automatic static_host_map generation
- ✅ **Host-Based Firewall** - Firewall rules per host using certificate groups
- ✅ **Smart Config Updates** - Regenerates only when meaningful fields change
- ✅ **Sensible Defaults** - Production-ready settings out of the box

### 🌐 Network Management
- ✅ **CIDR Validation** - Ensures valid network ranges (IPv4)
- ✅ **IP Validation** - Hosts must be within network CIDR
- ✅ **Unique Constraints** - No duplicate IPs per network
- ✅ **Tenant Isolation** - Networks provide natural boundaries

### 🔄 Real-Time Sync
- ✅ **Two-Tier Regeneration** - Smart distinction between cert and config updates
- ✅ **Recursion Prevention** - No infinite loops or excessive processing
- ✅ **Event Filtering** - Optional custom event handling
- ✅ **Detailed Logging** - Clear visibility into what's happening

### 🔒 Security
- ✅ **PocketBase Auth** - Email/password authentication for hosts
- ✅ **Self-Service** - Hosts can only access their own records
- ✅ **Hidden Keys** - CA private key hidden from API
- ✅ **At-Rest Encryption** - Optional AES-256-GCM encryption of CA + host private keys
- ✅ **JSON Validation** - Invalid firewall rules rejected immediately

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

**Run your application:**

```bash
go run main.go serve
```

Access the admin UI at `http://127.0.0.1:8090/_/`

## Architecture

### Collections

```
PocketBase Collections
├── nebula_ca           CA certificates (admin only, multi-CA supported)
├── nebula_networks     Network definitions with CIDR ranges
└── nebula_hosts        Auth collection with certificates & configs

Automatic Workflow
├── Create CA → Certificate auto-generated
├── Create Network → CIDR validated
├── Create Host → Certificate + Config auto-generated
├── Update Groups/IP/Hostname → Certificate regenerated (embedded in cert)
├── Update Firewall → Config regenerated (not in cert)
├── Update Lighthouse → Peer host configs regenerated
└── Update Network CIDR → All host configs regenerated
```

### Data Model

#### `nebula_ca` (Base Collection)
Certificate authorities. Multiple CAs are supported — each CA roots its own
independent mesh and can serve multiple networks.

| Field | Type | Description |
|-------|------|-------------|
| name | text | CA name |
| certificate | text | PEM encoded CA certificate (auto-generated) |
| private_key | text | PEM encoded CA private key (HIDDEN) |
| validity_years | number | Certificate validity (default: 10) |
| expires_at | date | CA expiration timestamp |
| curve | text | Cryptographic curve (CURVE25519) |

**Security:** Admin only, private_key field hidden from API.

#### `nebula_networks` (Base Collection)
Network definitions for tenant isolation.

| Field | Type | Description |
|-------|------|-------------|
| name | text | Network name |
| cidr_range | text | IPv4 CIDR (e.g., "10.128.0.0/16") |
| description | text | Network description |
| ca_id | relation | Link to nebula_ca |
| active | bool | Enable/disable network |

**Uniqueness:** Network `name` and `cidr_range` are unique per CA — the same
name or CIDR can exist under different CAs (separate meshes).

**Note:** Firewall rules are HOST-BASED, not network-based (Nebula design).

#### `nebula_hosts` (Auth Collection)
Host configurations with PocketBase authentication.

| Field | Type | Description |
|-------|------|-------------|
| email | text | PocketBase auth email |
| password | text | PocketBase auth password |
| hostname | text | Nebula hostname (unique per network) |
| network_id | relation | Link to nebula_networks |
| overlay_ip | text | Overlay IP (e.g., "10.128.0.100") |
| groups | json | Array of group names (embedded in cert) |
| is_lighthouse | bool | Is this a lighthouse? |
| public_host_port | text | Public IP:PORT (required if lighthouse) |
| certificate | text | PEM host certificate (auto-generated) |
| private_key | text | PEM host private key (auto-generated) |
| ca_certificate | text | PEM CA cert (denormalized) |
| config_yaml | text | Complete Nebula config (auto-generated) |
| firewall_outbound | json | Outbound firewall rules |
| firewall_inbound | json | Inbound firewall rules |
| validity_years | number | Certificate validity (default: 1) |
| expires_at | date | Certificate expiration |
| active | bool | Enable/disable host |

**Security:** Users can only access their own records (self-service).

## Usage Guide

Admin requests authenticate with a superuser token:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://127.0.0.1:8090/api/collections/_superusers/auth-with-password \
  -H "Content-Type: application/json" \
  -d '{"identity":"admin@example.com","password":"adminpassword"}' | jq -r .token)
```

### 1. Create Certificate Authority

```bash
curl -X POST http://127.0.0.1:8090/api/collections/nebula_ca/records \
  -H "Content-Type: application/json" \
  -H "Authorization: $ADMIN_TOKEN" \
  -d '{
    "name": "my-org-ca",
    "validity_years": 10
  }'
```

**Result:** CA certificate and private key automatically generated.

**Expected Log:**
```
[15:04:05] 🔐 CERT Generating CA certificate for my-org-ca...
[15:04:05] ✅ SUCCESS Generated CA certificate for my-org-ca
```

### 2. Create Network

```bash
curl -X POST http://127.0.0.1:8090/api/collections/nebula_networks/records \
  -H "Content-Type: application/json" \
  -H "Authorization: $ADMIN_TOKEN" \
  -d '{
    "name": "production",
    "cidr_range": "10.128.0.0/16",
    "ca_id": "<ca_record_id>",
    "description": "Production network",
    "active": true
  }'
```

### 3. Create Lighthouse Host

```bash
curl -X POST http://127.0.0.1:8090/api/collections/nebula_hosts/records \
  -H "Content-Type: application/json" \
  -H "Authorization: $ADMIN_TOKEN" \
  -d '{
    "email": "lighthouse@example.com",
    "password": "secure-password-here",
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

**Result:** 
- Certificate generated and signed by CA
- Complete Nebula config with `am_lighthouse: true`
- Config stored in `config_yaml` field

**Expected Log:**
```
[15:04:05] 🔐 CERT Generating certificate and config for lighthouse-01...
[15:04:05] ✅ SUCCESS Generated certificate and config for lighthouse-01
[15:04:05] ℹ️  INFO Skipping regeneration for lighthouse-01 (initial certificate generation)
```

### 4. Create Regular Host

```bash
curl -X POST http://127.0.0.1:8090/api/collections/nebula_hosts/records \
  -H "Content-Type: application/json" \
  -H "Authorization: $ADMIN_TOKEN" \
  -d '{
    "email": "web01@example.com",
    "password": "secure-password-here",
    "hostname": "web-01",
    "network_id": "<network_record_id>",
    "overlay_ip": "10.128.0.100",
    "groups": ["web"],
    "is_lighthouse": false,
    "firewall_outbound": [
      {"port": "any", "proto": "any", "host": "any"}
    ],
    "firewall_inbound": [
      {"port": "any", "proto": "icmp", "host": "any"},
      {"port": "443", "proto": "tcp", "host": "any"},
      {"port": "22", "proto": "tcp", "groups": ["admin"]}
    ],
    "validity_years": 1,
    "active": true
  }'
```

**Result:**
- Certificate generated with `["web"]` group embedded
- Config includes lighthouse discovery via `static_host_map`
- Firewall rules applied (HTTPS from any, SSH from admin group only)

### 5. Host Downloads Configuration

Hosts authenticate and download their configuration:

```bash
# Authenticate as host
AUTH_RESPONSE=$(curl -X POST http://127.0.0.1:8090/api/collections/nebula_hosts/auth-with-password \
  -H "Content-Type: application/json" \
  -d '{
    "identity": "web01@example.com",
    "password": "secure-password-here"
  }')

AUTH_TOKEN=$(echo $AUTH_RESPONSE | jq -r '.token')

# Download complete config
curl http://127.0.0.1:8090/api/collections/nebula_hosts/records/<host_id> \
  -H "Authorization: Bearer $AUTH_TOKEN" \
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

## Smart Regeneration

pb-nebula intelligently regenerates certificates and configs based on what changed:

### 🔐 Certificate Regeneration (Expensive)

These fields are **embedded in the certificate** and require regeneration:

| Field Changed | Action | Why |
|--------------|--------|-----|
| `groups` | Regenerate certificate + config | Groups are in the certificate |
| `validity_years` | Regenerate certificate + config | Changes certificate lifetime |

**Log Output:**
```
[15:04:05] ℹ️  INFO Groups changed for web-01, regenerating certificate
[15:04:05] 🔐 CERT Regenerating certificate and config for web-01...
[15:04:05] ✅ SUCCESS Regenerated certificate and config for web-01
```

### 📝 Config Regeneration Only (Cheap)

These fields are **only in the config** and don't require certificate regeneration:

| Field Changed | Action | Why |
|--------------|--------|-----|
| `is_lighthouse` | Regenerate config only | Config setting |
| `public_host_port` | Regenerate config only | Config setting |
| `firewall_outbound` | Regenerate config only | Config setting |
| `firewall_inbound` | Regenerate config only | Config setting |

**Log Output:**
```
[15:04:05] ℹ️  INFO Firewall inbound rules changed for web-01, regenerating config
[15:04:05] 📝 CONFIG Regenerating config for web-01...
[15:04:05] ✅ SUCCESS Regenerated config for web-01
```

### ⏭️ No Regeneration

These fields don't affect certificates or configs:

- `email`, `password` - Auth only
- `hostname` - Can't change (in certificate)
- `overlay_ip` - Can't change (in certificate)
- `active` - Management flag

**Log Output:**
```
[15:04:05] ℹ️  INFO No meaningful changes detected for web-01, skipping regeneration
```

## Firewall Rules

Firewall rules are **host-based** (not network-based) following Nebula's design.

### Default Behavior

If no firewall rules specified:

**Outbound:** Allow all
```json
[{"port": "any", "proto": "any", "host": "any"}]
```

**Inbound:** Allow ICMP only (Nebula recommended)
```json
[{"port": "any", "proto": "icmp", "host": "any"}]
```

This allows ping for troubleshooting while blocking all TCP/UDP by default.

### Nebula Firewall Format

Rules use Nebula's native JSON format:

```json
{
  "firewall_inbound": [
    {
      "port": "443",
      "proto": "tcp",
      "host": "any"
    },
    {
      "port": "22",
      "proto": "tcp",
      "groups": ["admin"]
    },
    {
      "port": "5432",
      "proto": "tcp",
      "groups": ["app", "web"]
    }
  ]
}
```

**Fields:**
- `port`: Port number, range ("80-443"), or "any"
- `proto`: "tcp", "udp", "icmp", or "any"
- `host`: "any" or specific IP
- `groups`: Array of group names (from certificates)

### Example Firewall Configurations

#### Web Server (Public HTTPS)
```json
{
  "firewall_inbound": [
    {"port": "any", "proto": "icmp", "host": "any"},
    {"port": "443", "proto": "tcp", "host": "any"},
    {"port": "80", "proto": "tcp", "host": "any"},
    {"port": "22", "proto": "tcp", "groups": ["admin"]}
  ]
}
```

#### Database Server (Internal Only)
```json
{
  "firewall_inbound": [
    {"port": "any", "proto": "icmp", "host": "any"},
    {"port": "5432", "proto": "tcp", "groups": ["app", "web"]},
    {"port": "22", "proto": "tcp", "groups": ["admin"]}
  ]
}
```

#### Admin Host (Locked Down)
```json
{
  "firewall_inbound": [
    {"port": "any", "proto": "icmp", "host": "any"},
    {"port": "22", "proto": "tcp", "groups": ["admin"]}
  ],
  "firewall_outbound": [
    {"port": "any", "proto": "any", "host": "any"}
  ]
}
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

    // Optional at-rest encryption key (32 chars). Empty = disabled.
    EncryptionKey string
}
```

### Custom Configuration Example

```go
options := pbnebula.DefaultOptions()

// Customize collection names (for multi-tenant)
options.CACollectionName = "tenant1_ca"
options.NetworkCollectionName = "tenant1_networks"
options.HostCollectionName = "tenant1_hosts"

// Customize validity periods
options.DefaultCAValidityYears = 20
options.DefaultHostValidityYears = 2

// Disable logging
options.LogToConsole = false

// Custom event filter
options.EventFilter = func(collectionName, eventType string) bool {
    // Disable network update regeneration
    if eventType == "network_update" {
        return false
    }
    return true
}

pbnebula.Setup(app, options)
```

## At-Rest Encryption

pb-nebula can encrypt sensitive private keys at rest using AES-256-GCM. When enabled, the CA `private_key` and each host `private_key` column are stored encrypted in the database.

### Enabling

Provide a 32-character key via `Options.EncryptionKey`. Validation rejects any other length at setup time.

```go
options := pbnebula.DefaultOptions()

// 32-character key — load from env, secret manager, etc. Do NOT hardcode.
options.EncryptionKey = os.Getenv("PB_NEBULA_ENCRYPTION_KEY")

if err := pbnebula.Setup(app, options); err != nil {
    log.Fatal(err)
}
```

On startup the log line confirms the mode:

```
[15:04:05] ℹ️  INFO At-rest encryption: enabled (CA + host private_key)
```

### What is encrypted

| Field | Encrypted? |
|-------|-----------|
| `nebula_ca.private_key` | ✅ Yes |
| `nebula_hosts.private_key` | ✅ Yes |
| `nebula_ca.certificate` | ❌ No (public) |
| `nebula_hosts.certificate` | ❌ No (public) |
| `nebula_hosts.ca_certificate` | ❌ No (public) |
| `nebula_hosts.config_yaml` | ❌ No — see limitation below |

### Limitation: `config_yaml` is plaintext

The generated `config_yaml` field embeds the host's private key inline because Nebula's `pki.key` block requires it. That field stays plaintext at rest so hosts can download it directly via the standard PocketBase API. **Encryption protects the standalone `private_key` column, not the same key as embedded inside the YAML.**

If your threat model requires the YAML itself to be encrypted at rest, you'd need to add a custom download route that encrypts on store and decrypts on read — out of scope for the default flow.

### Backward compatibility

Encrypted values are tagged with an `enc::` prefix. Records written before encryption was enabled (no prefix) continue to read transparently — turning the key on does not break existing data, and existing records will be re-encrypted the next time they're regenerated (e.g., on a `groups` or `validity_years` change).

### Operational warnings

- **Loss of the encryption key = loss of the CA private key.** Without the CA key you cannot sign new host certificates and must regenerate the entire CA. Treat the key like the CA itself: back it up, rotate carefully, never commit it.
- **Rotation is not automatic.** Changing `EncryptionKey` will leave already-encrypted columns unreadable. Plan a re-encryption migration before swapping keys.
- **Use a strong key.** 32 random bytes (e.g., `openssl rand -base64 24` truncated to 32 chars, or `head -c 32 /dev/urandom | base64 | head -c 32`).

## Multi-Tenant Setup

Run multiple isolated Nebula instances with custom collection names:

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

Each tenant has complete isolation with their own CA, networks, and hosts.

## API Reference

### Setup

```go
func Setup(app *pocketbase.PocketBase, options Options) error
```

Main entry point. Initializes pb-nebula with PocketBase application.

**Parameters:**
- `app`: PocketBase application instance
- `options`: Configuration options

**Returns:** Error if initialization fails

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

## Logging

pb-nebula provides detailed logging with emoji prefixes for quick status recognition:

```
[15:04:05] 🚀 START Initializing pb-nebula...
[15:04:05] ✅ SUCCESS Collections initialized
[15:04:05] 🔐 CERT Generating certificate for web-01...
[15:04:05] 📝 CONFIG Regenerating config for web-01...
[15:04:05] ℹ️  INFO Groups changed for web-01, regenerating certificate
[15:04:05] ⚠️  WARNING Failed to find hosts in network
[15:04:05] ❌ ERROR Failed to generate certificate
```

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

### Build from Source

```bash
git clone https://github.com/skeeeon/pb-nebula
cd pb-nebula
go mod download
go build ./examples/basic
./basic serve
```

## Troubleshooting

### Host Creation Slow

**Problem:** Host creation takes > 5 seconds

**Solution:** This was fixed in the latest version with recursion prevention. Upgrade to latest version.

### Certificate Not Regenerating

**Problem:** Updating groups doesn't regenerate certificate

**Check:**
1. Verify `groups` field is JSON format (not text)
2. Check logs for regeneration messages
3. Ensure groups actually changed

### Firewall Rules Not Applying

**Problem:** Custom firewall rules not in generated config

**Check:**
1. Verify JSON format is valid
2. Use PocketBase's JSON field type
3. Check for validation errors in API response

### ICMP Not Working

**Problem:** Can't ping hosts

**Solution:** 
- Default config now includes ICMP
- If using custom firewall rules, explicitly add ICMP rule
- Verify Nebula is running on both hosts

## Security Considerations

### Production Deployment

1. **Protect CA Private Key**
   - Stored in HIDDEN field (not via API)
   - Still in database — protect database access
   - Enable [at-rest encryption](#at-rest-encryption) via `Options.EncryptionKey` for an additional layer
   - Note: `config_yaml` embeds host private keys inline and remains plaintext at rest

2. **Use HTTPS**
   - Always serve PocketBase behind HTTPS in production
   - Protects credentials and certificates in transit

3. **Backup Regularly**
   - CA private key cannot be regenerated
   - Loss of CA = regenerate all certificates
   - Backup `pb_data/data.db` regularly

4. **Rotate Certificates**
   - Plan for certificate renewal before expiration
   - Default 1 year for hosts provides good balance
   - Monitor expiration dates

5. **Network Isolation**
   - Use separate networks for different security zones
   - Apply firewall rules based on certificate groups
   - Follow principle of least privilege

## License

MIT License - See LICENSE file for details
