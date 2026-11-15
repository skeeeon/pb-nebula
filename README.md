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
- ✅ **Certificate Revocation** - Deactivating a host blocklists its certificate across the network
- ✅ **JSON Validation** - Invalid firewall rules rejected immediately

## Installation

```bash
go get github.com/skeeeon/pb-nebula
```

### Requirements

**Every host on the mesh must run Nebula v1.10 or newer.** pb-nebula issues
version 2 certificates, matching the current default of `nebula-cert ca`, and
[Nebula's own upgrade guide](https://nebula.defined.net/docs/guides/upgrade-to-cert-v2-and-ipv6/)
is explicit that "older versions cannot validate v2 certificates." A host on an
older build will not fail loudly — it simply never completes a handshake.

## Quick Start

```go
package main

import (
    "log"
    "ganigeorgiev.com/pocketbase/pocketbase"
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
| public_host_port | text | Public HOST:PORT (required if lighthouse or relay) |
| additional_host_ports | json | Further endpoints peers can reach this host at — see [Lighthouse Addresses](#lighthouse-addresses) |
| advertise_addrs | json | Addresses this host reports to the lighthouses, format `"ip:port"` with `0` meaning the real listening port |
| local_allow_list | json | Which of this host's own interface addresses it advertises |
| certificate | text | PEM host certificate (auto-generated) |
| private_key | text | PEM host private key (auto-generated) |
| ca_certificate | text | PEM CA cert (denormalized) |
| config_yaml | text | Complete Nebula config (auto-generated) |
| revoked_certificates | json | PEM certificates this host was issued that every peer refuses (auto-generated) — see [A replaced certificate is still valid](#a-replaced-certificate-is-still-valid) |
| retired_certificates | json | PEM certificates replaced by renewal or CA rotation, refused once the host is inactive (auto-generated) |
| firewall_outbound | json | Outbound firewall rules |
| firewall_inbound | json | Inbound firewall rules |
| validity_years | number | Certificate validity (default: 1) |
| expires_at | date | Certificate expiration |
| active | bool | Host is a member of the network. Setting it `false` blocklists its certificate — see [Certificate Revocation](#certificate-revocation) |

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

Each of these, and `renew`, also **revokes the certificate it replaced**, so
every other config under the CA is regenerated with it in `pki.blocklist` — see
[A replaced certificate is still valid](#a-replaced-certificate-is-still-valid).

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
| `additional_host_ports` | Regenerate config for **every host in the network** | Peers carry the whole address list in `static_host_map` |
| `advertise_addrs` | Regenerate config only | Reported at runtime, so no peer config holds it |
| `local_allow_list` | Regenerate config only | Reported at runtime, so no peer config holds it |
| `firewall_outbound` | Regenerate config only | Config setting |
| `firewall_inbound` | Regenerate config only | Config setting |
| `active` | Regenerate config for **every host in the network** | Revocation lives in each peer's `pki.blocklist` — see [Certificate Revocation](#certificate-revocation) |

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

**Log Output:**
```
[15:04:05] ℹ️  INFO No meaningful changes detected for web-01, skipping regeneration
```

## Certificate Revocation

**Nebula has no CRL and no OCSP.** The only way to refuse a certificate the CA
has already signed is `pki.blocklist` — a list of certificate fingerprints
carried by every *other* host, loaded into the CA pool at startup and again on
`SIGHUP`. Revocation is therefore a property of the whole network that every
member config has to restate. This is the opposite shape from a JWT-based system
like NATS, where a revocation list lives inside one signed document and a single
write reaches every server.

Flip `active` on a host — in either direction — and pb-nebula:

1. Computes the SHA-256 fingerprint of each certificate the host holds or held,
   from the stored PEM rather than a cached column.
2. Regenerates every *other* config in the network, with those fingerprints in
   `pki.blocklist`.
3. Regenerates the changed host's own config, since the peer fan-out
   deliberately excludes the record that triggered it.

Reactivating a host issues it a new certificate, and the ones it held stay on
the list (see below).

```yaml
pki:
  ca: |
    -----BEGIN NEBULA CERTIFICATE-----
    ...
  cert: |
    -----BEGIN NEBULA CERTIFICATE-----
    ...
  key: |
    ...
  disconnect_invalid: true
  blocklist:
    - 7d0dc0bd1ae0bbd1a4a2ec8dd4a4b1d1e7d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6
```

`disconnect_invalid` is the one Nebula default pb-nebula restates rather than
omits. Nebula's docs say it defaults to `false`, its code defaults it to `true`,
and its own example config shows it commented as `true` — when the documented
default and the real one disagree, the config says what it means. Revocation
does not depend on it (a blocklisted certificate is disconnected regardless),
but an expired certificate and a finished CA rotation both do.

The blocklist is scoped to the **CA**, not the network — because that is where
Nebula's trust boundary is. Every host carrying a CA in `pki.ca` will verify
anything that CA signed, including hosts in a *different* pb-nebula network
under the same CA. A network-scoped blocklist would revoke a host from its own
peers and leave it verifiable by its siblings. So deactivating a host
regenerates every config under its CA; lighthouse and relay changes stay
network-scoped, since no host renders another network's lighthouses.

An empty blocklist is **omitted** rather than written as an empty list, so a
network with nothing revoked renders exactly the config it did before this
feature. Fingerprints are sorted — unsorted, map iteration order would make
every regeneration look like a change.

A host with no certificate yet is skipped. One unparseable certificate is logged
and omitted rather than costing the network its entire blocklist, and a failure
to build the list is never fatal: a config without a blocklist is the config
this library generated for years, and failing would stop a host getting any
config at all.

### A replaced certificate is still valid

Re-issuing a host does not make the certificate it replaces stop working; only
expiry or the blocklist does. So pb-nebula keeps each replaced certificate on
the host, until it expires or its CA leaves the trust bundle, and lists it:

- **Revoked** when the re-issue was asked for: an edit to `hostname`,
  `overlay_ip`, `groups`, `unsafe_networks` or `validity_years`, `renew`, or
  reactivation. Every peer refuses it from then on, so a host taken out of a
  group does not keep the group in its old certificate, and `renew` is a remedy
  for a leaked key. The fan-out reaches every config under the CA. The host is
  cut off from each peer that redeploys before it fetches its own new config.
- **Retired** when the re-issue was routine: the renewal cron and CA rotation.
  It keeps working, so a host that has not fetched yet stays on the mesh, and
  rotation still needs no cut-over. It is listed only once the host is
  deactivated, because the device may still hold it.

Kept as `revoked_certificates` and `retired_certificates` on the host, as PEM.
A certificate whose CA has left the bundle is never listed, since no host can
verify it, so a finished CA rotation empties the list of everything the old CA
signed. That is the remedy if the list grows toward the 50000-byte
`config_yaml` cap (about 75 bytes an entry); pb-nebula warns past 400 entries.

### Deactivate to revoke — do not delete

A deleted host record takes its certificate with it, and a fingerprint that is
not in the database cannot be blocklisted. **Deleting a host leaves its
certificate valid until it expires.** Deletion is for hosts you are content to
leave trusted.

### An inactive host is never re-signed

An inactive host is revoked, so a certificate issued to it would be revoked from
the start, and one more fingerprint in every peer config. Nothing re-signs an
inactive host:

- **`renew = true` is refused** with an error wrapping `ErrHostInactive` (a 400
  through the record API, with the reason in the message). Reactivate the host
  instead: reactivation issues a new certificate by itself.
- **Certificate-field edits are kept but not signed.** Renaming a decommissioned
  host or freeing its `overlay_ip` is legitimate, so `hostname`, `overlay_ip`,
  `groups`, `unsafe_networks` and `validity_years` still save; the certificate
  stays as it was, and reactivation re-issues from the record as it then stands.
  This includes a single save that deactivates a host *and* edits one of those
  fields: the certificate revoked is the one the device holds.
- The renewal cron and the CA rotation sweep skip inactive hosts.

### The config is not the delivery

Regenerating `config_yaml` updates the database; it does not push anything to a
device. Revocation takes effect when each peer's config is redeployed and the
process reloads — `SIGHUP` is enough, no restart required. So "revoked" here
means "revoked in the material pb-nebula hands out", not "already off the mesh".
Plan for that gap: a network whose configs are never redeployed has no
revocation at all.

### A host is born active

PocketBase bools have no schema-level default, so a create that omits `active`
lands as `false` — and every host minted through the API omits it. pb-nebula
forces `active = true` on create, because otherwise a freshly issued certificate
would be blocklisted by every peer from the moment it was signed. It is forced
rather than defaulted-if-absent because by the time a hook sees the record,
"field omitted" and "explicitly false" are indistinguishable; creating an
already-revoked host is not a meaningful operation, and deactivation is an
update.

## Preferred Ranges

`preferred_ranges` tells a host which **underlay** prefixes to favour when a peer
advertises several addresses — typically the LAN it sits on, so two hosts in one
rack use their private addresses rather than the public ones a lighthouse
learned for them.

```json
{
  "preferred_ranges": ["10.0.0.0/8", "192.168.0.0/16"]
}
```

It is a **host** field, not a network one, because it describes where the host
physically sits rather than which overlay it belongs to — two hosts in one
network can be in different datacenters, and two hosts in different networks can
share a rack. Config-only: changing it re-renders that host's `config_yaml` and
nothing else.

Validation rejects unparseable CIDRs, host bits (`172.16.0.5/24` — you meant
`172.16.0.0/24`), duplicates, and more than 16 entries. That matters because
Nebula's own failure mode is silence: it parses each entry and, on error, logs a
warning and skips it, so a typo costs the host its preference while the tunnel
still forms over the public path.

**IPv6 is accepted here even though pb-nebula's overlay is IPv4-only** — these
are underlay prefixes, and Nebula ranks IPv6 addresses in `preferred_ranges`
highest of all. Overlapping entries are allowed: Nebula matches an address
against the set, so a broad range plus a narrower one inside it is coherent.

Omitted from the config entirely when unset.

## Lighthouse Addresses

Nebula's `static_host_map` maps an overlay IP to a **list** of underlay
endpoints, and tries them. `public_host_port` is the primary; `additional_host_ports`
carries any others.

```json
{
  "public_host_port": "198.51.100.10:4242",
  "additional_host_ports": ["[2001:db8::10]:4242", "192.168.10.5:4242"]
}
```

Every peer in the network then gets:

```yaml
static_host_map:
  10.128.0.1:
    - 198.51.100.10:4242
    - '[2001:db8::10]:4242'
    - 192.168.10.5:4242
```

Three ordinary deployments need this and none of them fit in a single value:

- **dual-stack** — the lighthouse has a v4 and a v6 address
- **two internet paths** — two uplinks, two public addresses
- **split horizon** — peers in the lighthouse's own rack should bootstrap via
  its LAN address, roaming peers via the public one

The order is yours and is not sorted: `public_host_port` leads, then
`additional_host_ports` as stored.

`listen.port` still comes from `public_host_port` alone — a host listens on one
port, and the extra entries name other *addresses* it is reachable at.

Every entry is validated like `public_host_port` (host:port, IPv6 bracketed, a
port in 1–65535, no duplicates). **Port `0` is refused here**: a peer has to
dial the value as written.

**Only a lighthouse's list reaches anyone else.** A relay's endpoint is learned
through the lighthouse at runtime and is never embedded in a peer config, so
extra addresses on a relay are stored and unused.

Changing either column fans out to every host in the network, because every one
of them carries the list.

## Advertising and Filtering a Host's Own Addresses

These two are the complement of `static_host_map`, not a duplicate of it, and
**behind NAT both are needed**:

- `static_host_map` is the **bootstrap** path. It lives in every *other* host's
  config and is how a peer finds this one before any handshake.
- `advertise_addrs` and `local_allow_list` are what this host **reports about
  itself** once it is talking to a lighthouse.

Both apply to **any** host, not only a lighthouse, and both are config-only:
changing one re-renders that host's `config_yaml` and nothing else.

### `advertise_addrs`

Routable addresses to report to the lighthouses, added to the ones Nebula
discovers on its own interfaces.

```json
{
  "advertise_addrs": ["198.51.100.10:4242", "203.0.113.7:0"]
}
```

The case this exists for is **cloud 1:1 NAT**: a host in AWS or GCP sees only
its private `10.x` address on the wire, so that is the address it reports to
every peer that queries — while `static_host_map` is simultaneously, and
correctly, pointing those peers at the public one.

Format is `"ip:port"`, and **a port of `0` means "use the real listening
port"**, which is what makes this usable on a host with `listen.port: 0`. That
is the one rule where it differs from `additional_host_ports`.

A DNS name is accepted, but **its failure mode here is the opposite of
`public_host_port`'s, so prefer an IP literal.** In `static_host_map` Nebula
resolves a name in a background goroutine and re-resolves on a cadence, so a
lookup failure is logged and the entry simply does not work yet. Here it
resolves **synchronously at startup**, and both a lookup error and an empty
result stop Nebula starting — there is no retry. An unresolvable name costs a
`static_host_map` entry its usefulness and costs an `advertise_addrs` host its
next reboot. Only the first address returned is used, so a name with several A
records silently advertises one of them.

It is accepted rather than refused because this validation is offline: it
cannot tell a name that will resolve at the edge from one that will not, and
refusing a shape Nebula accepts on the strength of a condition pb-nebula cannot
evaluate would be a guess rather than a check.

Entries are validated rather than merely warned about, because **Nebula refuses
to start** on one it cannot parse — a typo costs the host its next restart, not
just an optimisation.

### `local_allow_list`

Filters which of this host's **own** interface addresses it advertises. Nebula's
default is all of them, which on a containerised host means `docker0` at
`172.17.0.1`, every VM bridge, and any other tun device. Peers then attempt
handshakes against those and wait out a timeout each, so the symptom is slow
tunnel establishment rather than anything that logs as an error.

```json
{
  "local_allow_list": {
    "interfaces": { "tun0": false, "docker.*": false },
    "172.17.0.0/16": false
  }
}
```

The structure is Nebula's own and is rendered verbatim: an optional `interfaces`
sub-map of regular-expression-to-bool matched against interface *names*, plus
CIDR-to-bool entries matched against addresses. Interface patterns are anchored
by Nebula (`docker.*` becomes `^docker.*$`).

Validation restates Nebula's acceptance rules, because Nebula **refuses to
start** on a list it cannot make sense of rather than skipping the bad entry:

- every value is a bool, and every key that is not `interfaces` is a CIDR
- the interface rules must all be `true` or all be `false`
- if the CIDR rules of one address family mix `true` and `false`, that family
  needs an explicit default — `0.0.0.0/0` for v4, `::/0` for v6

That last one surprises people. Nebula infers the default as the *inverse* of
the rules when they agree and refuses outright when they do not, so blocking
`172.17.0.0/16` alone is fine and allowing `10.0.0.0/8` alone is fine, but doing
both at once without a default is a startup error. The two families are judged
independently.

Host bits are allowed here, unlike `preferred_ranges` — `172.17.0.1/32` is an
ordinary single-address rule.

`remote_allow_list`, the inverse filter controlling which remote addresses this
node will handshake *to*, is not supported yet.

Both are omitted from the config entirely when unset.

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

    // Host certificate renewal (background job, serve only)
    DisableHostCertRenewal bool    // Default: false (renewal is ON)
    HostRenewalThreshold   float64 // Default: 0.20 — renew once 80% of the lifetime is gone
    HostRenewalCron        string  // Default: "0 3 * * *"

    // CA expiry warning (log only; never gated by DisableHostCertRenewal)
    CAExpiryWarningDays int // Default: 90

    // Optional event filter
    EventFilter func(collectionName, eventType string) bool

    // Optional at-rest encryption key (32 chars). Empty = disabled.
    EncryptionKey string
}
```

`CAExpiryWarningDays` is separate from renewal on purpose. A host certificate
can be renewed; a CA cannot — the only remedy is rotation, which is a
three-step operator procedure with a deliberate wait in the middle. Nebula's
rotation guide asks you to start two to three months out, so the warning has to
arrive with room for the wait, not just room for the work. Turning automatic
host renewal off is a reason to want *more* warning about an expiring CA, which
is why `DisableHostCertRenewal` does not silence it.

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

### HostCertNetworkIsStale

```go
func HostCertNetworkIsStale(certPEM, overlayIP, networkCIDR string) (bool, error)
```

Reports whether a host's certificate still carries a network that no longer
matches the overlay it belongs to — the predicate behind the `/32` audit, so a
console can badge the affected hosts and offer the fix beside them instead of
leaving it in a server log.

The comparison is exact rather than mask-only, so an edited `overlay_ip` counts
as stale too. An empty `certPEM` returns `false` (a host mid-creation is not yet
wrong). Skip inactive hosts: they are revoked, and re-signing one would publish
a new fingerprint while the old certificate stayed valid.

Fix a `true` by setting `renew = true` on the host record. Do not sweep a fleet
with it unprompted — re-signing moves fingerprints, which rewrites every peer
config in the network.

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

### Nebula says "private key is not a pair with public key in nebula cert"

**Problem:** A host issued by pb-nebula v0.5.0 or earlier will not start.

**Cause:** Those versions generated an Ed25519 key pair for each host and wrote
the seed as its X25519 private key. Nebula checks the pair before it starts,
and that pair never matched, so no host issued by those versions could run.

**Solution:** Upgrade. The renewal sweep re-issues every **active** host whose
key does not pair with its certificate the next time it runs (daily at 03:00 by
default), even a young certificate, because a host that cannot start has
nothing to lose from a new fingerprint. To fix a host at once, set
`renew = true` on it. With `DisableHostCertRenewal` set, `renew` is the only
way. An inactive host is not re-issued: reactivating it issues a new pair.

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

5. **Decommission by Deactivating**
   - Set `active = false` — do not delete the host record
   - A deleted certificate cannot be fingerprinted, so it stays trusted until it expires
   - Redeploy peer configs (`SIGHUP` is enough) for the revocation to take effect
   - See [Certificate Revocation](#certificate-revocation)

6. **Network Isolation**
   - Use separate networks for different security zones
   - Apply firewall rules based on certificate groups
   - Follow principle of least privilege

## License

MIT License - See LICENSE file for details
