# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`pb-nebula` is a **Go library**, not a standalone application. It's imported into a PocketBase app (via `pbnebula.Setup(app, options)`) and layers three collections plus event hooks onto PocketBase to turn it into a Nebula mesh VPN certificate authority and host configuration manager. All crypto is delegated to `github.com/slackhq/nebula/cert` — this codebase does not reimplement Nebula primitives.

## Build / run

The library itself has no main. The `examples/basic` app is the driver used during development:

```bash
go mod download
go build ./...                      # compile-check everything
go vet ./...                        # static checks
go build -o basic ./examples/basic  # build the example server
./basic serve                       # run PocketBase with pb-nebula on :8090
```

Admin UI at `http://127.0.0.1:8090/_/`. Data is written to `./pb_data` by default (see `examples/basic/main.go:163` `init()` — it sets `PB_DATA_DIR` if unset).

`go test ./...` runs the test suite — the pure packages (`internal/cert`, `internal/ipam`, `internal/config`, `internal/types`, root options) are covered; hook behavior in `internal/sync` is not (needs a live PocketBase app). `gofmt -l .` should print nothing before committing.

## Architecture

### Initialization order matters
`Setup()` (nebula.go:77) registers a single `OnBootstrap` hook. On bootstrap, `initializeComponents()` wires everything in this fixed order because later components depend on earlier ones:

1. **collections.Manager** — creates `nebula_ca`, `nebula_networks`, `nebula_hosts` (must run first; other components query these by name).
2. **cert.Manager** — stateless wrapper over `slackhq/nebula/cert` for CA + host cert generation.
3. **config.Generator** — stateless; renders Nebula YAML.
4. **ipam.Manager** — needs the app handle to look up networks for CIDR/IP validation.
5. **sync.Manager** — owns all the PocketBase record hooks and orchestrates the other four.

Do not reorder or move initialization out of the `OnBootstrap` callback — collections must exist in the DB before hooks that reference them fire.

### The three collections
- `nebula_ca` — base collection, admin-only, `private_key` is `Hidden: true` (not exposed via API). Unique index on `name`. **Multiple CAs are supported** — each CA roots its own independent mesh and can serve multiple networks.
- `nebula_networks` — base collection. Unique per CA: composite indexes on `(ca_id, name)` and `(ca_id, cidr_range)`. The `ca_id` relation is added in a **second save** after the collection exists, because PocketBase relation fields need a target collection ID. If you add a new relation field, follow this same two-phase pattern (see `createNetworksCollection` and `createHostsCollection`).
- `nebula_hosts` — **auth collection** (PocketBase email/password). Access rules are self-service (`@request.auth.id = id`). Unique per network: composite indexes on `(network_id, overlay_ip)` and `(network_id, hostname)`.

Index changes only apply to fresh databases — `InitializeCollections` is idempotent and never alters an existing collection's schema. Existing deployments need manual index migration.

### Tiered regeneration (do not break this)
The update hook in `internal/sync/manager.go` (`setupHostHooks`) distinguishes what *has* to be regenerated:

- **Cert regeneration (expensive)** when `hostname`, `overlay_ip`, `groups`, or `validity_years` change — these are embedded in the certificate.
- **Config-only regeneration (cheap)** when `is_lighthouse`, `public_host_port`, `firewall_outbound`, or `firewall_inbound` change — these are config-only.
- **Peer fan-out** (`regenerateNetworkHostConfigs`) when a lighthouse-relevant field changes on a host that is or was a lighthouse (`is_lighthouse`, `active`, `public_host_port`, `overlay_ip`) — peers embed lighthouse data in their `static_host_map`/`lighthouse` sections. Fan-out also fires on active-lighthouse create and delete, and on network `cidr_range` change.
- **`active` on ANY host** — lighthouse or not — triggers both the peer fan-out *and* that host's own config regeneration. Deactivating a host revokes its certificate, and Nebula revocation lives in every OTHER host's `pki.blocklist` (see **Revocation** below), so an active flip makes every config in the network stale. The host's own config is regenerated separately because the fan-out deliberately excludes the record that changed.
- **No regeneration** for `email`, `password`, or anything else.

If you add a new host field, decide which tier it belongs in and update the diff logic in `setupHostHooks`. Otherwise the field will silently never trigger regeneration, or will trigger an expensive cert regen it doesn't need.

### Revocation is a fan-out, not a record

**Nebula has no CRL and no OCSP.** The only way to refuse a certificate the CA already signed is `pki.blocklist`: a list of certificate fingerprints carried by every *other* host, loaded into the CA pool at startup and again on SIGHUP (`nebula/pki.go`, `loadCAPoolFromConfig` / `reloadCAPool`). Revocation is therefore a property of the whole network that every member config has to restate — the opposite shape from NATS, where a revocation list lives inside the signed account JWT and one write reaches every server.

Consequences worth keeping:

- `getBlocklist(networkID)` (`internal/sync/manager.go`) returns the fingerprints of every host in the network with `active = false`, **sorted** — unsorted, map iteration order would make every regeneration look like a change.
- The fingerprint is **derived from the stored certificate** (`cert.FingerprintFromPEM`), not cached in a column. `InitializeCollections` never alters an existing collection's schema, so a new field would be silently absent on every deployment that already exists.
- An empty blocklist is **omitted** from the config rather than written as an empty list, so a network with nothing revoked renders exactly the config it did before this feature.
- A failure to build the blocklist is **logged, never fatal**. A config without a blocklist is the config this library generated for years; failing would stop a host getting any config at all.

**A host is born active.** PocketBase bools have no schema-level default, so a create that omits `active` lands as false -- and every host minted through the API omits it. That was nearly harmless while `active` only gated `getLighthouses`; it stopped being harmless once `active` drove `pki.blocklist`, because a freshly issued certificate would be blocklisted by every peer from the moment it was created. `setupHostHooks` therefore forces `active = true` on create. It is forced rather than defaulted-if-absent because by the time a hook sees the record, "field omitted" and "explicitly false" are indistinguishable; creating an already-revoked host is not a meaningful operation, and deactivation is an update.

**Deactivate to revoke; do not delete.** A deleted host record takes its certificate with it, and a fingerprint that is not in the database cannot be blocklisted — so deleting a host leaves its certificate valid until it expires. Deletion is for hosts you are content to leave trusted.

**The config is not the delivery.** Regenerating `config_yaml` updates the database; it does not push anything to a device. Revocation takes effect when each peer's config is redeployed and the process reloads. That boundary is deliberate and matches the NATS side, where the platform mints a credential and does not care what connects with it — but it means "revoked" here means "revoked in the material we hand out", not "already off the mesh".

`internal/config/blocklist_honoured_test.go` is the test that earns this: it reproduces `loadCAPoolFromConfig` with Nebula's own `cert` package and asserts the blocklisted certificate actually fails `VerifyCertificate`, paired with one that still passes. A YAML assertion cannot catch a fingerprint computed the wrong way — Nebula compares the string opaquely, so a wrong-but-plausible hex value blocks nothing and reports no error.

### Recursion prevention (saveInternal — do not bypass)
Saves issued by pb-nebula itself re-fire the update hooks, and `e.Record.Original()` inside a re-fired hook still holds the **pre-request** snapshot — so any field-diff that triggered once would trigger again, looping forever (this exact loop shipped in the pre-`saveInternal` code: changing `public_host_port` regenerated ~37k times until killed). All internal writes go through `sm.saveInternal(record)`, which marks the record ID in `internalSaves`; the host update hook skips marked events via `isInternalSave`. If you add a hook that saves records, use `saveInternal`, never `sm.app.Save` directly. The older "certificate empty → populated" guard is kept as defense in depth for the creation flow (commits `f9823fb`, `1780bff`).

### Firewall rules are host-based, not network-based
This mirrors Nebula's own design. `nebula_networks` has no firewall fields. Every host carries `firewall_outbound` and `firewall_inbound` as JSON arrays in Nebula's native format. The config generator (`internal/config/generator.go`) applies Nebula-recommended defaults (allow-all outbound, ICMP-only inbound) when a host's rules are empty.

### Host cert expiration is clamped
`cert.Manager.GenerateHostCert` caps host cert `NotAfter` at the **parsed CA certificate's own `NotAfter`** — not the `expires_at` value stored in the DB. Cert timestamps have whole-second precision; a stored timestamp with sub-second precision can land fractionally after the real `NotAfter`, and `nebula/cert` then rejects the signing ("certificate expires after signing certificate"). Don't remove the clamp and don't reintroduce an external expiry source — `TestGenerateHostCertClampsToCAExpiry` guards this.

### Options defaults
`DefaultOptions()` → `applyDefaultOptions()` → `validateOptions()`. `applyDefaultOptions` only fills zero/empty values, so partial `Options` structs work. `validateOptions` enforces that collection names are unique and `DefaultHostValidityYears <= DefaultCAValidityYears`.

### Optional at-rest encryption
`Options.EncryptionKey` (32 chars, validated at setup) turns on AES-256-GCM encryption for the CA `private_key` and host `private_key` columns. Helpers live in `internal/types/encryption.go`:

- `EncryptField` / `DecryptField` use an `enc::` prefix; values without the prefix pass through, so unencrypted records continue to work after the flag is enabled (backward-compat).
- `EncryptAndSet(record, field, value, key)` is the standard write path.

Call sites in `internal/sync/manager.go`:

- `generateCA` encrypts before writing.
- `generateHostCertAndConfig` decrypts the CA private key before signing, sets host private_key as **plaintext** temporarily so `generateHostConfig` can embed it into `config_yaml`, then encrypts the column at the end.
- `recordToHostModel` decrypts defensively. Call this anywhere you need a usable plaintext key from a record.

**Known limitation (call out to users):** `config_yaml` contains the host's private key inline because Nebula's PKI block requires it. That field is plaintext at rest — encryption only protects the standalone column. This mirrors how pb-nats handles `creds_file`.

If you add a new sensitive field, route writes through `EncryptAndSet` and reads through `DecryptField`. Don't bypass — silent plaintext leaks are the failure mode.

### EventFilter escape hatch
`Options.EventFilter func(collectionName, eventType string) bool` lets callers suppress specific regeneration events (e.g., skip `network_update` fan-out). Event type constants are in `internal/types/types.go` and re-exported paths go through `nebula.go`'s imports. When adding a new event, add the constant in `types` and consult `EventFilter` at the appropriate hook site.

## Conventions worth matching

- Every package has a doc comment on the `package` line and on each exported type/function. Existing comments are verbose (multi-section: DESIGN, PARAMETERS, RETURNS, SIDE EFFECTS). New code in the same files should match the surrounding style; greenfield packages may use briefer docs.
- Errors are wrapped with `fmt.Errorf("...: %w", err)` or `WrapError`/`WrapErrorf` from `errors.go`. Sentinel errors live in `internal/types/errors.go` (so internal packages can wrap them without an import cycle) and are re-exported from the root `errors.go` for `errors.Is` matching by consumers. Wrap the matching sentinel at validation/lookup/generation sites.
- Logging goes through `internal/utils/logger.go`. Methods like `logger.Cert(...)`, `logger.Config(...)`, `logger.Success(...)` produce the emoji-prefixed output described in the README. Don't bypass with `fmt.Println`.
- The codebase uses the phrase "grug-brained" as shorthand for "keep it simple, no clever optimizations." When a change starts feeling clever, reconsider.
