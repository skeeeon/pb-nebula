# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`pb-nebula` is a **Go library**, not a standalone application. It's imported into a PocketBase app (via `pbnebula.Setup(app, options)`) and layers three collections plus event hooks onto PocketBase to turn it into a Nebula mesh VPN certificate authority and host configuration manager. All crypto is delegated to `github.com/slackhq/nebula/cert` — this codebase does not reimplement Nebula primitives.

Certificates are issued at **version 2**, matching the current default of `nebula-cert ca`, so **every host on the mesh needs Nebula v1.10+** — older builds cannot validate a v2 certificate and simply never handshake. Don't drop to v1 to widen compatibility without deciding that deliberately: v2 is what carries multiple networks and IPv6.

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

`go test ./...` runs the test suite — the pure packages (`internal/cert`, `internal/ipam`, `internal/config`, `internal/types`, root options) are covered; hook behavior in `internal/sync` is not (needs a live PocketBase app), so **tier and fan-out changes have to be verified by hand against `examples/basic`**. That gap is not theoretical: a missing config-only tier entry for `is_relay` was caught only by driving the running app.

DB-backed validators keep their rules in a pure unexported half (`validateUnsafeNetworks`, `validateUnsafeRoutes`) with the exported method doing only the record lookup, so the rules stay testable.

`gofmt -l .` should print nothing before committing — but on a Windows checkout with `core.autocrlf=true` it flags **every** file, because the working tree is CRLF while gofmt wants LF. Git normalizes on commit, so the repo is fine; to actually check formatting there, copy the tree through `tr -d '\r'` and run `gofmt -l` on the copy. Note also that gofmt rewrites multi-line `// -` doc bullets into `//   - ` form; the codebase uses single-line bullets with prose underneath, so keep bullets to one line.

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

**Fields migrate; indexes do not.** `InitializeCollections` is idempotent: it creates a collection that does not exist, and for one that does it *adds any declared field it is missing* (`addMissingFields`). It never removes, retypes, or narrows an existing field, and it never touches indexes or access rules.

The declaration is therefore shared — `caFields()`, `networkFields()` and `hostFields()` are read by both the create path and the migration, so a field added to one of them cannot reach a fresh database and miss an existing one. **Add new fields there, not inline in `create*Collection`.** Relation fields (`ca_id`, `network_id`) are the exception: they need their target collection's ID resolved at runtime, stay in the two-phase create path, and are excluded from the migration because they exist on every deployment that has the collection at all.

Index changes still only apply to fresh databases and need manual migration on existing deployments. Adding a column is safe on a populated table; adding a UNIQUE index to one with violating rows fails the save and takes the rest of initialization with it.

Fields whose zero value means "inherit the default" (`mtu`, `tun_device`) rely on PocketBase short-circuiting validation on `0` / `""` before checking `Min` / `Pattern`, so the bounds can be declared without a special case.

### Tiered regeneration (do not break this)
The update hook in `internal/sync/manager.go` (`setupHostHooks`) distinguishes what *has* to be regenerated:

- **Cert regeneration (expensive)** when `hostname`, `overlay_ip`, `groups`, `unsafe_networks`, or `validity_years` change — these are embedded in the certificate.
- **Config-only regeneration (cheap)** when `is_lighthouse`, `is_relay`, `public_host_port`, `firewall_outbound`, `firewall_inbound`, `mtu`, `tun_device`, or `unsafe_routes` change — these are config-only.
- **Peer fan-out** (`regenerateNetworkHostConfigs`) when a lighthouse-relevant field changes on a host that is or was a lighthouse (`is_lighthouse`, `active`, `public_host_port`, `overlay_ip`) — peers embed lighthouse data in their `static_host_map`/`lighthouse` sections. The same applies to relays (`is_relay`, `active`, `overlay_ip` — but *not* `public_host_port`, since peers carry only a relay's overlay IP, not its endpoint). Fan-out also fires on active lighthouse/relay create and delete, and on network `cidr_range` change.

  **A fan-out field almost always needs a config-only entry too.** `regenerateNetworkHostConfigs` deliberately excludes the record that changed, so a field that only appears in the fan-out list updates every host *except* the one that was edited. This shipped briefly for `is_relay`: clearing the flag left `am_relay: true` in the host's own config, so it kept relaying for peers that had already dropped it.
- **`active` on ANY host** — lighthouse or not — triggers both the peer fan-out *and* that host's own config regeneration. Deactivating a host revokes its certificate, and Nebula revocation lives in every OTHER host's `pki.blocklist` (see **Revocation** below), so an active flip makes every config in the network stale. The host's own config is regenerated separately because the fan-out deliberately excludes the record that changed.
- **`renew` (action field)** forces a cert regeneration regardless of remaining lifetime, then resets itself. See **Renewal** below.
- **Reactivation** (`active` false→true) forces a cert regeneration — a host parked across a CA rotation is never re-signed by the commit sweep, so it comes back on a CA that may have been retired. See **CA rotation** below.
- **No regeneration** for `email`, `password`, or anything else.

If you add a new host field, decide which tier it belongs in and **add it to `certFields` or `configFields`** at the top of `internal/sync/manager.go`. `changedFields` diffs a tier through `GetString`, which renders bools and numbers uniformly, so the tables are the whole edit — there is no matching `if` to write. `TestTiersAreDisjointAndComplete` keeps a second copy of the membership and fails when it drifts, so a field cannot be half-added. Otherwise the field will silently never trigger regeneration, or will trigger an expensive cert regen it doesn't need.

`validity_years` stays out of the tables on purpose: clearing it to `0` means "use the configured default", which is a request to keep the current lifetime rather than to re-issue. `renew`, `active` and the fan-out rules stay explicit too — each is a transition or a condition, not a plain diff.

### Revocation is a fan-out, not a record

**Nebula has no CRL and no OCSP.** The only way to refuse a certificate the CA already signed is `pki.blocklist`: a list of certificate fingerprints carried by every *other* host, loaded into the CA pool at startup and again on SIGHUP (`nebula/pki.go`, `loadCAPoolFromConfig` / `reloadCAPool`). Revocation is therefore a property of the whole network that every member config has to restate — the opposite shape from NATS, where a revocation list lives inside the signed account JWT and one write reaches every server.

Consequences worth keeping:

- `getBlocklist(networkID)` (`internal/sync/manager.go`) returns the fingerprints of every host in the network with `active = false`, **sorted** — unsorted, map iteration order would make every regeneration look like a change.
- The fingerprint is **derived from the stored certificate** (`cert.FingerprintFromPEM`), not cached in a column. That was originally forced — `InitializeCollections` could not add a field to an existing deployment — but it is still the right shape now that it can: a cached fingerprint is a second copy of something the certificate already states, and the two can disagree after any re-issue. Derive, don't cache. (`rotation_state` is absent from `nebula_ca` for the same reason.)
- An empty blocklist is **omitted** from the config rather than written as an empty list, so a network with nothing revoked renders exactly the config it did before this feature.
- `pki.disconnect_invalid: true` is the **one Nebula default the generator restates** rather than omits, because it is the one that is not knowable: the docs say it defaults to `false`, `interface.go` defaults it to `true` in 1.10 and 1.11 alike, and upstream's own example config shows it commented as `true`. Revocation does not need it — a blocklisted certificate skips the check and disconnects regardless (`connection_manager.go`) — but an expired certificate and a finished CA rotation both do: without it a host still holding a certificate from the dropped CA keeps its established tunnels open indefinitely. Everything else that matches a Nebula default stays omitted (`use_relays`, the relay section, `static_host_map` on a lighthouse).
- A failure to build the blocklist is **logged, never fatal**. A config without a blocklist is the config this library generated for years; failing would stop a host getting any config at all.

**A host is born active.** PocketBase bools have no schema-level default, so a create that omits `active` lands as false -- and every host minted through the API omits it. That was nearly harmless while `active` only gated `getLighthouses`; it stopped being harmless once `active` drove `pki.blocklist`, because a freshly issued certificate would be blocklisted by every peer from the moment it was created. `setupHostHooks` therefore forces `active = true` on create. It is forced rather than defaulted-if-absent because by the time a hook sees the record, "field omitted" and "explicitly false" are indistinguishable; creating an already-revoked host is not a meaningful operation, and deactivation is an update.

**Deactivate to revoke; do not delete.** A deleted host record takes its certificate with it, and a fingerprint that is not in the database cannot be blocklisted — so deleting a host leaves its certificate valid until it expires. Deletion is for hosts you are content to leave trusted.

**The config is not the delivery.** Regenerating `config_yaml` updates the database; it does not push anything to a device. Revocation takes effect when each peer's config is redeployed and the process reloads. That boundary is deliberate and matches the NATS side, where the platform mints a credential and does not care what connects with it — but it means "revoked" here means "revoked in the material we hand out", not "already off the mesh".

`internal/config/blocklist_honoured_test.go` is the test that earns this: it reproduces `loadCAPoolFromConfig` with Nebula's own `cert` package and asserts the blocklisted certificate actually fails `VerifyCertificate`, paired with one that still passes. A YAML assertion cannot catch a fingerprint computed the wrong way — Nebula compares the string opaquely, so a wrong-but-plausible hex value blocks nothing and reports no error.

### Recursion prevention (saveInternal — do not bypass)
Saves issued by pb-nebula itself re-fire the update hooks, and `e.Record.Original()` inside a re-fired hook still holds the **pre-request** snapshot — so any field-diff that triggered once would trigger again, looping forever (this exact loop shipped in the pre-`saveInternal` code: changing `public_host_port` regenerated ~37k times until killed). All internal writes go through `sm.saveInternal(record)`, which marks the record ID in `internalSaves`; the host update hook skips marked events via `isInternalSave`. If you add a hook that saves records, use `saveInternal`, never `sm.app.Save` directly. The older "certificate empty → populated" guard is kept as defense in depth for the creation flow (commits `f9823fb`, `1780bff`).

### CA rotation takes three steps, and that is not negotiable

`internal/sync/rotation.go`. Driven by the `rotate` **text** action field on `nebula_ca`: `prepare` → `commit` → `finish`. Text rather than bool because there are three verbs and a stuck `true` is dangerous.

**Why three steps.** Nebula verification is **mutual** — each peer checks the other against its *own* local CA pool (`handshake_manager.go` builds the verifier as `pki.GetCAPool().VerifyCertificate`), with no chain and no fallback. Config distribution here is **pull-based**: a host reads `config_yaml` whenever it likes and nothing tells us when it did. So one write carrying both the new bundle *and* the new certificate splits the mesh — a host that fetched presents a new-CA cert to a host that hasn't, whose pool holds only the old CA, and the handshake fails in **both** directions until propagation finishes. Publishing trust first and switching issuance second removes the window. The wait between them is operator judgment and cannot be designed away, only made visible.

- **`prepare`** mints the incoming CA into `next_certificate`/`next_private_key` and fans out **config-only**. `certificate`, `private_key` and `expires_at` are untouched: issuance stays put, no host cert changes, no fingerprint moves, the blocklist is unaffected. Fully reversible.
- **`commit`** swaps the incoming CA in, then re-signs every **active** host. **Idempotent and resumable** — re-running it skips the swap and re-signs only hosts whose cert `Issuer()` still names the outgoing CA, so recovery from a partial sweep is the same verb, not a separate lever.
- **`finish`** drops the outgoing CA, and **refuses while any active host is still on it** (`assertAllHostsMigrated`). That interlock is what makes `finish` safe to expose: dropping the old CA early takes a host off the mesh silently.

**Rotation state is derived, never stored.** `next_certificate` set → prepared; `previous_certificate` set → rotated; neither → idle. A status column could only disagree with the certificates that already say this — same rule as blocklist fingerprints.

**The bundle content is identical in both phases** — `[old, new]` either way (`caBundle`) — which is precisely what lets a host fetch at any instant from `prepare` onward and still talk to every peer. It is read from the **CA record** on every generation, not denormalized onto hosts, which makes rotation self-healing: any regeneration hands out the current bundle, so `finish` and partial recovery need no re-signing. `host.ca_certificate` stays a single certificate.

**Inactive hosts are never re-signed.** Their fingerprint is in every peer's blocklist; re-signing would change it, so `getBlocklist` would publish the new one while the old cert stayed valid under the still-trusted outgoing CA — silently un-revoking it. Verified live across two rotations: the revoked host's fingerprint survived unchanged.

**So reactivation must force a cert regeneration**, and that is why the `active` false→true branch sets `needsCertRegeneration`. A host parked across a rotation comes back holding a certificate from a CA that may since have been retired — off the blocklist, healthy-looking in the Admin UI, able to handshake with nobody.

**Rotation guards return `router.NewBadRequestError`, not a plain error.** PocketBase flattens a plain error from a request hook into a generic "Something went wrong" 400, which discards the only thing that makes these messages worth writing — `finish` names the host that is blocking it. Validation lives in the **request** hook (can refuse) and execution in **AfterUpdateSuccess** (cannot), keyed on the `rotate` *transition* so a crash between commit and hook doesn't re-fire on the next unrelated edit. The After hook checks `isInternalSave` first: the CA *create* hook calls `saveInternal`, which fires an update event, and without that guard creating a CA would enter the rotation path.

### Renewal is a cron, and the clamp is what makes it tricky

`internal/sync/renewal.go` re-issues host certificates that have burned through `HostRenewalThreshold` (default 0.20, i.e. renew once 80% of the lifetime is gone). Registered in `SetupCron` during `OnBootstrap`; PocketBase starts the cron on `OnServe`, so the job is scheduled in time **and only ever runs under `serve`** — no CLI invocation quietly re-issues certificates.

`shouldRenew` is pure and takes `now` as a parameter, so tests advance the clock instead of sleeping and the whole sweep evaluates every host against one instant.

**The clamp trap.** `GenerateHostCert` clamps `NotAfter` to the CA's own `NotAfter`. Once the CA's expiry is the binding constraint, a re-issued certificate carries the *same* `NotAfter` as the one it replaced — so it is still past the threshold and the host gets re-signed on **every sweep until the CA expires**. That is a nightly fingerprint change plus a full config fan-out, arriving exactly when the CA needs calm attention. `hostCertNeedsRenewal` therefore refuses to renew when `notAfter` is not before the CA's, and warns naming the real fix: rotate the CA. Verified — a clamped host warns on every tick and is never re-signed.

**Only active hosts are renewed.** An inactive host is revoked; re-issuing it changes its fingerprint, so `getBlocklist` would publish the new one while the old certificate stayed valid and unblocklisted. Renewing a revoked host would un-revoke it. The CA rotation sweep skips them for the same reason.

**A CA gets its own warning, and renewal cannot silence it.** `WarnOnExpiringCAs` (`internal/sync/ca_expiry.go`) runs at bootstrap and on its own cron (`30 3 * * *`, registered *before* the `DisableHostCertRenewal` early return), warning `CAExpiryWarningDays` (default 90) ahead of a CA's `NotAfter`. A host certificate is renewable; a CA is not — the only remedy is rotation, which needs a wait in the middle that nothing can compress, which is why Nebula's guide asks for two to three months' notice. The clamp warning in `hostCertNeedsRenewal` is not a substitute: it fires only for hosts already past their own threshold and reports a symptom rather than the deadline. `classifyCAExpiry` is pure with `now` injected, like `shouldRenew`, and truncates days rather than rounding so a countdown never promises time the operator does not have. It deliberately does *not* warn about a half-finished rotation — a CA sitting in `prepared` is the documented procedure, and nothing here can tell that apart from neglect.

`DisableHostCertRenewal` is named negatively on purpose: `applyDefaultOptions` only fills zero values, so a bool defaulting to *true* is indistinguishable from unset (same reason `LogToConsole` is not defaulted). The zero value means renewal is on, which is the safe direction — a mesh that silently expires is worse than one that re-issues.

`renew` is an **action field**: set it true and the update hook re-issues immediately and resets it to false in the same save. Keyed on the false→true transition, and reset even when the event filter suppressed the work, so it can never stay pending. Same shape the CA rotation verbs use — a manual lever that needs no Go API and no HTTP route, so the platform drives it through the PocketBase client it already has.

### Gateway routing is two halves on two different hosts

`unsafe_networks` and `unsafe_routes` are the **provider** and **consumer** halves of the same feature, they live on *different* hosts, and neither derives the other. Both are required for traffic to flow.

- `unsafe_networks` (on the gateway) is signed **into the certificate**. Nebula authorizes routing on the certificate, not on config — a gateway whose cert omits the prefix silently refuses to route it, and the packet is dropped before any firewall rule runs. This is why it sits in the **cert regeneration** tier: editing it is completely inert until a new certificate is issued.
- `unsafe_routes` (on every host that wants to reach that subnet) is plain config: `[{route, via}]`, where `via` is the gateway's overlay IP. Config-only tier, **no fan-out** — no peer embeds another host's routes.

**Routes are not auto-derived, deliberately.** Two gateways can legitimately advertise the same prefix (two branch offices both on `192.168.1.0/24` is the common case), and inference would emit two entries for one route with different `via` values for Nebula to pick between arbitrarily. It would also push a prefix over the mesh for a host already sitting on that LAN.

What compensates for that is validation, in `internal/ipam`: host bits rejected, duplicates and overlaps rejected, and **overlap with the network's own CIDR rejected** — an unsafe network inside the overlay shadows real mesh peers, because Nebula builds one routing table from the certificate's networks and unsafe networks together. `via` must be an overlay IP inside the network, since a typo there is otherwise inert.

The cross-host half is a **warning, never a rejection** (`warnOnUnroutableUnsafeRoutes`). A route may legitimately be added before the gateway's certificate is updated, so rejecting would force an ordering — but staying silent leaves the operator with the failure this exists to surface: Nebula drops the packet with no log line, which reads like a peer or LAN outage rather than a config error.

### Relays are config-only; lighthouses are not the same shape

`is_relay` is pure config — nothing about relaying reaches the certificate, so toggling it never triggers a cert regeneration. That is the whole difference from a cert-bound field like `groups`.

`config.buildRelayConfig` emits `am_relay: true` for a relay and `relays: [...]` for everyone else, and **omits the section entirely** when a network has no relays, so existing deployments see no diff. It never emits `use_relays`: Nebula defaults it to true and forces `useRelays = use_relays && !amRelay` (`relay_manager.go`), and ignores `relay.relays` outright when `am_relay` is set (`lighthouse.go`) — so a relay can never route through another relay no matter what we write. Emitting only `am_relay` states that directly instead of restating Nebula's defaults in every config.

Relays are **not** added to `static_host_map` — unlike a lighthouse, a relay's address is learned through the lighthouse at runtime. But a relay does need `public_host_port`, because `extractPort` would otherwise give it `listen.port: 0` (ephemeral) while every peer is handed its overlay IP as a usable path. `validateHostRecord` rejects a relay without one rather than letting that fail silently.

### Firewall rules are host-based, not network-based
This mirrors Nebula's own design. `nebula_networks` has no firewall fields. Every host carries `firewall_outbound` and `firewall_inbound` as JSON arrays in Nebula's native format. The config generator (`internal/config/generator.go`) applies Nebula-recommended defaults (allow-all outbound, ICMP-only inbound) when a host's rules are empty.

### The host cert's network mask is the network's, never /32

`GenerateHostCert` signs the host address at the **overlay network's** mask (`10.128.0.5/24`), taken from `nebula_networks.cidr_range` and passed in as `HostCertParams.NetworkCIDR`. It is required — there is no fallback, because the fallback is what was wrong.

Nebula does not read a certificate's network as "this host's address". It reads the prefix straight onto the tun device: `pki.go` fills `myVpnNetworks` from `crt.Networks()`, `main.go` hands that to the device factory, and `overlay/tun_linux.go` adds the interface address with `net.CIDRMask(prefix.Bits(), …)` and installs a link-scope route for `prefix.Masked()`. **The mask in the certificate is the host's route to the overlay.**

pb-nebula signed `/32` until this was fixed, which gives a host a route covering only itself. Nothing errors — the certificate verifies, the config renders, the handshake completes — but the kernel never hands peer traffic to the tun, so no packet crosses the mesh. It also breaks `unsafe_routes`, since Nebula only accepts a gateway that `isGatewayInVpnNetworks` finds inside the overlay.

Every `nebula-cert sign` example upstream uses the overlay mask (`-networks "192.168.100.10/24"`), and Nebula's own e2e suite signs `10.128.0.1/24`. `TestGenerateHostCertCarriesTheOverlayNetworkMask` guards it, asserting both the mask and the `Contains` predicate the kernel route and Nebula both evaluate.

`overlayPrefix` also rejects an address outside its network. That duplicates an ipam check on the request path on purpose: the rotation and renewal sweeps re-sign records written long before, and never pass through request validation.

**Existing deployments carry `/32` certificates until each host is re-signed, and nothing re-signs them automatically.** `AuditHostCertNetworkMasks` (`internal/sync/audit.go`) warns — at bootstrap for every network, and from the network hook when `cidr_range` changes — naming each active host whose certificate no longer matches its network, and telling the operator to set `renew`. It never writes.

That restraint is the point. Re-signing moves a certificate's fingerprint, and a fingerprint is what `pki.blocklist` revokes, so a sweep that re-signed on its own would churn every fingerprint and every peer config in a fleet on the strength of a library upgrade. **Inactive hosts are excluded** for the usual reason: they are revoked, and re-signing one would publish a new fingerprint while the old certificate stayed valid. `cert.HostCertNetworkIsStale` is the predicate, compared exactly rather than mask-only so an edited `overlay_ip` counts too.

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
