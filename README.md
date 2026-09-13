# Herald

<p align="center">
  <a href="https://github.com/LatticeAG/herald/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/LatticeAG/herald?style=for-the-badge" alt="License" />
  </a>
  <a href="https://github.com/LatticeAG/herald">
    <img src="https://img.shields.io/badge/TypeScript-5.9%2B-blue?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" />
  </a>
  <a href="https://github.com/LatticeAG/herald">
    <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  </a>
  <a href="https://github.com/LatticeAG/herald">
    <img src="https://img.shields.io/badge/Node-22.5%2B-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node" />
  </a>
</p>

<p align="center">
  <b>The sovereign agent identity registry.</b><br/>
  DIDs. Signed Agent Cards. Human binding. Hash-chained revocation. Independently verifiable evidence.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#what-herald-is">What Herald is</a> ·
  <a href="#protocol">Protocol</a> ·
  <a href="#cli">CLI</a> ·
  <a href="#http-api">HTTP API</a> ·
  <a href="#verification">Verification</a> ·
  <a href="#repository-layout">Layout</a> ·
  <a href="#conformance">Conformance</a>
</p>

---

Herald is LatticeAG's sovereign agent identity registry. A Herald **root** issues `did:herald:<root>:<agent>` identities, binds each agent to a human principal under an explicit accountability consent, mints short-lived **Agent Cards**, and publishes a hash-chained audit log plus a privacy-preserving revocation bitmap. Gateways verify a card **offline** from a signed bundle — or **fresh** against the registry's challenge endpoint — without Herald learning which agent was checked.

The OSS core is fully self-hostable: `herald serve` runs a real registry on `node:http` + `node:sqlite`, and the Cloudflare Worker/Durable Object entry point deploys the same reducer at the edge. Nothing here phones home to LatticeAG.

Part of [LatticeAG](https://github.com/LatticeAG).

## What Herald is

- **DIDs + roots** — every identity is anchored to a root document signed by control, service, and registrar keys. Roots rotate (bounded 64-epoch history) and freeze (terminal, irrevocable).
- **Human binding** — an agent is always answerable to a `hp_` principal. Enrollments carry human + agent + registrar signatures; renewal replaces a binding without breaking card provenance.
- **Agent Cards** — short-lived (≤ 24 h), slot-indexed capabilities receipts with explicit `key_epoch`. Rotation requires old-key, new-key, and human signatures plus a `ROTATION` proof binding old and new card hashes.
- **Revocation that verifies** — status is a 131072-slot bitmap signed by the live service key; revocations flip bits inside the same hash chain. Freshness answers are bound to caller challenges and are never cached.
- **Independently verifiable evidence** — every mutation returns a signed receipt; the audit chain, receipts, and bundles all verify offline against a pinned genesis.
- **LexScope adapter** — `HeraldCheck → HeraldObservation` mapping for private gateway checks without changing the LexScope wire shape.

Herald is **not** a token-minting system, a delegation tree, a governance court, a market, a human-IAM product, or a hosted SaaS. Hosted roots, if they ever exist, add operation of those roots — not exclusive security semantics.

## Quick start

Node 22.5+ (built-in `node:sqlite` and TypeScript type-stripping). No runtime dependencies.

```bash
npm install
npm test                    # 60-vector conformance suite + schema coherence
```

```bash
# 1. keys (0600 files under a 0700 dir, exclusive create)
herald key generate --purpose service   --out .devin/herald/keys/svc.json
herald key generate --purpose control   --out .devin/herald/keys/ctl.json
herald key generate --purpose registrar --out .devin/herald/keys/reg.json

# 2. author + sign the genesis root document (control+service+registrar proofs)
herald sign --tag ROOT --body root.json --key-ref ctl --out r1.json
herald sign --tag ROOT --body root.json --key-ref svc --out r2.json
herald sign --tag ROOT --body root.json --key-ref reg --out r3.json
herald combine --signed r1.json --signed r2.json --signed r3.json \
  --roots r1.json --out genesis.json

# 3. bootstrap + serve
herald root init --document genesis.json --state .devin/herald/state
herald serve --port 8080
```

Then enroll a binding, issue a card, and verify it:

```bash
herald binding enroll --command enroll.json --json
herald card issue    --command issue.json  --json
herald status fetch  --root $R --out status.json --json
herald verify        --bundle bundle.json --status status.json --json
herald verify fresh  --bundle bundle.json --root $R --json
herald doctor        --root $R --json
```

`tests/smoke/mint.ts` mints a complete development playground (fixture keys, real-time commands) — see the [smoke section](#conformance).

## Protocol

| Concept | Wire |
| --- | --- |
| Encoding | Strict JSON (no BOM, fractions, exponents, or duplicate keys) + RFC 8785 canonicalization |
| Digests | Tagged SHA-256: `D("ROOT" | "BINDING" | "CARD" | "ROTATION" | "COMMAND" | "QUERY" | "EVENT" | "RECEIPT" | "STATUS" | "FRESH" | "EVIDENCE" | "CAPABILITIES", body)` |
| Signatures | Ed25519 strict profile — canonical encodings, small-order rejection, canonical `S`, cofactorless equation |
| Envelopes | `{body, proofs[]}`; proofs sorted strictly ascending unique by `kid` |
| IDs | `<prefix>_<nanoid>`: `hr` root, `ha` agent, `hc` card, `hp` principal, `hb` binding, `hk` key, `ho` op, `hq` query, `hn` nonce |
| Status | 131072-slot bitmap (16384 B) signed under `STATUS`; allocation + revocation bits share one chain |
| Freshness | `POST /freshness` challenge-bound, linearized behind the same barrier as mutations |

`schemas/` carries generated JSON Schema 2020-12 artifacts for every wire type; the runtime validators in `packages/core/src/schema.ts` are authoritative and the artifacts are tested for field-set coherence.

## CLI

| Command | Notes |
| --- | --- |
| `key generate --purpose <p> --out <f>` | Ed25519 keypair → 0600 KeyFile; refuses overwrite |
| `sign --tag T --body f --key-ref k --out f` | Offline signer; consent summary on BINDING/CARD/ROTATION |
| `combine --signed f… --roots f --out f` | Merge 2–4 proof envelopes after verifying each |
| `root init / inspect / rotate / freeze` | Bootstrap is local-only; freeze requires `--confirm-root` |
| `binding enroll / renew`, `card issue / rotate` | Submit signed commands |
| `revoke --command f --confirm-target id` | Card, binding, or agent |
| `resolve / receipt / audit export / audit verify` | Signed queries + offline chain verification |
| `status fetch`, `verify [--status f]`, `verify fresh` | Bounded-cache and challenge-fresh verification |
| `doctor`, `serve`, `config check` | Operator surface |

Exit codes: `0` ok · `2` usage/input · `3` denied (expired/revoked/frozen) · `4` authenticity failure · `5` unavailable · `6` conflict · `7` local key/storage error.

## HTTP API

```
GET  /v1/roots/{root}/documents?after=&limit=   RootHistoryReply   public
GET  /v1/roots/{root}/status                   Signed<Status>     public, no-store
GET  /v1/roots/{root}/events?after=&limit=     LogPage            public
POST /v1/roots/{root}/freshness                FreshRequest→FreshReply  public, linearized
POST /v1/roots/{root}/commands                 Signed<Command>→MutationReply
POST /v1/roots/{root}/queries                  Signed<Query>→ResolveReply|Receipt|ExportReply
GET  /healthz  /readyz  /metrics               liveness / readiness / Prometheus
```

Errors share the `ErrorReply` schema (`{v, error:{code, retryable}}`); `retryable` is true only for `RATE_LIMITED`, `UNAVAILABLE`, `STORAGE_BUSY`. HEAD/PUT/PATCH/DELETE/OPTIONS → 405.

## Verification

```bash
npm run typecheck                       # strict tsc, exactOptionalPropertyTypes
npm test                                # TV-H--01…60 + schema coherence
npm run fixtures                        # regenerate fixtures/fixtures.json (Python)
npm run fuzz:differential               # 100k parser/crypto mutation cases
npm run fuzz:schedule                   # 10k randomized command schedules
cd python && PYTHONPATH=src pytest -q   # Python parity suite
```

The fixture corpus (`fixtures/fixtures.json`) is the normative byte-exact anchor shared by both implementations. Conformance fixture keys are blocklisted in production mode (`production: true` server configs and `mode: "production"` client configs refuse them).

## Repository layout

```
packages/core     @latticeag/herald-core    strict JSON · JCS · Ed25519 · schemas · verify()
packages/worker   @latticeag/herald-worker  RootDO reducer · HTTP · node server · CF Worker/DO
packages/client   @latticeag/herald-client  HTTP client · trust store · LexScope adapter
packages/cli      @latticeag/herald-cli     `herald` command line
python/           latticeag-herald          Python parity implementation
fixtures/         normative conformance vectors (generated, committed)
schemas/          JSON Schema 2020-12 artifacts (generated, committed)
tests/            conformance · fuzzers · smoke mint
```

## Conformance

- **TV-H--01–60** — full vector suite in `tests/conformance/` (TS) and `python/tests/` (parity subset).
- **Differential fuzz** — 100 000 seeded parser/crypto mutations; every case rejects with a known code or canonicalizes to a stable fixed point.
- **Schedule fuzz** — 10 000 randomized valid/invalid command schedules against the real reducer; event chain continuity, replay, and revision invariants checked.
- **Smoke** — `tests/smoke/mint.ts` + the live CLI path (init → serve → enroll → issue → rotate → resolve → verify → revoke) run in CI.

## Security notes

- No seeds on argv, stdout, or logs; KeyFiles are 0600 under 0700 dirs, symlinks and wrong modes rejected.
- The reducer is a pure transaction: a failed mutation commits nothing; replayed operations return the stored reply; `op_id` reuse with a different payload is `IDEMPOTENCY_CONFLICT`.
- Freshness never caches; public reads are rate-limited separately from the reserved revocation lane.
- Report vulnerabilities via GitHub private security advisories before public disclosure.

MIT © LatticeAG
