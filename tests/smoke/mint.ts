/**
 * Smoke-test minter: writes a live playground into a scratch directory —
 * key files (fixture seeds, development mode), client/server configs, the
 * signed genesis document, and command/query envelopes stamped at real time.
 *
 * Usage: node tests/smoke/mint.ts <outdir>
 */

import { writeFileSync, mkdirSync, chmodSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  b64uDecode, b64uEncode, callerJkt, canonicalize, digest, digestBytes,
  ed25519Sign,
} from "@latticeag/herald-core";
import type { JsonObject, Signed } from "@latticeag/herald-core";

const FX = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../fixtures/fixtures.json"), "utf8"),
) as Record<string, any>;

const out: string = process.argv[2] ?? (() => { throw new Error("usage: mint.ts <outdir>"); })();
const NOW = Math.floor(Date.now() / 1000);
const R: string = FX.R;
const A: string = FX.A;

const seed = (n: number): Uint8Array => b64uDecode(FX.KEYS[String(n)].seed_b64u)!;
const pub = (n: number): { id: string; public_key: string } => ({
  id: FX.KEYS[String(n)].kid, public_key: FX.KEYS[String(n)].public_key,
});
const ident = (p: string, n: number): string => `${p}_${String(n).padStart(21, "0")}`;

function signed<T extends JsonObject>(tag: any, body: T, signers: number[]): Signed<T> {
  const uniq = [...new Set(signers)].sort((a, b) => a - b);
  return {
    body: JSON.parse(JSON.stringify(body)),
    proofs: uniq.map((n) => ({
      kid: FX.KEYS[String(n)].kid,
      signature: b64uEncode(ed25519Sign(seed(n), digestBytes(tag, body))),
    })),
  };
}

function w(path: string, v: unknown, mode = 0o644): void {
  const p = join(out, path);
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, Buffer.from(canonicalize(v as JsonObject)).toString() + "\n", { mode });
}

// --- key files (0600 under 0700 dir) --------------------------------------
mkdirSync(join(out, "keys"), { recursive: true });
chmodSync(join(out, "keys"), 0o700);
for (const n of [1, 2, 3, 4, 5, 6, 7]) {
  const kid = FX.KEYS[String(n)].kid;
  w(`keys/${kid}.json`, { v: 1, kid, algorithm: "Ed25519", seed_b64u: FX.KEYS[String(n)].seed_b64u }, 0o600);
}

// --- configs ----------------------------------------------------------------
const port = Number(process.env.SMOKE_PORT ?? 8931);
const pin = { ...FX.CLIENT_CONFIG.roots[0], origin: `http://localhost:${port}` };
w("client.json", {
  v: 1, mode: "development", roots: [pin], cache_dir: "cache",
  key_refs: [1, 2, 3, 4, 5, 6, 7].map((n) => ({ kid: FX.KEYS[String(n)].kid, path: `keys/${FX.KEYS[String(n)].kid}.json` })),
  clock_max_error_s: 2, read_max_age_s: 60, fresh_max_age_s: 5,
});
w("server.json", { ...FX.SERVER_CONFIG });
w("genesis.json", FX.SR);
w("roots.json", [FX.SR]);

// --- commands at real time ---------------------------------------------------
const binding = signed("BINDING", {
  v: 1, root: R, id: ident("hb", 1), did: A, principal_id: FX.P,
  human_key: pub(4), agent_key: pub(5), assurance: "operator-attested",
  consent: "agent-accountability-v1", issued_at: NOW - 10,
  expires_at: NOW + 2_592_000, registrar_epoch: "1", previous: null,
}, [3, 4, 5]);
const enroll = signed("COMMAND", {
  v: 1, root: R, op_id: ident("ho", 1), actor: pub(3).id, subject: A,
  expected_revision: "0", issued_at: NOW - 5, expires_at: NOW + 90,
  action: { kind: "binding.enroll", binding },
}, [3]);

const bindingHash = digest("BINDING", binding.body);
const capHash = digest("CAPABILITIES", FX.CAP);
const card = signed("CARD", {
  v: 1, root: R, id: ident("hc", 1), did: A, key: pub(5), key_epoch: "1",
  human_principal: FX.P, binding_hash: bindingHash, capabilities_hash: capHash,
  issued_at: NOW - 10, not_before: NOW - 10, expires_at: NOW + 3600,
  status_index: 17, previous: null,
  gateway_bindings: [{ gateway: FX.G, sub: FX.SUB, tenant_id: FX.TEN, caller_jkt: callerJkt(pub(5).public_key) }],
}, [4, 5]);
const issue = signed("COMMAND", {
  v: 1, root: R, op_id: ident("ho", 2), actor: pub(5).id, subject: A,
  expected_revision: "1", issued_at: NOW - 5, expires_at: NOW + 90,
  action: { kind: "card.issue", card },
}, [5]);

const card2 = signed("CARD", {
  v: 1, root: R, id: ident("hc", 2), did: A, key: pub(6), key_epoch: "2",
  human_principal: FX.P, binding_hash: bindingHash, capabilities_hash: capHash,
  issued_at: NOW - 10, not_before: NOW - 10, expires_at: NOW + 3600,
  status_index: 18, previous: digest("CARD", card.body),
  gateway_bindings: [{ gateway: FX.G, sub: FX.SUB, tenant_id: FX.TEN, caller_jkt: callerJkt(pub(6).public_key) }],
}, [4, 6]);
const rotation = signed("ROTATION", {
  v: 1, root: R, did: A, old_key_id: pub(5).id, new_key: pub(6),
  old_card_hash: digest("CARD", card.body), new_card_hash: digest("CARD", card2.body),
  from_epoch: "1", to_epoch: "2", issued_at: NOW - 5, expires_at: NOW + 90, nonce: FX.N,
}, [4, 5, 6]);
const rotate = signed("COMMAND", {
  v: 1, root: R, op_id: ident("ho", 3), actor: pub(5).id, subject: A,
  expected_revision: "2", issued_at: NOW - 5, expires_at: NOW + 90,
  action: { kind: "card.rotate", card: card2, rotation },
}, [5]);

w("cmd-enroll.json", enroll);
w("cmd-issue.json", issue);
w("cmd-rotate.json", rotate);

// --- queries ------------------------------------------------------------------
const query = (id: number, q: JsonObject) => signed("QUERY", {
  v: 1, root: R, query_id: ident("hq", id), actor: pub(4).id,
  issued_at: NOW - 5, expires_at: NOW + 25, query: q,
}, [4]);
w("q-resolve.json", query(1, { kind: "resolve", did: A, card_id: null }));
w("q-receipt.json", query(2, { kind: "receipt", op_id: ident("ho", 2) }));
w("q-export.json", query(3, { kind: "export", did: A, after_revision: "0", limit: 100 }));

// Card body + binding for bundle assembly after issue reply is captured.
w("binding.json", binding);
w("card.json", card);
console.log(`minted playground at ${out} (now=${NOW})`);
