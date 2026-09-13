/**
 * `herald` CLI (spec §9.1). One canonical JSON object + newline to stdout on
 * --json; diagnostics to stderr. Exit codes per the §9.1 table.
 */

import { readFileSync, writeFileSync, openSync, closeSync, existsSync, statSync } from "node:fs";
import { resolve, dirname, isAbsolute } from "node:path";
import {
  b64uDecode, canonicalize, callerJkt, digest, ed25519Verify, err, isDid, isKeyId,
  isRootId, newId, parseJsonStrict, LIMITS_ORDINARY, publicKeyFromSeed, sha256Hex,
  validate, verifyHistory, verifyWithContext, isTag, ed25519Sign, digestBytes, b64uEncode,
} from "@latticeag/herald-core";
import type {
  AgentCard, AuditEvent, Capabilities, ClientConfig, Command, Frontier,
  IdentityBundle, JsonObject, JsonValue, KeyFile, PublicKey, Query, Receipt,
  RootDocument, RootPin, Signed, Status, Fresh, VerifyResult, ExportReply,
  ExportSummary, DoctorReply, HumanBinding, Rotation,
} from "@latticeag/herald-core";
import { HeraldClient, HeraldHttpError, TrustStore, HeraldVerifier } from "@latticeag/herald-client";
import { CliExit, loadKeyFile, keyGenerate, signWith } from "./keystore.ts";

const TAGS_SIGNABLE = new Set(["ROOT", "BINDING", "CARD", "ROTATION", "COMMAND", "QUERY"]);

export interface CliOptions {
  config: string | undefined;
  json: boolean;
  timeoutMs: number;
  offline: boolean;
}

interface ParsedArgs {
  pos: string[];
  flags: Map<string, string[]>;
  bools: Set<string>;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const pos: string[] = [];
  const flags = new Map<string, string[]>();
  const bools = new Set<string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--json" || a === "--offline") { bools.add(a.slice(2)); continue; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) {
        flags.set(a.slice(2, eq), [...(flags.get(a.slice(2, eq)) ?? []), a.slice(eq + 1)]);
      } else {
        const v = argv[++i];
        if (v === undefined) throw new CliExit(2, `flag ${a} requires a value`);
        flags.set(a.slice(2), [...(flags.get(a.slice(2)) ?? []), v]);
      }
      continue;
    }
    pos.push(a);
  }
  return { pos, flags, bools };
}

function one(args: ParsedArgs, name: string, required = true): string {
  const v = args.flags.get(name);
  if (!v || v.length !== 1) {
    if (required) throw new CliExit(2, `missing required flag --${name}`);
    return "";
  }
  return v[0]!;
}

function readJson(path: string): JsonValue {
  let raw: Uint8Array;
  if (path === "-") raw = new Uint8Array(readFileSync(0));
  else {
    if (!existsSync(path)) throw new CliExit(2, `file not found: ${path}`);
    raw = new Uint8Array(readFileSync(path));
  }
  const p = parseJsonStrict(raw, { ...LIMITS_ORDINARY, maxBytes: 1 << 22 });
  if (!p.ok) throw new CliExit(2, `invalid JSON in ${path}: ${p.code}`);
  return p.value;
}

function readJsonOrDie<T>(path: string): T {
  return readJson(path) as T;
}

/** Exclusive-create output file (never overwrite). */
function writeExclusive(path: string, data: string): string {
  const p = resolve(path);
  try {
    const fd = openSync(p, "wx", 0o600);
    writeFileSync(fd, data);
    closeSync(fd);
    return p;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new CliExit(7, `output exists: ${path}`);
    throw new CliExit(7, `cannot write output: ${path}`);
  }
}

// ---------------------------------------------------------------------------
// Config

function loadConfig(path: string | undefined): { cfg: ClientConfig; dir: string } {
  const p = resolve(path ?? ".devin/herald/client.json");
  if (!existsSync(p)) throw new CliExit(2, `config not found: ${p}`);
  const v = readJsonOrDie<ClientConfig>(p);
  const bad = validate("ClientConfig", v as unknown as JsonObject);
  if (bad !== null) throw new CliExit(2, `config invalid: ${bad}`);
  return { cfg: v, dir: dirname(p) };
}

function resolveCfgPath(dir: string, p: string): string {
  return isAbsolute(p) ? p : resolve(dir, p);
}

function pinFor(cfg: ClientConfig, root: string): RootPin {
  const pin = cfg.roots.find((r) => r.root === root);
  if (!pin) throw new CliExit(2, `root not pinned in config: ${root}`);
  return pin;
}

function clientFor(cfg: ClientConfig, dir: string, root: string, timeoutMs: number): HeraldClient {
  const pin = pinFor(cfg, root);
  return new HeraldClient({ origin: pin.origin, timeoutMs });
}

function keyFileFor(cfg: ClientConfig, dir: string, ref: string): KeyFile {
  // ref may be a kid registered in key_refs or a direct file path.
  const entry = cfg.key_refs.find((k) => k.kid === ref);
  const path = entry ? resolveCfgPath(dir, entry.path) : resolve(ref);
  const kf = loadKeyFile(path);
  if (entry && kf.kid !== ref) throw new CliExit(7, `key file kid mismatch: expected ${ref}`);
  return kf;
}

// ---------------------------------------------------------------------------
// Output

function emit(opts: CliOptions, v: JsonValue): void {
  const text = Buffer.from(canonicalize(v as JsonObject)).toString() + "\n";
  if (opts.json) process.stdout.write(text);
  else {
    process.stdout.write(text); // canonical JSON either way (single wire format)
  }
}

function diag(msg: string): void {
  process.stderr.write(msg.replace(/[\x00-\x1f\x7f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`) + "\n");
}

// ---------------------------------------------------------------------------
// Exit-code mapping

export function exitForHttp(status: number, code: string): number {
  if ([400, 404, 405, 413, 422].includes(status)) return 2;
  if (status === 403) return 3;
  if (status === 401) {
    return ["COMMAND_EXPIRED", "QUERY_EXPIRED", "NOT_YET_VALID"].includes(code) ? 3 : 4;
  }
  if (status === 429 || status === 503) return 5;
  if (status === 409) return 6;
  return 5;
}

export function exitForVerify(r: VerifyResult): number {
  if (r.decision === "allow") return 0;
  const liveDeny = new Set(["CARD_REVOKED", "CARD_EXPIRED", "BINDING_EXPIRED", "ROOT_FROZEN", "STATUS_STALE", "REPLAY", "CHALLENGE_MISMATCH"]);
  if (liveDeny.has(r.code)) return 3;
  return 4;
}

// ---------------------------------------------------------------------------
// Commands

async function cmdSubmit(args: ParsedArgs, opts: CliOptions, cfg: ClientConfig, dir: string): Promise<void> {
  if (opts.offline) throw new CliExit(2, "mutations require the network (--offline given)");
  const cmd = readJsonOrDie<Signed<Command>>(one(args, "command"));
  const bad = validate("Command", cmd as unknown as JsonObject);
  if (bad !== null) throw new CliExit(2, `command invalid: ${bad}`);
  const client = clientFor(cfg, dir, cmd.body.root, opts.timeoutMs);
  const reply = await client.submit(cmd);
  emit(opts, reply as unknown as JsonValue);
}

function consentSummary(kind: string, body: JsonObject): void {
  // Human-approval surface (spec §9.1): before signing BINDING/CARD/ROTATION
  // proofs, display the fields a human must see.
  const b = body as Record<string, unknown>;
  diag(`signing ${kind}: root=${String(b["root"] ?? "")} did=${String(b["did"] ?? "")} ` +
    `principal=${String(b["principal_id"] ?? b["human_principal"] ?? "")} ` +
    `expires=${String(b["expires_at"] ?? "")} capabilities=${String(b["capabilities_hash"] ?? "")}`);
}

export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const opts: CliOptions = {
    config: args.flags.get("config")?.[0],
    json: args.bools.has("json"),
    timeoutMs: 2000,
    offline: args.bools.has("offline"),
  };
  if (args.flags.has("timeout-ms")) {
    const t = Number(one(args, "timeout-ms"));
    if (!Number.isInteger(t) || t < 100 || t > 10000) throw new CliExit(2, "--timeout-ms must be 100..10000");
    opts.timeoutMs = t;
  }
  const [cmd, sub] = args.pos;
  if (!cmd) throw new CliExit(2, "usage: herald <command> [subcommand] [flags]");

  // Commands that do not need the client config:
  if (cmd === "key" && sub === "generate") {
    const purpose = one(args, "purpose");
    if (!["control", "service", "registrar", "human", "agent"].includes(purpose)) throw new CliExit(2, "--purpose must be control|service|registrar|human|agent");
    const out = one(args, "out");
    const { publicKey } = keyGenerate(out);
    emit(opts, { v: 1, purpose, public_key: publicKey } as unknown as JsonValue);
    return 0;
  }
  if (cmd === "config" && sub === "check") {
    const { cfg } = loadConfig(opts.config);
    for (const p of cfg.roots) {
      if (!isRootId(p.root)) throw new CliExit(2, `invalid root pin: ${p.root}`);
    }
    emit(opts, { v: 1, valid: true });
    return 0;
  }

  const { cfg, dir } = loadConfig(opts.config);
  const store = new TrustStore(resolveCfgPath(dir, cfg.cache_dir), cfg.roots);

  if (cmd === "audit" && sub === "verify") {
    const events = readJsonOrDie<Signed<AuditEvent>[]>(one(args, "events"));
    const roots = readJsonOrDie<Signed<RootDocument>[]>(one(args, "roots"));
    const pins = cfg.roots;
    const r = verifyHistory(events, roots, pins);
    emit(opts, r as unknown as JsonValue);
    return r.valid ? 0 : 4;
  }

  if (cmd === "sign") {
    const tag = one(args, "tag").toUpperCase();
    if (!TAGS_SIGNABLE.has(tag)) throw new CliExit(2, `unsupported tag: ${tag}`);
    const body = readJsonOrDie<JsonObject>(one(args, "body"));
    const kf = keyFileFor(cfg, dir, one(args, "key-ref"));
    if (["BINDING", "CARD", "ROTATION"].includes(tag)) consentSummary(tag, body);
    if (tag === "CARD" && args.flags.has("manifest")) {
      const manifest = readJsonOrDie<Capabilities>(one(args, "manifest"));
      const c = body as unknown as AgentCard;
      if (digest("CAPABILITIES", manifest) !== c.capabilities_hash)
        throw new CliExit(2, "manifest does not match capabilities_hash");
      diag(`manifest entries: ${JSON.stringify(manifest.capabilities)}`);
    }
    const signed = signWith(kf, tag as Parameters<typeof digestBytes>[0], body);
    const p = writeExclusive(one(args, "out"), Buffer.from(canonicalize(signed as unknown as JsonObject)).toString() + "\n");
    emit(opts, { v: 1, written: p } as unknown as JsonValue);
    return 0;
  }

  if (cmd === "combine") {
    const files = args.flags.get("signed") ?? [];
    if (files.length < 2 || files.length > 4) throw new CliExit(2, "combine requires 2-4 --signed files");
    const roots = readJsonOrDie<Signed<RootDocument>[]>(one(args, "roots"));
    const envs = files.map((f) => readJsonOrDie<Signed<JsonObject>>(f));
    const canon = envs.map((e) => Buffer.from(canonicalize(e.body)).toString("hex"));
    if (new Set(canon).size !== 1) throw new CliExit(2, "bodies differ; refusing to combine");
    const body = envs[0]!.body;
    // Verify each signature under keys discoverable in the body or the pinned
    // root documents; unknown kids are rejected.
    const known = new Map<string, PublicKey>();
    for (const d of roots) {
      for (const k of [d.body.control_key, d.body.service_key, d.body.registrar_key]) known.set(k.id, k);
    }
    for (const k of ["human_key", "agent_key", "key", "new_key", "control_key", "service_key", "registrar_key"] as const) {
      const kk = body[k] as PublicKey | undefined;
      if (kk && typeof kk === "object" && isKeyId(kk.id)) known.set(kk.id, kk);
    }
    const allProofs = new Map<string, { kid: string; signature: string }>();
    for (const e of envs) {
      for (const p of e.proofs) allProofs.set(p.kid, p);
    }
    for (const [kid, p] of allProofs) {
      const key = known.get(kid);
      if (!key) throw new CliExit(4, `unknown kid in proof set: ${kid}`);
      const sig = b64uDecode(p.signature);
      const pub = b64uDecode(key.public_key);
      if (!sig || !pub) throw new CliExit(4, `bad signature encoding for ${kid}`);
      // Determine the tag from the body shape heuristically is unsafe; use the
      // signed envelope's implied domain via validate + the --tag-independent
      // domain resolution table.
      const tag = tagForBody(body);
      if (!tag || !ed25519Verify(pub, digestBytes(tag, body), sig)) throw new CliExit(4, `signature invalid for ${kid}`);
    }
    const merged = { body, proofs: [...allProofs.values()].sort((a, b) => a.kid < b.kid ? -1 : 1) };
    const p = writeExclusive(one(args, "out"), Buffer.from(canonicalize(merged as unknown as JsonObject)).toString() + "\n");
    emit(opts, { v: 1, written: p, proofs: merged.proofs.length } as unknown as JsonValue);
    return 0;
  }

  if (cmd === "root" && sub === "init") {
    const docFile = one(args, "document");
    const stateDir = one(args, "state");
    const genesis = readJsonOrDie<Signed<RootDocument>>(docFile);
    const bad = validate("RootDocument", genesis.body);
    if (bad !== null) throw new CliExit(2, `document invalid: ${bad}`);
    const { LocalRegistry, MapKeySource } = await import("@latticeag/herald-worker");
    const pin = cfg.roots.find((r) => r.root === genesis.body.root);
    if (!pin) throw new CliExit(2, `root not pinned in config: ${genesis.body.root}`);
    // The configured service key signs the genesis event: load it from key_refs.
    const svcKid = genesis.body.service_key.id;
    const svc = keyFileFor(cfg, dir, svcKid);
    const svcSeed = b64uDecode(svc.seed_b64u)!;
    if (b64uEncode(publicKeyFromSeed(svcSeed)) !== genesis.body.service_key.public_key)
      throw new CliExit(7, `key file ${svcKid} does not match document service key`);
    const reg = new LocalRegistry({
      stateDir: resolve(stateDir),
      keys: new MapKeySource([[svcKid, svcSeed]]),
      dataKey: new Uint8Array(32).fill(0),
    });
    const ev = reg.initRoot(genesis);
    emit(opts, ev as unknown as JsonValue);
    return 0;
  }

  // Network-requiring commands:
  const needNet = !opts.offline;
  const netCommands = [
    ["root", "inspect"], ["root", "rotate"], ["root", "freeze"],
    ["binding", "enroll"], ["binding", "renew"], ["card", "issue"], ["card", "rotate"],
    ["revoke", undefined], ["resolve", undefined], ["receipt", undefined],
    ["audit", "export"], ["status", "fetch"], ["verify", "fresh"],
  ];
  const isNet = netCommands.some(([c, s]) => c === cmd && s === sub) ||
    (cmd === "verify" && sub === "fresh");
  if (!needNet && isNet) throw new CliExit(2, `${cmd} ${sub ?? ""} requires the network (--offline given)`);

  if (cmd === "root" && sub === "inspect") {
    const root = one(args, "root");
    const client = clientFor(cfg, dir, root, opts.timeoutMs);
    emit(opts, (await client.root(root)) as unknown as JsonValue);
    return 0;
  }

  if (cmd === "root" && sub === "rotate") return (await cmdSubmit(args, opts, cfg, dir), 0);
  if (cmd === "root" && sub === "freeze") {
    const confirm = one(args, "confirm-root");
    const c = readJsonOrDie<Signed<Command>>(one(args, "command"));
    if (c.body.subject !== confirm || c.body.action.kind !== "root.freeze")
      throw new CliExit(2, "--confirm-root does not match command subject");
    return (await cmdSubmit(args, opts, cfg, dir), 0);
  }
  if (cmd === "binding" || cmd === "card") return (await cmdSubmit(args, opts, cfg, dir), 0);
  if (cmd === "revoke") {
    const confirm = one(args, "confirm-target");
    const c = readJsonOrDie<Signed<Command>>(one(args, "command"));
    const a = c.body.action;
    if (a.kind !== "revoke" || a.id !== confirm) throw new CliExit(2, "--confirm-target does not match command target");
    return (await cmdSubmit(args, opts, cfg, dir), 0);
  }
  if (cmd === "resolve" || cmd === "receipt") {
    const q = readJsonOrDie<Signed<Query>>(one(args, "query"));
    const bad = validate("Query", q as unknown as JsonObject);
    if (bad !== null) throw new CliExit(2, `query invalid: ${bad}`);
    const client = clientFor(cfg, dir, q.body.root, opts.timeoutMs);
    emit(opts, (await client.query(q)) as JsonValue);
    return 0;
  }
  if (cmd === "audit" && sub === "export") {
    const q = readJsonOrDie<Signed<Query>>(one(args, "query"));
    const client = clientFor(cfg, dir, q.body.root, opts.timeoutMs);
    const page = (await client.exportAudit(q)) as ExportReply;
    const out = one(args, "out");
    const abs = writeExclusive(out, Buffer.from(canonicalize(page as unknown as JsonObject)).toString() + "\n");
    const summary: ExportSummary = {
      v: 1, count: page.records.length, next_revision: page.next_revision,
      path: abs, hash: digest("EVIDENCE", { export: page } as unknown as JsonObject),
    };
    emit(opts, summary as unknown as JsonValue);
    return 0;
  }
  if (cmd === "status" && sub === "fetch") {
    const root = one(args, "root");
    const client = clientFor(cfg, dir, root, opts.timeoutMs);
    const status = await client.status(root);
    // Verify before caching: pinned genesis, doc continuity, and the STATUS
    // signature under the current epoch's service key.
    const pin = pinFor(cfg, root);
    const docsPage = await client.rootHistory(root, "0", 64);
    const docs = docsPage.documents;
    const genesis = docs[0]?.body;
    if (!genesis || digest("ROOT", genesis) !== pin.genesis_hash) throw new CliExit(4, "root genesis does not match pin");
    const cur = docs[docs.length - 1]!.body;
    if (status.body.root !== root || BigInt(status.body.root_epoch) < BigInt(cur.epoch))
      throw new CliExit(4, "status epoch below pinned root chain");
    const svc = cur.service_key;
    const sig = status.proofs.length === 1 ? b64uDecode(status.proofs[0]!.signature) : null;
    const pub = b64uDecode(svc.public_key);
    if (!sig || !pub || status.proofs[0]!.kid !== svc.id ||
        !ed25519Verify(pub, digestBytes("STATUS", status.body), sig))
      throw new CliExit(4, "status signature invalid");
    // Frontier: refuse rollback below the locally pinned head.
    const st = store.load(root);
    if (st.frontier && BigInt(status.body.seq) < BigInt(st.frontier.seq)) throw new CliExit(4, "status seq below local frontier");
    if (st.frontier && status.body.seq === st.frontier.seq && status.body.log_hash !== st.frontier.log_hash)
      throw new CliExit(4, "conflicting head at pinned frontier");
    const out = one(args, "out");
    store.saveStatus(root, status);
    writeExclusive(out, Buffer.from(canonicalize(status as unknown as JsonObject)).toString() + "\n");
    emit(opts, status as unknown as JsonValue);
    return 0;
  }
  if (cmd === "verify") {
    const bundle = readJsonOrDie<IdentityBundle>(one(args, "bundle"));
    if (sub === "fresh") {
      const root = one(args, "root");
      const client = clientFor(cfg, dir, root, opts.timeoutMs);
      const v = new HeraldVerifier(store, client);
      const r = await v.verifyFresh(bundle);
      emit(opts, r as unknown as JsonValue);
      return exitForVerify(r);
    }
    const statusPath = one(args, "status");
    const status = readJsonOrDie<Signed<Status>>(statusPath);
    // Bounded-cache verify: received_age_s reflects the status file's age.
    const mtime = statSync(statusPath).mtimeMs;
    const receivedAgeS = Math.max(0, Math.ceil((Date.now() - mtime) / 1000));
    const root = bundle.roots[0]?.body.root ?? "";
    const ctx = store.context(root, { received_age_s: receivedAgeS });
    const r = verifyWithContext(
      { bundle, status, fresh: null, challenge: null, now: Math.floor(Date.now() / 1000), mode: "bounded_cache" },
      ctx,
    );
    emit(opts, r as unknown as JsonValue);
    return exitForVerify(r);
  }
  if (cmd === "doctor") {
    const root = one(args, "root");
    const reply = await doctor(cfg, dir, root, opts);
    emit(opts, reply as unknown as JsonValue);
    return reply.ready ? 0 : 5;
  }
  if (cmd === "serve") {
    if (opts.offline) throw new CliExit(2, "serve requires the network");
    const serverCfgPath = one(args, "server-config", false) || resolve(dir, "server.json");
    const sc = readJsonOrDie<import("@latticeag/herald-core").ServerConfig>(serverCfgPath);
    const { LocalRegistry, MapKeySource, serve } = await import("@latticeag/herald-worker");
    const keyDir = resolveCfgPath(dir, "keys");
    const { DirKeySource } = await import("@latticeag/herald-worker");
    const reg = new LocalRegistry({
      stateDir: resolveCfgPath(dir, "state"),
      keys: new DirKeySource(keyDir),
      dataKey: new Uint8Array(Buffer.from(process.env[sc.private_data_key_binding] ?? "", "base64")).length === 32
        ? new Uint8Array(Buffer.from(process.env[sc.private_data_key_binding]!, "base64"))
        : new Uint8Array(32).fill(0),
    });
    void MapKeySource;
    const port = Number(args.flags.get("port")?.[0] ?? "8080");
    const bound = await serve(reg, port);
    diag(`herald dev server listening on http://127.0.0.1:${bound}`);
    return new Promise<number>(() => {});
  }
  throw new CliExit(2, `unknown command: ${argv.join(" ")}`);
}

function tagForBody(body: JsonObject): "ROOT" | "BINDING" | "CARD" | "ROTATION" | "COMMAND" | "QUERY" | null {
  if ("status_slots" in body) return "ROOT";
  if ("principal_id" in body) return "BINDING";
  if ("status_index" in body) return "CARD";
  if ("new_card_hash" in body) return "ROTATION";
  if ("op_id" in body) return "COMMAND";
  if ("query_id" in body) return "QUERY";
  return null;
}

async function doctor(cfg: ClientConfig, dir: string, root: string, opts: CliOptions): Promise<DoctorReply> {
  const checks: DoctorReply["checks"] = {
    clock: "ok", root: "untrusted", storage: "unavailable", capacity: "warning", cache: "stale",
  };
  const pin = cfg.roots.find((r) => r.root === root);
  if (pin && pin.enabled) checks.root = "trusted";
  const store = new TrustStore(resolveCfgPath(dir, cfg.cache_dir), cfg.roots);
  const st = store.load(root);
  checks.storage = "ok";
  checks.cache = st.state === "USABLE" ? "usable" : st.state === "FORKED" ? "forked" : "stale";
  if (st.frontier) checks.cache = st.state === "FORKED" ? "forked" : "usable";
  // Capacity from the last cached status.
  if (st.status) {
    const bits = b64uDecode(st.status.body.bits);
    if (bits) {
      let set = 0;
      for (const b of bits) for (let i = 0; i < 8; i++) if (b & (1 << i)) set++;
      checks.capacity = set >= 131072 ? "full" : set > 114688 ? "warning" : "ok";
    }
  }
  const ready = checks.clock === "ok" && checks.root === "trusted" && checks.storage === "ok" &&
    checks.capacity !== "full" && checks.cache !== "forked";
  return { v: 1, ready, checks };
}

// Entry point wrapper maps thrown errors to exit codes.
export async function run(argv: string[]): Promise<number> {
  try {
    return await main(argv);
  } catch (e) {
    if (e instanceof CliExit) {
      diag(e.message);
      return e.exitCode;
    }
    if (e instanceof HeraldHttpError) {
      diag(`request failed: ${e.status} ${e.code}`);
      return exitForHttp(e.status, e.code);
    }
    diag(`internal error: ${(e as Error).message}`);
    return 5;
  }
}
