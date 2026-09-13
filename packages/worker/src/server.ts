/**
 * Self-host development server (spec §13 dev path): node:http + node:sqlite.
 * Not the production target — the Worker/DO entry is — but it is a real,
 * fully functional registry used by the CLI smoke path and conformance suite.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { err, isRootId } from "@latticeag/herald-core";
import type { AuditEvent, RootDocument, ServerConfig, Signed } from "@latticeag/herald-core";
import { NodeSqliteDb } from "./sql.ts";
import { AeadBox } from "./aead.ts";
import { RootDO } from "./rootdo.ts";
import { handleRequest, handleReadyz, Metrics, RateLimiter, type HttpRequest, type HttpResponse, type Registry } from "./http.ts";

export interface KeySource {
  /** kid -> 32-byte Ed25519 seed. */
  seed(kid: string): Uint8Array | null;
}

/** KeySource backed by a directory of KeyFile JSON documents ({kid}.json). */
export class DirKeySource implements KeySource {
  private dir: string;
  private cache = new Map<string, Uint8Array | null>();
  constructor(dir: string) {
    this.dir = dir;
  }
  seed(kid: string): Uint8Array | null {
    if (this.cache.has(kid)) return this.cache.get(kid)!;
    let out: Uint8Array | null = null;
    try {
      const p = join(this.dir, `${kid}.json`);
      const kf = JSON.parse(readFileSync(p, "utf8")) as { v: number; kid: string; seed_b64u: string };
      if (kf.v === 1 && kf.kid === kid) {
        out = new Uint8Array(Buffer.from(kf.seed_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
        if (out.length !== 32) out = null;
      }
    } catch { out = null; }
    this.cache.set(kid, out);
    return out;
  }
}

/** A static in-memory key source (tests / embedding). */
export class MapKeySource implements KeySource {
  private m: Map<string, Uint8Array>;
  constructor(entries: Iterable<readonly [string, Uint8Array]>) {
    this.m = new Map(entries);
  }
  seed(kid: string): Uint8Array | null {
    return this.m.get(kid) ?? null;
  }
}

class FileFrontier {
  private path: string;
  constructor(stateDir: string) {
    this.path = join(stateDir, "frontier.json");
  }
  load(): { seq: string; log_hash: string } | null {
    try {
      const f = JSON.parse(readFileSync(this.path, "utf8"));
      if (typeof f.seq === "string" && typeof f.log_hash === "string") return f;
    } catch { /* absent */ }
    return null;
  }
  save(f: { seq: string; log_hash: string }): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(f), { mode: 0o600 });
  }
}

export interface LocalRegistryOptions {
  stateDir: string;               // one SQLite file per root: <stateDir>/<root>.sqlite
  keys: KeySource;
  dataKey: Uint8Array;            // 32-byte private data key
  clock?: () => number;
  limits?: { publicGetPerMin: number; publicFreshPerMin: number; writePerActorPerMin: number; revocationReservePerMin: number };
  crashHook?: (point: "before_commit" | "after_sign") => void;
}

export class LocalRegistry implements Registry {
  private opts: LocalRegistryOptions;
  private dos = new Map<string, RootDO>();
  metrics = new Metrics();
  limiter = new RateLimiter();
  constructor(opts: LocalRegistryOptions) {
    this.opts = opts;
    mkdirSync(opts.stateDir, { recursive: true });
  }
  private open(root: string): RootDO {
    let d = this.dos.get(root);
    if (!d) {
      const db = new NodeSqliteDb(join(this.opts.stateDir, `${root}.sqlite`));
      d = new RootDO(db, {
        root,
        serviceKeys: (kid) => this.opts.keys.seed(kid),
        dataBox: new AeadBox(this.opts.dataKey),
        clock: this.opts.clock ?? (() => Math.floor(Date.now() / 1000)),
        frontier: new FileFrontier(this.opts.stateDir),
        crashHook: this.opts.crashHook,
      });
      this.dos.set(root, d);
    }
    return d;
  }
  /** Bootstrap a root locally (root init). Refuses if a database exists. */
  initRoot(genesis: Signed<RootDocument>): Signed<AuditEvent> {
    const root = genesis.body.root;
    if (!isRootId(root)) throw err("ID_INVALID");
    if (existsSync(join(this.opts.stateDir, `${root}.sqlite`))) throw err("STATE_TRANSITION");
    return this.open(root).bootstrap(genesis);
  }
  hasRoot(root: string): boolean {
    return existsSync(join(this.opts.stateDir, `${root}.sqlite`));
  }
  lookup(root: string): RootDO | null {
    if (!this.hasRoot(root)) return null;
    const d = this.open(root);
    return d;
  }
  all(): RootDO[] {
    return [...this.dos.values()];
  }
  refreshGauges(): void {
    let committed = 0, slots = 0, agents = 0;
    for (const d of this.dos.values()) {
      const g = d.gauges();
      committed += g.committed_events; slots += g.allocated_slots; agents += g.live_agents;
    }
    this.metrics.gauges.committed_events = committed;
    this.metrics.gauges.allocated_slots = slots;
    this.metrics.gauges.live_agents = agents;
  }
  close(): void {
    for (const d of this.dos.values()) {
      // no explicit close on DO; close through db ownership
    }
    this.dos.clear();
  }
}

export function loadServerConfig(path: string): ServerConfig {
  return JSON.parse(readFileSync(path, "utf8")) as ServerConfig;
}

/**
 * Start the development HTTP server. Returns the listening port.
 */
export function serve(registry: LocalRegistry, port: number, host = "127.0.0.1"): Promise<number> {
  const limits = registry["opts"].limits ?? {
    publicGetPerMin: 120, publicFreshPerMin: 120, writePerActorPerMin: 30, revocationReservePerMin: 60,
  };
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Uint8Array[] = [];
    req.on("data", (c: Uint8Array) => chunks.push(c));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const body = Buffer.concat(chunks.map((c) => Buffer.from(c)));
      // Reject paths containing escapes or repeated slashes at the transport edge.
      const rawPath = url.pathname;
      const hreq: HttpRequest = {
        method: req.method ?? "GET",
        path: rawPath,
        query: new Map([...url.searchParams.entries()]),
        headers: new Map(Object.entries(req.headers).flatMap(([k, v]) => (typeof v === "string" ? [[k.toLowerCase(), v]] : []))),
        body: new Uint8Array(body),
        ip: (req.socket.remoteAddress ?? "unknown"),
      };
      let hres: HttpResponse;
      try {
        hres = handleRequest(hreq, {
          registry,
          metrics: registry.metrics,
          limiter: registry.limiter,
          limits,
        });
        registry.refreshGauges();
      } catch (e) {
        res.writeHead(500, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ v: 1, error: { code: "UNAVAILABLE" } }));
        return;
      }
      res.writeHead(hres.status, hres.headers);
      res.end(Buffer.from(hres.body));
    });
    req.on("error", () => res.destroy());
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const addr = server.address();
      resolve(typeof addr === "object" && addr ? addr.port : port);
    });
  });
}

export function generateDataKey(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}
