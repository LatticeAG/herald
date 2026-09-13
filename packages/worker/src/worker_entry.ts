/**
 * Cloudflare Worker + Durable Object entry (spec §2 hosted profile).
 *
 * The Worker terminates TLS, applies edge rate limits, and forwards each
 * root-scoped request to the per-root Durable Object named by the path root.
 * The DO runs RootDO over its transactional SQLite storage — all
 * serialization-barrier and single-writer semantics come from the DO.
 *
 * This module targets the Workers runtime (`env` bindings); it is exercised
 * by deployment, not by the node development server. The same RootDO powers
 * both profiles.
 */

import { DoSqlDb, type DoSqlStorage } from "./sql.ts";
import { AeadBox } from "./aead.ts";
import { RootDO } from "./rootdo.ts";
import { handleRequest, Metrics, RateLimiter, type HttpRequest, type HttpResponse } from "./http.ts";

export interface DurableObjectNamespaceLike {
  idFromName(name: string): { toString(): string };
  get(id: { toString(): string }): { fetch(input: string | Request, init?: unknown): Promise<Response> };
}

export interface HeraldEnv {
  HERALD_ROOT: DurableObjectNamespaceLike;
  /** base64url 32-byte private data key (secret binding). */
  HERALD_DATA_KEY: string;
  /**
   * JSON map of service-key kid -> base64url seed, provisioned via secret
   * store. The DO selects the seed for the current root epoch's service key;
   * a new epoch's key must be provisioned before/at rotation.
   */
  HERALD_SERVICE_KEYS: string;
}

const metrics = new Metrics();
const limiter = new RateLimiter();
const LIMITS = { publicGetPerMin: 120, publicFreshPerMin: 120, writePerActorPerMin: 30, revocationReservePerMin: 60 };

function b64d(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
}

function toHttpRequest(request: Request, body: ArrayBuffer, ip: string): HttpRequest {
  const url = new URL(request.url);
  const headers = new Map<string, string>();
  request.headers.forEach((v, k) => headers.set(k.toLowerCase(), v));
  return {
    method: request.method,
    path: url.pathname,
    query: new Map([...url.searchParams.entries()]),
    headers,
    body: new Uint8Array(body),
    ip,
  };
}

function toFetchResponse(h: HttpResponse): Response {
  return new Response(Buffer.from(h.body) as unknown as NonNullable<RequestInit["body"]>, { status: h.status, headers: h.headers });
}

export default {
  async fetch(request: Request, env: HeraldEnv, ctx: unknown): Promise<Response> {
    const body = await request.arrayBuffer();
    const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
    const url = new URL(request.url);
    const m = /^\/v1\/roots\/([^/]+)\//.exec(url.pathname);
    if (!m) {
      // Global routes run at the edge; readiness is aggregated across DOs by
      // the platform health checker, so /readyz here reports liveness only.
      const hres = handleRequest(toHttpRequest(request, body, ip), {
        registry: { lookup: () => null, all: () => [] }, metrics, limiter, limits: LIMITS,
      });
      return toFetchResponse(hres);
    }
    const id = env.HERALD_ROOT.idFromName(m[1]!);
    const stub = env.HERALD_ROOT.get(id);
    const fwd: RequestInit = { method: request.method, headers: request.headers };
    if (body.byteLength) fwd.body = body;
    return stub.fetch(new Request(request.url, fwd));
  },
};

/**
 * Durable Object: one instance per root id; owns authoritative state in its
 * transactional SQLite storage. `idFromName(root)` binds the instance.
 */
export class HeraldRootDO {
  private dos = new Map<string, RootDO>();
  private sql: DoSqlStorage;
  private env: HeraldEnv;
  private seeds: Map<string, Uint8Array>;
  private dataKey: Uint8Array;

  constructor(ctx: { storage: { sql: DoSqlStorage }; id: { toString(): string; name?: string } }, env: HeraldEnv) {
    this.sql = ctx.storage.sql;
    this.env = env;
    this.dataKey = b64d(env.HERALD_DATA_KEY);
    this.seeds = new Map(
      Object.entries(JSON.parse(env.HERALD_SERVICE_KEYS) as Record<string, string>)
        .map(([k, v]) => [k, b64d(v)] as const),
    );
  }

  private do(rootId: string): RootDO {
    let d = this.dos.get(rootId);
    if (!d) {
      d = new RootDO(new DoSqlDb(this.sql), {
        root: rootId,
        serviceKeys: (kid) => this.seeds.get(kid) ?? null,
        dataBox: new AeadBox(this.dataKey),
        clock: () => Math.floor(Date.now() / 1000),
      });
      this.dos.set(rootId, d);
    }
    return d;
  }

  async fetch(request: Request): Promise<Response> {
    const body = await request.arrayBuffer();
    const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
    const url = new URL(request.url);
    const rootSeg = /^\/v1\/roots\/([^/]+)\//.exec(url.pathname)?.[1] ?? "";
    const d = this.do(rootSeg);
    const hres = handleRequest(toHttpRequest(request, body, ip), {
      registry: { lookup: (r) => (r === rootSeg ? d : null), all: () => [d] },
      metrics, limiter, limits: LIMITS,
    });
    return toFetchResponse(hres);
  }
}
