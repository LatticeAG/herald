/**
 * HTTP surface (spec §8): exact path grammar, ordered error precedence,
 * content types, cache policies, rate limits, health/readiness/metrics.
 *
 * Path grammar (percent escapes, repeated slashes, dot segments rejected):
 *   GET  /v1/roots/{root}/document
 *   GET  /v1/roots/{root}/documents?after&limit
 *   GET  /v1/roots/{root}/status
 *   POST /v1/roots/{root}/freshness
 *   GET  /v1/roots/{root}/events?after&limit
 *   POST /v1/roots/{root}/commands
 *   POST /v1/roots/{root}/queries
 *   GET  /healthz
 *   GET  /readyz
 *   GET  /metrics
 */

import {
  err, HeraldError, isNonce, isRootId, LIMITS_ORDINARY, parseJsonStrict,
  validate, canonicalize, ERROR_HTTP, isRetryable,
} from "@latticeag/herald-core";
import type { FreshRequest, JsonObject, JsonValue, Signed, Command } from "@latticeag/herald-core";
import type { RootDO } from "./rootdo.ts";

export interface HttpRequest {
  method: string;
  path: string;
  query: Map<string, string>;
  headers: Map<string, string>;
  body: Uint8Array;
  ip: string;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

const JSON_CT = { "content-type": "application/json" };

export interface Registry {
  /** Resolve the DO for a pinned root, or null when not provisioned. */
  lookup(root: string): RootDO | null;
  /** All provisioned roots (for the global readiness probe). */
  all(): RootDO[];
}

// ---------------------------------------------------------------------------
// Error mapping (§8.2)

export function errorBody(code: string): JsonValue {
  return { v: 1, error: { code, retryable: isRetryable(code) } };
}

export function statusFor(code: string): number {
  return ERROR_HTTP[code] ?? 503;
}

// ---------------------------------------------------------------------------
// Metrics (§14)

export type RouteClass =
  | "document" | "documents" | "status" | "freshness" | "events"
  | "commands" | "queries" | "healthz" | "readyz" | "metrics" | "unknown";

export class Metrics {
  private counters = new Map<string, number>();
  private histograms = new Map<string, { count: number; sum: number; buckets: number[] }>();
  gauges: Record<string, number> = { ready: 0, committed_events: 0, allocated_slots: 0, live_agents: 0, backup_lag_events: 0, cache_frontier_seq: 0 };

  private key(name: string, labels: Record<string, string>): string {
    const l = Object.keys(labels).sort().map((k) => `${k}="${labels[k]}"`).join(",");
    return `${name}{${l}}`;
  }
  inc(name: string, labels: Record<string, string>, by = 1): void {
    const k = this.key(name, labels);
    this.counters.set(k, (this.counters.get(k) ?? 0) + by);
  }
  observe(name: string, labels: Record<string, string>, v: number): void {
    const k = this.key(name, labels);
    let h = this.histograms.get(k);
    if (!h) { h = { count: 0, sum: 0, buckets: [0, 0, 0, 0, 0, 0] }; this.histograms.set(k, h); }
    h.count++; h.sum += v;
    const bounds = [0.005, 0.05, 0.5, 5, 50];
    for (let i = 0; i < h.buckets.length; i++) if (v <= (bounds[i] ?? Infinity)) h.buckets[i]!++;
  }
  render(): string {
    const lines: string[] = [];
    for (const [k, v] of [...this.counters.entries()].sort()) lines.push(`${k} ${v}`);
    for (const [k, h] of [...this.histograms.entries()].sort()) {
      const base = k.slice(0, -1);
      const bounds = [0.005, 0.05, 0.5, 5, 50];
      for (let i = 0; i < bounds.length; i++) lines.push(`${base},le="${bounds[i]}"} ${h.buckets[i]!}`);
      lines.push(`${base},le="+Inf"} ${h.count}`);
      lines.push(`${k.slice(0, k.indexOf("{"))}_sum{${k.slice(k.indexOf("{") + 1)} ${h.sum}`);
      lines.push(`${k.slice(0, k.indexOf("{"))}_count{${k.slice(k.indexOf("{") + 1)} ${h.count}`);
    }
    for (const [k, v] of Object.entries(this.gauges)) lines.push(`herald_${k} ${v}`);
    return lines.join("\n") + "\n";
  }
}

// ---------------------------------------------------------------------------
// Rate limiting (§8)

export class RateLimiter {
  private buckets = new Map<string, { count: number; reset: number }>();
  private nowMs: () => number;
  constructor(nowMs: () => number = () => Date.now()) {
    this.nowMs = nowMs;
  }
  /** Returns true when allowed under `limit` per minute. */
  allow(key: string, limit: number): boolean {
    const t = this.nowMs();
    const b = this.buckets.get(key);
    if (!b || t >= b.reset) {
      this.buckets.set(key, { count: 1, reset: t + 60_000 });
      return true;
    }
    if (b.count >= limit) return false;
    b.count++;
    return true;
  }
}

// ---------------------------------------------------------------------------
// Request handling

export interface HandlerOptions {
  registry: Registry;
  metrics: Metrics;
  limiter: RateLimiter;
  limits: { publicGetPerMin: number; publicFreshPerMin: number; writePerActorPerMin: number; revocationReservePerMin: number };
  maxBodyBytes?: number;
  onServeError?: (e: unknown) => void;
}

type Route =
  | { cls: RouteClass; kind: "document" | "documents" | "status" | "freshness" | "events" | "commands" | "queries"; root: string }
  | { cls: RouteClass; kind: "healthz" | "readyz" | "metrics"; root?: undefined };

const ROUTES: { kind: string; method: string; cls: RouteClass }[] = [
  { kind: "document", method: "GET", cls: "document" },
  { kind: "documents", method: "GET", cls: "documents" },
  { kind: "status", method: "GET", cls: "status" },
  { kind: "freshness", method: "POST", cls: "freshness" },
  { kind: "events", method: "GET", cls: "events" },
  { kind: "commands", method: "POST", cls: "commands" },
  { kind: "queries", method: "POST", cls: "queries" },
];

const QUERY_PARAMS: Record<string, Set<string>> = {
  document: new Set(), status: new Set(), freshness: new Set(), commands: new Set(), queries: new Set(),
  documents: new Set(["after", "limit"]), events: new Set(["after", "limit"]),
};

function jsonResponse(status: number, body: JsonValue, extraHeaders: Record<string, string> = {}): HttpResponse {
  return {
    status,
    headers: { ...JSON_CT, "cache-control": "no-store", ...extraHeaders },
    body: canonicalize(body as JsonObject),
  };
}

function fail(code: string, metrics: Metrics, cls: RouteClass): HttpResponse {
  const status = statusFor(code);
  metrics.inc("herald_requests_total", { route_class: cls, code });
  metrics.inc("herald_rejections_total", { code });
  const headers: Record<string, string> = {};
  if (["RATE_LIMITED", "UNAVAILABLE", "STORAGE_BUSY"].includes(code)) headers["retry-after"] = "1";
  return jsonResponse(status, errorBody(code), headers);
}

/**
 * Path parse with spec-ordered errors:
 * unknown route → ROUTE_UNKNOWN (even under wrong method); known route with
 * wrong method → 405; malformed hr_ segment → ID_INVALID; unknown query
 * parameters → SCHEMA_INVALID.
 */
function parseRoute(path: string): { route: Route } | { error: string } {
  if (path === "/healthz") return { route: { cls: "healthz", kind: "healthz" } };
  if (path === "/readyz") return { route: { cls: "readyz", kind: "readyz" } };
  if (path === "/metrics") return { route: { cls: "metrics", kind: "metrics" } };
  const m = /^\/v1\/roots\/([^/]+)\/([^/?]+)$/.exec(path);
  if (!m) return { error: "ROUTE_UNKNOWN" };
  const [, rootSeg, leaf] = m;
  const rt = ROUTES.find((r) => r.kind === leaf);
  if (!rt) return { error: "ROUTE_UNKNOWN" };
  if (!isRootId(rootSeg)) return { error: "ID_INVALID" };
  return {
    route: {
      cls: rt.cls,
      kind: rt.kind as "document" | "documents" | "status" | "freshness" | "events" | "commands" | "queries",
      root: rootSeg,
    },
  };
}

export function handleRequest(req: HttpRequest, opts: HandlerOptions): HttpResponse {
  const { metrics, limiter, limits } = opts;
  const started = Date.now();
  let cls: RouteClass = "unknown";
  const done = (resp: HttpResponse, code?: string): HttpResponse => {
    if (code !== undefined && resp.status < 400) metrics.inc("herald_requests_total", { route_class: cls, code });
    metrics.observe("herald_verify_ms", { route_class: cls }, (Date.now() - started));
    return resp;
  };
  try {
    // Path order (§8.2): malformed path → ROUTE_UNKNOWN; unknown leaf →
    // ROUTE_UNKNOWN even under wrong method; known leaf wrong method → 405.
    const pr = parseRoute(req.path);
    if ("error" in pr) {
      cls = "unknown";
      if (pr.error === "ID_INVALID") cls = "unknown";
      return done(fail(pr.error, metrics, cls));
    }
    const route = pr.route;
    cls = route.cls;

    if (route.kind === "healthz") {
      if (req.method !== "GET") return done(fail("METHOD_NOT_ALLOWED", metrics, cls));
      metrics.inc("herald_requests_total", { route_class: cls, code: "OK" });
      return done(jsonResponse(200, { v: 1, status: "alive" }));
    }
    if (route.kind === "readyz") {
      if (req.method !== "GET") return done(fail("METHOD_NOT_ALLOWED", metrics, cls));
      return done(handleReadyz(opts.registry.all(), metrics));
    }
    if (route.kind === "metrics") {
      if (req.method !== "GET") return done(fail("METHOD_NOT_ALLOWED", metrics, cls));
      metrics.inc("herald_requests_total", { route_class: cls, code: "OK" });
      return {
        status: 200,
        headers: { "content-type": "text/plain; version=0.0.4", "cache-control": "no-store" },
        body: new TextEncoder().encode(metrics.render()),
      };
    }

    // Root-scoped routes: method check comes before provisioning.
    const expected = ROUTES.find((r) => r.kind === route.kind)!;
    if (req.method !== expected.method) {
      return done(fail("METHOD_NOT_ALLOWED", metrics, cls));
    }

    // Unknown query parameters → SCHEMA_INVALID; malformed counters → SCHEMA_INVALID.
    const allowed = QUERY_PARAMS[route.kind]!;
    for (const k of req.query.keys()) {
      if (!allowed.has(k)) return done(fail("SCHEMA_INVALID", metrics, cls));
    }
    const afterParam = req.query.get("after");
    const limitParam = req.query.get("limit");
    let after = 0n, limit = 100;
    if (afterParam !== undefined) {
      if (!/^[0-9]{1,20}$/.test(afterParam)) return done(fail("SCHEMA_INVALID", metrics, cls));
      after = BigInt(afterParam);
    }
    if (limitParam !== undefined) {
      if (!/^[0-9]{1,9}$/.test(limitParam)) return done(fail("SCHEMA_INVALID", metrics, cls));
      limit = Math.max(1, Math.min(1000, Number(limitParam)));
    }

    const maxBody = opts.maxBodyBytes ?? LIMITS_ORDINARY.maxBytes;
    if (req.body.length > maxBody) return done(fail("TOO_LARGE", metrics, cls));

    const root = route.root;
    if (root === undefined) return done(fail("ROUTE_UNKNOWN", metrics, cls)); // unreachable: kind-narrowed
    const dos = opts.registry;
    const d = dos.lookup(root);

    // Rate limits before dispatch (after path checks, before signature work).
    if (route.kind === "document" || route.kind === "documents" || route.kind === "status" || route.kind === "events") {
      if (!limiter.allow(`pub:${req.ip}`, limits.publicGetPerMin)) return done(fail("RATE_LIMITED", metrics, cls));
    }
    if (route.kind === "freshness") {
      if (!limiter.allow(`fresh:${req.ip}`, limits.publicFreshPerMin)) return done(fail("RATE_LIMITED", metrics, cls));
    }

    switch (route.kind) {
      case "document": {
        if (!d) return done(fail("ROOT_UNKNOWN", metrics, cls));
        const body = d.getDocument();
        return done(jsonResponse(200, body as unknown as JsonValue, { "cache-control": "no-store" }), "OK");
      }
      case "documents": {
        if (!d) return done(fail("ROOT_UNKNOWN", metrics, cls));
        const body = d.getDocuments(after, Math.min(limit, 64));
        return done(jsonResponse(200, body as unknown as JsonValue, { "cache-control": "no-store" }), "OK");
      }
      case "status": {
        if (!d) return done(fail("ROOT_UNKNOWN", metrics, cls));
        const body = d.getStatus();
        return done(jsonResponse(200, body as unknown as JsonValue, { "cache-control": "public,max-age=30,must-revalidate" }), "OK");
      }
      case "events": {
        if (!d) return done(fail("ROOT_UNKNOWN", metrics, cls));
        const body = d.getEvents(after, Math.min(limit, 100));
        return done(jsonResponse(200, body as unknown as JsonValue, { "cache-control": "no-store" }), "OK");
      }
      case "freshness": {
        if (!d) return done(fail("ROOT_UNKNOWN", metrics, cls));
        const parsed = parseJsonStrict(req.body, LIMITS_ORDINARY);
        if (!parsed.ok) return done(fail(parsed.code, metrics, cls));
        const badSchema = validate("FreshRequest", parsed.value);
        if (badSchema !== null) return done(fail(badSchema, metrics, cls));
        const fr = parsed.value as unknown as FreshRequest;
        const body = d.postFreshness(fr.challenge);
        metrics.inc("herald_requests_total", { route_class: cls, code: "OK" });
        return done(jsonResponse(200, body as unknown as JsonValue), "OK");
      }
      case "commands": {
        // Parse for actor/rate-limit routing; full validation in the DO.
        const peek = parseJsonStrict(req.body, LIMITS_ORDINARY);
        if (!peek.ok) return done(fail(peek.code, metrics, cls));
        const badSchema = validate("Command", peek.value);
        if (badSchema !== null) return done(fail(badSchema, metrics, cls));
        const cmd = peek.value as unknown as Signed<Command>;
        if (cmd.body.root !== root) return done(fail("METHOD_TARGET_INVALID", metrics, cls));
        if (!d) return done(fail("ROOT_UNKNOWN", metrics, cls));
        const isRevocation = cmd.body.action.kind === "revoke" || cmd.body.action.kind === "root.freeze";
        const lane = isRevocation ? `rev:${cmd.body.actor}` : `w:${cmd.body.actor}`;
        const lim = isRevocation ? limits.revocationReservePerMin : limits.writePerActorPerMin;
        if (!limiter.allow(lane, lim)) return done(fail("RATE_LIMITED", metrics, cls));
        const reply = d.submitCommand(req.body);
        metrics.inc("herald_mutations_total", { kind: reply.receipt.body.kind });
        if (reply.receipt.body.kind === "AgentRevoked" || reply.receipt.body.kind === "CardRevoked" ||
            reply.receipt.body.kind === "BindingRevoked")
          metrics.inc("herald_revocations_total", { kind: reply.receipt.body.kind });
        metrics.inc("herald_requests_total", { route_class: cls, code: "OK" });
        return done(jsonResponse(200, reply as unknown as JsonValue), "OK");
      }
      case "queries": {
        const peek = parseJsonStrict(req.body, LIMITS_ORDINARY);
        if (!peek.ok) return done(fail(peek.code, metrics, cls));
        const badSchema = validate("Query", peek.value);
        if (badSchema !== null) return done(fail(badSchema, metrics, cls));
        const q = peek.value as JsonObject;
        const qb = q["body"] as JsonObject;
        if (qb["root"] !== root) return done(fail("METHOD_TARGET_INVALID", metrics, cls));
        if (!d) return done(fail("ROOT_UNKNOWN", metrics, cls));
        const reply = d.submitQuery(req.body);
        metrics.inc("herald_requests_total", { route_class: cls, code: "OK" });
        return done(jsonResponse(200, reply as JsonValue), "OK");
      }
    }
    return done(fail("ROUTE_UNKNOWN", metrics, cls));
  } catch (e) {
    const code = e instanceof HeraldError ? e.code : "UNAVAILABLE";
    if (!(e instanceof HeraldError)) opts.onServeError?.(e);
    return done(fail(code, metrics, cls));
  }
}

/** Readiness across all provisioned roots; any failure → 503. */
export function handleReadyz(dos: RootDO[], metrics: Metrics): HttpResponse {
  for (const d of dos) {
    const r = d.readiness();
    metrics.gauges.ready = r.status === "ready" ? 1 : 0;
    if (r.status !== "ready") {
      metrics.inc("herald_requests_total", { route_class: "readyz", code: r.code });
      return jsonResponse(503, { v: 1, status: "not_ready", code: r.code });
    }
  }
  metrics.gauges.ready = 1;
  metrics.inc("herald_requests_total", { route_class: "readyz", code: "OK" });
  return jsonResponse(200, { v: 1, status: "ready", code: "OK" });
}
