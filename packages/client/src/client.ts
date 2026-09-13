/**
 * @latticeag/herald-client — one-to-one HTTP wrappers (spec §9): submit,
 * query, root, rootHistory, status, freshness, events. No additional RPCs.
 */

import { parseJsonStrict, LIMITS_ORDINARY } from "@latticeag/herald-core";
import type {
  Signed, Command, Query, MutationReply, ResolveReply, ExportReply,
  RootDocument, RootHistoryReply, Status, FreshReply, LogPage, Receipt, JsonValue,
} from "@latticeag/herald-core";

export class HeraldHttpError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(`${status} ${code}`);
    this.status = status;
    this.code = code;
  }
}

export interface ClientOptions {
  origin: string;           // e.g. https://registry.example.test
  timeoutMs?: number;       // 100..10000, default 2000
  fetchFn?: typeof fetch;
}

export class HeraldClient {
  private origin: string;
  private timeoutMs: number;
  private fetchFn: typeof fetch;
  constructor(opts: ClientOptions) {
    this.origin = opts.origin.replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 2000;
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  private async call(method: string, path: string, body?: Uint8Array): Promise<JsonValue> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.timeoutMs);
    try {
      const init: RequestInit = { method, signal: ac.signal };
      if (body) {
        init.headers = { "content-type": "application/json" };
        init.body = body as unknown as NonNullable<RequestInit["body"]>;
      }
      const res = await this.fetchFn(`${this.origin}${path}`, init);
      const raw = new Uint8Array(await res.arrayBuffer());
      const parsed = parseJsonStrict(raw, { ...LIMITS_ORDINARY, maxBytes: 1 << 22 });
      const v = parsed.ok ? parsed.value : null;
      if (res.status < 200 || res.status >= 300) {
        const code = v && typeof v === "object" && !Array.isArray(v)
          ? ((v as Record<string, unknown>)["error"] as Record<string, unknown> | undefined)?.["code"]
          : undefined;
        throw new HeraldHttpError(res.status, typeof code === "string" ? code : "UNAVAILABLE");
      }
      return v as JsonValue;
    } finally {
      clearTimeout(t);
    }
  }

  submit(command: Signed<Command>): Promise<MutationReply> {
    return this.call("POST", `/v1/roots/${command.body.root}/commands`,
      new TextEncoder().encode(JSON.stringify(command))) as unknown as Promise<MutationReply>;
  }
  query(query: Signed<Query>): Promise<JsonValue> {
    return this.call("POST", `/v1/roots/${query.body.root}/queries`,
      new TextEncoder().encode(JSON.stringify(query)));
  }
  resolve(query: Signed<Query>): Promise<ResolveReply> { return this.query(query) as unknown as Promise<ResolveReply>; }
  exportAudit(query: Signed<Query>): Promise<ExportReply> { return this.query(query) as unknown as Promise<ExportReply>; }
  receipt(query: Signed<Query>): Promise<Signed<Receipt>> { return this.query(query) as unknown as Promise<Signed<Receipt>>; }
  root(rootId: string): Promise<Signed<RootDocument>> {
    return this.call("GET", `/v1/roots/${rootId}/document`) as unknown as Promise<Signed<RootDocument>>;
  }
  rootHistory(rootId: string, after = "0", limit = 64): Promise<RootHistoryReply> {
    return this.call("GET", `/v1/roots/${rootId}/documents?after=${after}&limit=${limit}`) as unknown as Promise<RootHistoryReply>;
  }
  status(rootId: string): Promise<Signed<Status>> {
    return this.call("GET", `/v1/roots/${rootId}/status`) as unknown as Promise<Signed<Status>>;
  }
  freshness(rootId: string, challenge: string): Promise<FreshReply> {
    const body = new TextEncoder().encode(JSON.stringify({ v: 1, challenge }));
    return this.call("POST", `/v1/roots/${rootId}/freshness`, body) as unknown as Promise<FreshReply>;
  }
  events(rootId: string, after = "0", limit = 100): Promise<LogPage> {
    return this.call("GET", `/v1/roots/${rootId}/events?after=${after}&limit=${limit}`) as unknown as Promise<LogPage>;
  }
}
