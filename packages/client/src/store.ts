/**
 * Durable trust/cache store (spec §7.1 wrapper state, §11 file layout):
 *   <cache_dir>/<root>/frontier.json — {seq, log_hash, root_epoch, bits, state}
 *   <cache_dir>/<root>/status.json   — retained Signed<Status> snapshot
 * Atomically replaced (tmp+rename) under an exclusive per-root in-process lock.
 */

import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync, openSync, closeSync, unlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import type { Frontier, RootPin, Status, Signed, TrustContext } from "@latticeag/herald-core";

export interface RootCacheState {
  frontier: Frontier | null;
  bits: string | null;           // accumulated known-revocation bitset
  status: Signed<Status> | null; // retained status snapshot
  state: "EMPTY" | "USABLE" | "STALE" | "FORKED" | "DISABLED";
}

interface FrontierFile {
  v: 1;
  seq: string;
  log_hash: string;
  root_epoch: string;
  bits: string;
  state: RootCacheState["state"];
}

export class TrustStore {
  private cacheDir: string;
  private pins: RootPin[];
  private locks = new Map<string, Promise<void>>();

  constructor(cacheDir: string, pins: RootPin[]) {
    this.cacheDir = cacheDir;
    this.pins = pins;
  }

  private dir(root: string): string {
    return join(this.cacheDir, root);
  }
  private frontierPath(root: string): string {
    return join(this.dir(root), "frontier.json");
  }
  private statusPath(root: string): string {
    return join(this.dir(root), "status.json");
  }

  load(root: string): RootCacheState {
    let f: FrontierFile | null = null;
    try {
      const raw = JSON.parse(readFileSync(this.frontierPath(root), "utf8"));
      if (raw && raw.v === 1 && typeof raw.seq === "string") f = raw as FrontierFile;
    } catch { /* absent/corrupt → EMPTY */ }
    let status: Signed<Status> | null = null;
    try {
      const raw = JSON.parse(readFileSync(this.statusPath(root), "utf8"));
      if (raw && raw.v === undefined && raw.body) status = raw as Signed<Status>;
      else if (raw && raw.body) status = raw as Signed<Status>;
    } catch { /* absent */ }
    if (!f) return { frontier: null, bits: null, status, state: "EMPTY" };
    return {
      frontier: { root, seq: f.seq, log_hash: f.log_hash, root_epoch: f.root_epoch },
      bits: f.bits,
      status,
      state: f.state,
    };
  }

  /** Atomic replace (write tmp + rename) of the frontier file. */
  saveFrontier(root: string, st: RootCacheState): void {
    mkdirSync(this.dir(root), { recursive: true });
    const ff: FrontierFile = {
      v: 1,
      seq: st.frontier?.seq ?? "0",
      log_hash: st.frontier?.log_hash ?? "0".repeat(64),
      root_epoch: st.frontier?.root_epoch ?? "0",
      bits: st.bits ?? "",
      state: st.state,
    };
    const tmp = this.frontierPath(root) + `.tmp-${process.pid}`;
    writeFileSync(tmp, JSON.stringify(ff), { mode: 0o600 });
    renameSync(tmp, this.frontierPath(root));
  }

  saveStatus(root: string, status: Signed<Status>): void {
    mkdirSync(this.dir(root), { recursive: true });
    const tmp = this.statusPath(root) + `.tmp-${process.pid}`;
    writeFileSync(tmp, JSON.stringify(status), { mode: 0o600 });
    renameSync(tmp, this.statusPath(root));
  }

  /** Serialize a mutation under the per-root lock (challenge + frontier). */
  async locked<T>(root: string, fn: () => T | Promise<T>): Promise<T> {
    const prev = this.locks.get(root) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((r) => (release = r));
    this.locks.set(root, prev.then(() => next));
    await prev;
    try {
      return await fn();
    } finally {
      release();
      if (this.locks.get(root) === next) this.locks.delete(root);
    }
  }

  /** Build a TrustContext snapshot for verify(). */
  context(root: string, opts: { received_age_s?: number; challenge?: string | null; consumed?: boolean } = {}): TrustContext {
    const st = this.load(root);
    return {
      pins: this.pins,
      frontiers: st.frontier ? [st.frontier] : [],
      known_revocations: st.bits !== null && st.bits !== "" ? [{ root, bits: st.bits }] : [],
      received_age_s: opts.received_age_s ?? 0,
      challenge_outstanding: opts.challenge ?? null,
      challenge_consumed: opts.consumed ?? false,
      cache_state: st.state,
    };
  }

  disable(root: string): void {
    const st = this.load(root);
    st.state = "DISABLED";
    this.saveFrontier(root, st);
  }
}
