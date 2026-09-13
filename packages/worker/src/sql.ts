/**
 * Minimal synchronous SQL adapter shared by the node:sqlite development
 * adapter and the Cloudflare Durable Object storage binding. All statements
 * are prepared/parameterized; no interpolated identifiers (spec §11).
 */

export type SqlParam = string | number | bigint | Uint8Array | null;
export type Row = Record<string, unknown>;

export interface SqlDb {
  run(sql: string, ...params: SqlParam[]): void;
  get(sql: string, ...params: SqlParam[]): Row | undefined;
  all(sql: string, ...params: SqlParam[]): Row[];
  exec(sql: string): void;
  /** Runs fn inside BEGIN IMMEDIATE/COMMIT, rolling back on throw. */
  transaction<T>(fn: () => T): T;
  close(): void;
}

import { DatabaseSync } from "node:sqlite";

export class NodeSqliteDb implements SqlDb {
  private db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode=WAL;");
    this.db.exec("PRAGMA synchronous=FULL;");
    this.db.exec("PRAGMA foreign_keys=ON;");
  }
  run(sql: string, ...params: SqlParam[]): void {
    this.db.prepare(sql).run(...(params as never[]));
  }
  get(sql: string, ...params: SqlParam[]): Row | undefined {
    return this.db.prepare(sql).get(...(params as never[])) as Row | undefined;
  }
  all(sql: string, ...params: SqlParam[]): Row[] {
    return this.db.prepare(sql).all(...(params as never[])) as Row[];
  }
  exec(sql: string): void {
    this.db.exec(sql);
  }
  transaction<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  close(): void {
    this.db.close();
  }
}

/**
 * Durable Object SQLite adapter (ctx.storage.sql). Uses the CF DO cursor API;
 * exercised through the same SqlDb surface as the development adapter.
 */
export interface DoSqlStorage {
  exec(sql: string, ...params: unknown[]): {
    toArray(): Record<string, unknown>[];
    one(): Record<string, unknown>;
  };
  transactionSync<T>(fn: () => T): T;
}

export class DoSqlDb implements SqlDb {
  private sql: DoSqlStorage;
  constructor(sql: DoSqlStorage) {
    this.sql = sql;
  }
  run(sql: string, ...params: SqlParam[]): void {
    this.sql.exec(sql, ...params);
  }
  get(sql: string, ...params: SqlParam[]): Row | undefined {
    const cur = this.sql.exec(sql, ...params);
    const rows = cur.toArray();
    return rows.length ? (rows[0] as Row) : undefined;
  }
  all(sql: string, ...params: SqlParam[]): Row[] {
    return this.sql.exec(sql, ...params).toArray() as Row[];
  }
  exec(sql: string): void {
    this.sql.exec(sql);
  }
  transaction<T>(fn: () => T): T {
    return this.sql.transactionSync(fn);
  }
  close(): void {}
}
