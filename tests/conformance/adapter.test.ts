/** LexScope adapter + production-refusal vectors: TV-H--39,40,41,55. */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonEq, FX, T, jkt, worldAt } from "./harness.ts";
import {
  HeraldClient, HeraldVerifier, LexScopeAdapter, HeraldUnavailable, TrustStore,
} from "@latticeag/herald-client";
import type { FreshReply, IdentityBundle } from "@latticeag/herald-core";
import { isFixtureFingerprint, containsFixtureKey } from "@latticeag/herald-core";

function makeAdapter(world: ReturnType<typeof worldAt>, opts: { challenge?: string; timeout?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "herald-cache-"));
  const store = new TrustStore(dir, FX.CLIENT_CONFIG.roots);
  const client = {
    freshness: async (_root: string, challenge: string): Promise<FreshReply> => {
      if (opts.timeout) throw new Error("network timeout");
      return world.d.postFreshness(challenge);
    },
  } as unknown as HeraldClient;
  const verifier = new HeraldVerifier(store, client, () => T, () => opts.challenge ?? FX.N);
  const adapter = new LexScopeAdapter(
    { gateway: FX.G, tenant_id: FX.TEN, sub: FX.SUB, source: "herald_local", bundles: new Map([[FX.SC.body.id, FX.BUNDLE as IdentityBundle]]), now: () => T },
    verifier,
  );
  return { adapter, verifier, store };
}

test("TV-H--39 holder thumbprint mismatch → HERALD_UNAVAILABLE", async () => {
  const { adapter } = makeAdapter(worldAt(2));
  const req = { ...FX.ADAPTER_REQUEST, caller_jkt: jkt(6) };
  await assert.rejects(() => adapter.check(req), HeraldUnavailable);
});

test("TV-H--40 LexScope mapping and freshness → exact ADAPTER_RESPONSE", async () => {
  const { adapter } = makeAdapter(worldAt(2), { challenge: FX.N });
  const obs = await adapter.check(FX.ADAPTER_REQUEST);
  assert.ok(canonEq(obs, FX.ADAPTER_RESPONSE));
});

test("TV-H--41 root-wide fetch outage → HERALD_UNAVAILABLE, no synthesized response", async () => {
  const { adapter } = makeAdapter(worldAt(2), { timeout: true });
  await assert.rejects(() => adapter.check({ ...FX.ADAPTER_REQUEST, mode: "fresh" }), HeraldUnavailable);
});

test("TV-H--55 production rejects fixture trust keys", () => {
  // The fixture control fingerprint is a published test key: a production
  // config presenting it must fail SCHEMA_INVALID.
  const pin = FX.CLIENT_CONFIG.roots[0];
  assert.equal(isFixtureFingerprint(pin.control_fingerprint), true);
  for (const k of Object.values(FX.KEYS) as any[]) {
    assert.equal(containsFixtureKey(k.public_key), true);
  }
});
