/**
 * Verify wrapper (spec §7.1): serializes frontier updates and challenge
 * consumption under the per-root lock; persists frontier/bits/status durably.
 * The pure verify() never touches this state itself.
 */

import {
  verifyWithContext, newChallenge,
} from "@latticeag/herald-core";
import type {
  IdentityBundle, Fresh, Signed, Status, TrustContext, VerifyResult,
} from "@latticeag/herald-core";
import type { TrustStore, RootCacheState } from "./store.ts";
import type { HeraldClient } from "./client.ts";

export class HeraldVerifier {
  private store: TrustStore;
  private client: HeraldClient;
  private nowFn: () => number;
  private challengeFn: () => string;
  constructor(store: TrustStore, client: HeraldClient, nowFn?: () => number, challengeFn?: () => string) {
    this.store = store;
    this.client = client;
    this.nowFn = nowFn ?? (() => Math.floor(Date.now() / 1000));
    this.challengeFn = challengeFn ?? newChallenge;
  }

  /**
   * Bounded-cache verify against a supplied (already retrieved) status.
   * `received_age_s` is the monotonic age since the status was fetched.
   */
  async verifyBounded(
    bundle: IdentityBundle, status: Signed<Status>, receivedAgeS: number,
  ): Promise<VerifyResult> {
    const root = bundle.roots[0]?.body.root ?? "";
    return this.store.locked(root, () => {
      const ctx = this.store.context(root, { received_age_s: receivedAgeS });
      const r = verifyWithContext(
        { bundle, status, fresh: null, challenge: null, now: this.nowFn(), mode: "bounded_cache" },
        ctx,
      );
      this.persist(root, ctx, status);
      return r;
    });
  }

  /**
   * Fresh verify: generates an unpredictable challenge, performs the
   * authoritative freshness read, consumes the challenge exactly once.
   */
  async verifyFresh(bundle: IdentityBundle): Promise<VerifyResult> {
    const root = bundle.roots[0]?.body.root ?? "";
    return this.store.locked(root, async () => {
      const challenge = this.challengeFn();
      const reply = await this.client.freshness(root, challenge);
      const ctx = this.store.context(root, { challenge, consumed: false });
      const r = verifyWithContext(
        { bundle, status: reply.status, fresh: reply.fresh, challenge, now: this.nowFn(), mode: "fresh" },
        ctx,
      );
      this.persist(root, ctx, reply.status);
      return r;
    });
  }

  private persist(root: string, ctx: TrustContext, status: Signed<Status>): void {
    const frontier = ctx.frontiers.find((f) => f.root === root) ?? null;
    const known = ctx.known_revocations.find((k) => k.root === root);
    const state: RootCacheState = {
      frontier,
      bits: known?.bits ?? null,
      status,
      state: ctx.cache_state ?? "EMPTY",
    };
    this.store.saveFrontier(root, state);
    this.store.saveStatus(root, status);
  }
}
