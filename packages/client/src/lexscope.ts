/**
 * LexScope private adapter (spec §10). Runs inside the gateway trust
 * boundary: verifies a retained identity bundle against whole-root status or
 * an authoritative fresh read, checks gateway/tenant/sub binding and
 * caller_jkt, and returns a HeraldObservation — or throws
 * HeraldUnavailable on any non-active outcome (fail-closed).
 *
 * The external LexScope challenge is echoed only after validation; the
 * internal Herald freshness challenge is an independent CSPRNG nonce.
 */

import { callerJkt, digest, isCardId } from "@latticeag/herald-core";
import type {
  HeraldCheck, HeraldObservation, IdentityBundle, Signed, Status, JsonObject,
} from "@latticeag/herald-core";
import type { HeraldVerifier } from "./wrap.ts";

export class HeraldUnavailable extends Error {
  readonly code = "HERALD_UNAVAILABLE";
  readonly detail: string;
  constructor(detail: string) {
    super(`HERALD_UNAVAILABLE: ${detail}`);
    this.detail = detail;
  }
}

export interface LexScopeAdapterConfig {
  gateway: string;            // expected gateway id (lsg_)
  tenant_id: string;          // expected tenant (ltn_)
  sub: string;                // expected subject (lsu_)
  source: string;             // adapter source tag, e.g. "herald_local"
  bundles: Map<string, IdentityBundle>; // retained bundles keyed by card_id
  now?: () => number;
}

export class LexScopeAdapter {
  private cfg: LexScopeAdapterConfig;
  private verifier: HeraldVerifier;
  private lastStatus = new Map<string, { status: Signed<Status>; receivedAt: number }>();

  constructor(cfg: LexScopeAdapterConfig, verifier: HeraldVerifier) {
    this.cfg = cfg;
    this.verifier = verifier;
  }

  /** Record a freshly retrieved status snapshot for bounded_cache reads. */
  noteStatus(root: string, status: Signed<Status>): void {
    this.lastStatus.set(root, { status, receivedAt: Math.floor(Date.now() / 1000) });
  }

  /**
   * Check a gateway admission. Returns a HeraldObservation with
   * status "active" | "revoked"; every other outcome throws
   * HeraldUnavailable (expired, frozen, unknown, untrusted, mismatched,
   * forked, or unavailable evidence).
   */
  async check(req: HeraldCheck): Promise<HeraldObservation> {
    const now = (this.cfg.now ?? (() => Math.floor(Date.now() / 1000)))();
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(req.binding.source) || req.binding.source !== this.cfg.source)
      throw new HeraldUnavailable("untrusted binding source");
    if (req.tenant_id !== this.cfg.tenant_id || req.sub !== this.cfg.sub)
      throw new HeraldUnavailable("tenant/sub mismatch");
    if (!isCardId(req.binding.card_id)) throw new HeraldUnavailable("card id form");
    const bundle = this.cfg.bundles.get(req.binding.card_id);
    if (!bundle) throw new HeraldUnavailable("no retained bundle");
    const card = bundle.card.body;
    if (digest("CARD", card) !== req.binding.card_hash) throw new HeraldUnavailable("card hash mismatch");
    if (card.id !== req.binding.card_id) throw new HeraldUnavailable("card id mismatch");
    const entry = card.gateway_bindings.find(
      (g) => g.gateway === this.cfg.gateway && g.tenant_id === req.tenant_id && g.sub === req.sub,
    );
    if (!entry) throw new HeraldUnavailable("no matching gateway/tenant/sub entry");
    if (entry.caller_jkt !== req.caller_jkt) throw new HeraldUnavailable("caller_jkt mismatch");
    if (req.caller_jkt !== callerJkt(card.key.public_key)) throw new HeraldUnavailable("caller_jkt mismatch");

    // verifyFresh derives a fresh internal Herald hn_ CSPRNG challenge and
    // retains the association inside the wrapper; the external LexScope
    // challenge is echoed only after validation (below).
    let result;
    try {
      result = req.mode === "fresh"
        ? await this.verifier.verifyFresh(bundle)
        : await this.verifyBounded(bundle, now);
    } catch {
      throw new HeraldUnavailable("evidence unavailable");
    }
    if (result.decision === "allow") {
      return {
        v: 1, challenge: req.challenge, card_hash: result.card_hash, sub: req.sub,
        caller_jkt: req.caller_jkt, status: "active", checked_at: result.checked_at,
        valid_until: result.valid_until, evidence_hash: result.evidence_hash,
      };
    }
    if (result.code === "CARD_REVOKED") {
      // Revocation is a definite observation, not an availability failure.
      const st = this.lastStatus.get(bundle.roots[0]!.body.root);
      const checked = st?.status.body.issued_at ?? now;
      return {
        v: 1, challenge: req.challenge, card_hash: req.binding.card_hash, sub: req.sub,
        caller_jkt: req.caller_jkt, status: "revoked", checked_at: checked,
        valid_until: checked + (req.mode === "fresh" ? 5 : 60),
        evidence_hash: digest("EVIDENCE", {
          bundle, status: st?.status ?? null, fresh: null,
        } as unknown as JsonObject),
      };
    }
    throw new HeraldUnavailable(result.code);
  }

  private async verifyBounded(bundle: IdentityBundle, now: number) {
    const root = bundle.roots[0]!.body.root;
    const cached = this.lastStatus.get(root);
    if (!cached) throw new HeraldUnavailable("no cached status");
    const age = Math.max(0, Math.ceil(now - cached.receivedAt));
    return this.verifier.verifyBounded(bundle, cached.status, age);
  }
}
