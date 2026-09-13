/**
 * Coherence check: generated JSON Schema artifacts (schemas/) must cover the
 * same wire types and closed field sets as the runtime validators.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FX } from "./conformance/harness.ts";

const dir = join(dirname(fileURLToPath(import.meta.url)), "../schemas");
const schemas = new Map(
  readdirSync(dir).filter((f) => f.endsWith(".schema.json"))
    .map((f) => [f.replace(/\.schema\.json$/, ""), JSON.parse(readFileSync(join(dir, f), "utf8"))]),
);

type J = Record<string, any>;

function sorted(xs: string[]): string[] { return [...xs].sort(); }

function fieldSetEq(doc: unknown, schema: J, path: string): void {
  if (schema.anyOf) {
    const ok = (schema.anyOf as J[]).some((s) => {
      try { fieldSetEq(doc, s, path); return true; } catch { return false; }
    });
    assert.ok(ok, `${path}: no anyOf branch matches`);
    return;
  }
  if (schema.oneOf) {
    const ok = (schema.oneOf as J[]).some((s) => {
      try { fieldSetEq(doc, s, path); return true; } catch { return false; }
    });
    assert.ok(ok, `${path}: no oneOf branch matches`);
    return;
  }
  if (typeof doc === "object" && doc !== null && !Array.isArray(doc)) {
    assert.equal(schema.type, "object", `${path}: schema is not object`);
    assert.equal(schema.additionalProperties, false, `${path}: not closed`);
    assert.deepEqual(sorted(schema.required as string[]), sorted(Object.keys(schema.properties as J)), `${path}: required != properties`);
    assert.deepEqual(sorted(Object.keys(doc as J)), sorted(schema.required as string[]), `${path}: field set mismatch`);
    for (const [k, v] of Object.entries(doc as J)) fieldSetEq(v, (schema.properties as J)[k], `${path}.${k}`);
    return;
  }
  if (Array.isArray(doc)) {
    assert.equal(schema.type, "array", `${path}: schema is not array`);
    for (const e of doc) fieldSetEq(e, schema.items as J, `${path}[]`);
  }
}

test("every runtime wire type has a generated schema artifact", () => {
  const expected = [
    "PublicKey", "Proof", "RootDocument", "SignedRootDocument", "HumanBinding",
    "SignedHumanBinding", "GatewayBinding", "AgentCard", "SignedAgentCard",
    "Capabilities", "Rotation", "SignedRotation", "Command", "Query",
    "AgentRecord", "Receipt", "IdentityBundle", "AuditEvent", "Status",
    "FreshRequest", "Fresh", "FreshReply", "LogPage", "RootHistoryReply",
    "MutationReply", "ResolveReply", "ExportReply", "ErrorReply", "HealthReply",
    "ReadinessReply", "Frontier", "RootPin", "ClientConfig", "ServerConfig",
    "KeyFile", "ExportSummary", "DoctorReply", "MigrationDescriptor",
    "HeraldCheck", "HeraldObservation",
  ];
  for (const name of expected) assert.ok(schemas.has(name), `missing schema ${name}`);
});

test("generated schemas match fixture field sets (closed objects)", () => {
  const cases: [string, unknown][] = [
    ["SignedRootDocument", FX.SR],
    ["HumanBinding", FX.B],
    ["AgentCard", FX.C],
    ["AgentCard", FX.C3],
    ["Rotation", FX.ROT],
    ["Status", FX.ST],
    ["AuditEvent", FX.E1],
    ["Command", FX.ENROLL],
    ["Command", FX.ROTATE],
    ["Query", FX.Q_RESOLVE],
    ["Query", FX.Q_EXPORT],
    ["IdentityBundle", FX.BUNDLE],
    ["FreshReply", FX.FRESH_REPLY],
    ["ClientConfig", FX.CLIENT_CONFIG],
    ["ServerConfig", FX.SERVER_CONFIG],
    ["Capabilities", FX.CAP],
  ];
  for (const [type, doc] of cases) {
    const s = schemas.get(type);
    assert.ok(s, `no schema for ${type}`);
    fieldSetEq(doc, s, type);
  }
});
