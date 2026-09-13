#!/usr/bin/env bash
# Live CLI smoke: mint a development playground, boot the registry, and drive
# the full happy path over HTTP. Exits non-zero on the first failure.
set -euo pipefail

ROOT="hr_000000000000000000001"
PORT="${SMOKE_PORT:-8931}"
DIR="$(mktemp -d)"
trap 'kill %1 2>/dev/null || true; rm -rf "$DIR"' EXIT

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
HERALD="node $REPO/packages/cli/src/herald.ts"
CFG="--config $DIR/client.json --json"

echo "== mint playground =="
node "$REPO/tests/smoke/mint.ts" "$DIR"

echo "== config check =="
$HERALD config check $CFG | grep -q '"valid":true'

echo "== root init =="
$HERALD root init $CFG --document "$DIR/genesis.json" --state "$DIR/state" | grep -q '"kind":"RootCreated"'

echo "== serve =="
$HERALD serve --config "$DIR/client.json" --port "$PORT" >/dev/null 2>&1 &
sleep 1.5
curl -sf http://localhost:$PORT/healthz | grep -q '"status":"alive"'
curl -sf http://localhost:$PORT/readyz | grep -q '"status":"ready"'

echo "== root inspect =="
$HERALD root inspect $CFG --root "$ROOT" | grep -q '"epoch":"1"'

echo "== enroll / issue / rotate =="
$HERALD binding enroll $CFG --command "$DIR/cmd-enroll.json" | grep -q '"kind":"BindingEnrolled"'
$HERALD card issue    $CFG --command "$DIR/cmd-issue.json"  | grep -q '"kind":"CardIssued"'
$HERALD card rotate   $CFG --command "$DIR/cmd-rotate.json" | grep -q '"kind":"CardRotated"'

echo "== queries =="
$HERALD resolve $CFG --query "$DIR/q-resolve.json" > "$DIR/resolve-out.json"
grep -q '"record"' "$DIR/resolve-out.json"
$HERALD receipt $CFG --query "$DIR/q-receipt.json" | grep -q '"kind":"CardIssued"'

echo "== status fetch + verify =="
$HERALD status fetch $CFG --root "$ROOT" --out "$DIR/status.json" >/dev/null
node --input-type=module -e "
import { readFileSync, writeFileSync } from 'node:fs';
const r = JSON.parse(readFileSync('$DIR/resolve-out.json', 'utf8'));
const roots = JSON.parse(readFileSync('$DIR/roots.json', 'utf8'));
const bundle = { v: 1, binding: r.bundle.binding, card: r.bundle.card,
  prior_card: r.bundle.prior_card ?? null, receipt: r.bundle.receipt,
  roots, rotation: r.bundle.rotation ?? null };
writeFileSync('$DIR/bundle.json', JSON.stringify(bundle) + '\n');
"
$HERALD verify $CFG --bundle "$DIR/bundle.json" --status "$DIR/status.json" | grep -q '"decision":"allow"'
$HERALD verify fresh $CFG --bundle "$DIR/bundle.json" --root "$ROOT" | grep -q '"decision":"allow"'

echo "== audit =="
curl -sf "http://localhost:$PORT/v1/roots/$ROOT/events?after=0&limit=100" > "$DIR/page.json"
node --input-type=module -e "
import { readFileSync, writeFileSync } from 'node:fs';
const p = JSON.parse(readFileSync('$DIR/page.json', 'utf8'));
writeFileSync('$DIR/events.json', JSON.stringify(p.events) + '\n');
"
$HERALD audit verify $CFG --events "$DIR/events.json" --roots "$DIR/roots.json" | grep -q '"valid":true'

echo "== doctor =="
$HERALD doctor $CFG --root "$ROOT" | grep -q '"ready":true'

echo "SMOKE OK"
