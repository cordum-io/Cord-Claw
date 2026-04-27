#!/usr/bin/env bash
set -euo pipefail

# Verifies the CordClaw pack DSL documents at least one shadow rule using the
# top-level `enforce: false` knob and that the static pack validator accepts the
# resulting policy fragment. This intentionally fails until step 5 lands the
# example shadow rule in pack/policies/openclaw-safety.yaml.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_BIN="${PYTHON:-python}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PYTHON_BIN=python3
fi

"$PYTHON_BIN" - "$ROOT" <<'PY'
from pathlib import Path
import sys
import yaml

root = Path(sys.argv[1])
policy_path = root / "pack" / "policies" / "openclaw-safety.yaml"
with policy_path.open("r", encoding="utf-8") as f:
    policy = yaml.safe_load(f)

rules = policy.get("rules") or []
shadow_rules = [rule for rule in rules if isinstance(rule, dict) and rule.get("enforce") is False]
if not shadow_rules:
    raise SystemExit("expected at least one openclaw-safety rule with top-level enforce: false")

ids = {str(rule.get("id", "")) for rule in shadow_rules}
if "openclaw-shadow-strict-web-fetch" not in ids:
    raise SystemExit("expected shadow example rule id openclaw-shadow-strict-web-fetch")

for rule in shadow_rules:
    if "description" in rule:
        raise SystemExit(f"shadow rule {rule.get('id')} must not use top-level description")
    if not isinstance(rule.get("match"), dict):
        raise SystemExit(f"shadow rule {rule.get('id')} must include match object")
    if str(rule.get("decision", "")).lower() not in {"allow", "deny", "require_approval", "allow_with_constraints"}:
        raise SystemExit(f"shadow rule {rule.get('id')} has unsupported decision {rule.get('decision')!r}")

print(f"[pack-shadow-test] OK: found {len(shadow_rules)} shadow rule(s): {sorted(ids)}")
PY

"$PYTHON_BIN" "$ROOT/pack/tests/verify_pack.py"
