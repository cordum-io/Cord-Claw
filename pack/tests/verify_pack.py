#!/usr/bin/env python3
"""Static verification for CordClaw pack metadata and fixtures."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PACK_DIR = ROOT / "pack"
PACK_FILE = PACK_DIR / "pack.yaml"
SIM_FILE = PACK_DIR / "tests" / "policy-simulations.yaml"
ALLOWED_DECISIONS = {"ALLOW", "DENY", "THROTTLE", "REQUIRE_APPROVAL", "CONSTRAIN"}
DLP_ACTIONS = {"ALLOW", "CONSTRAIN", "DENY"}
REQUIRED_DLP_PATTERNS = {
    "OPENAI_KEY",
    "SLACK_BOT",
    "AWS_ACCESS_KEY",
    "GITHUB_PAT",
    "AWS_SECRET",
}


def fail(message: str) -> None:
    print(f"[pack-verify] error: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_yaml(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:  # pragma: no cover
        fail(f"failed to parse YAML {path}: {exc}")
    if not isinstance(data, dict):
        fail(f"YAML root must be an object: {path}")
    return data


def expect_file(path: Path) -> None:
    if not path.is_file():
        fail(f"missing file: {path.relative_to(ROOT)}")


def assert_non_empty_list(value: object, label: str) -> list:
    if not isinstance(value, list) or not value:
        fail(f"{label} must be a non-empty list")
    return value


def validate_topics(pack: dict) -> None:
    topics = assert_non_empty_list(pack.get("topics"), "pack.topics")
    for idx, topic in enumerate(topics):
        if not isinstance(topic, dict):
            fail(f"pack.topics[{idx}] must be an object")
        for key in ("name", "capability", "riskTags"):
            if key not in topic:
                fail(f"pack.topics[{idx}] missing '{key}'")
        if not isinstance(topic["riskTags"], list):
            fail(f"pack.topics[{idx}].riskTags must be a list")


def validate_resources(pack: dict) -> None:
    resources = pack.get("resources", {})
    if not isinstance(resources, dict):
        fail("pack.resources must be an object")

    for schema in resources.get("schemas", []):
        if not isinstance(schema, dict) or "path" not in schema:
            fail("each resources.schemas entry must include a path")
        schema_path = PACK_DIR / schema["path"]
        expect_file(schema_path)
        try:
            with schema_path.open("r", encoding="utf-8") as f:
                json.load(f)
        except Exception as exc:
            fail(f"invalid JSON schema {schema_path.relative_to(ROOT)}: {exc}")

    for workflow in resources.get("workflows", []):
        if not isinstance(workflow, dict) or "path" not in workflow:
            fail("each resources.workflows entry must include a path")
        workflow_path = PACK_DIR / workflow["path"]
        expect_file(workflow_path)
        _ = load_yaml(workflow_path)


def validate_overlays(pack: dict) -> None:
    overlays = pack.get("overlays", {})
    if not isinstance(overlays, dict):
        fail("pack.overlays must be an object")

    for _, entries in overlays.items():
        if not isinstance(entries, list):
            fail("each overlays section must be a list")
        for entry in entries:
            if not isinstance(entry, dict) or "path" not in entry:
                fail("each overlay entry must include a path")
            overlay_path = PACK_DIR / entry["path"]
            expect_file(overlay_path)
            overlay_doc = load_yaml(overlay_path)
            validate_policy_rules_shape(overlay_doc, overlay_path)


def validate_policy_rules_shape(doc: dict, path: Path) -> None:
    rules = doc.get("rules")
    if rules is None:
        return
    if not isinstance(rules, list):
        fail(f"{path.relative_to(ROOT)} rules must be a list")
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            fail(f"{path.relative_to(ROOT)} rules[{idx}] must be an object")
        if "description" in rule:
            fail(
                f"{path.relative_to(ROOT)} rules[{idx}] must not contain top-level description; use reason/comments"
            )


def validate_prompt_pii_policy(pack: dict) -> None:
    policy_overlays = pack.get("overlays", {}).get("policy", [])
    registered = {
        str(entry.get("path"))
        for entry in policy_overlays
        if isinstance(entry, dict) and entry.get("path")
    }
    if "policies/openclaw-safety.yaml" not in registered:
        fail("pack.overlays.policy must register policies/openclaw-safety.yaml")

    schema_entries = pack.get("resources", {}).get("schemas", [])
    schema_ids = {
        str(entry.get("id"))
        for entry in schema_entries
        if isinstance(entry, dict) and entry.get("id")
    }
    if "cordclaw/PromptPIIRedact" not in schema_ids:
        fail("pack.resources.schemas must register cordclaw/PromptPIIRedact")

    policy_path = PACK_DIR / "policies" / "openclaw-safety.yaml"
    expect_file(policy_path)
    policy = load_yaml(policy_path)
    primitive = policy.get("prompt_pii_redact")
    if not isinstance(primitive, dict):
        fail("policies/openclaw-safety.yaml must contain prompt_pii_redact object")

    if primitive.get("action") not in DLP_ACTIONS:
        fail(f"prompt_pii_redact.action must be one of {sorted(DLP_ACTIONS)}")
    if not isinstance(primitive.get("reason"), str) or not primitive["reason"].strip():
        fail("prompt_pii_redact.reason is required")
    if "description" in primitive:
        fail("prompt_pii_redact must not contain top-level description; use reason/comments")

    patterns = assert_non_empty_list(primitive.get("patterns"), "prompt_pii_redact.patterns")
    names = set()
    for idx, pattern in enumerate(patterns):
        if not isinstance(pattern, dict):
            fail(f"prompt_pii_redact.patterns[{idx}] must be an object")
        if "description" in pattern:
            fail(
                f"prompt_pii_redact.patterns[{idx}] must not contain description; use YAML comments"
            )
        for key in ("name", "regex", "placeholder"):
            if not isinstance(pattern.get(key), str) or not pattern[key].strip():
                fail(f"prompt_pii_redact.patterns[{idx}] missing '{key}'")
        names.add(pattern["name"])
        try:
            re.compile(pattern["regex"])
        except re.error as exc:
            fail(f"invalid regex for prompt_pii_redact pattern {pattern['name']}: {exc}")
        expected_placeholder = f"<REDACTED-{pattern['name']}>"
        if pattern["placeholder"] != expected_placeholder:
            fail(
                f"placeholder for {pattern['name']} must be {expected_placeholder}, got {pattern['placeholder']}"
            )

    missing = REQUIRED_DLP_PATTERNS - names
    if missing:
        fail(f"prompt_pii_redact missing required patterns: {sorted(missing)}")


def validate_simulations(pack: dict) -> None:
    simulations_doc = load_yaml(SIM_FILE)
    simulations = assert_non_empty_list(
        simulations_doc.get("policySimulations"),
        "tests.policySimulations",
    )

    for idx, simulation in enumerate(simulations):
        if not isinstance(simulation, dict):
            fail(f"tests.policySimulations[{idx}] must be an object")
        if "name" not in simulation or "request" not in simulation or "expectDecision" not in simulation:
            fail(f"tests.policySimulations[{idx}] must include name, request, expectDecision")
        if simulation["expectDecision"] not in ALLOWED_DECISIONS:
            fail(
                f"tests.policySimulations[{idx}] expectDecision must be one of {sorted(ALLOWED_DECISIONS)}"
            )

    pack_tests = pack.get("tests", {})
    if not isinstance(pack_tests, dict):
        fail("pack.tests must be an object")
    inline = assert_non_empty_list(pack_tests.get("policySimulations"), "pack.tests.policySimulations")

    file_names = {str(item.get("name")) for item in simulations if isinstance(item, dict)}
    inline_names = {str(item.get("name")) for item in inline if isinstance(item, dict)}
    if file_names != inline_names:
        fail("pack.tests.policySimulations names must match pack/tests/policy-simulations.yaml")


def main() -> None:
    expect_file(PACK_FILE)
    expect_file(SIM_FILE)

    pack = load_yaml(PACK_FILE)
    if pack.get("apiVersion") != "cordum.io/v1alpha1":
        fail("pack.apiVersion must be cordum.io/v1alpha1")
    if pack.get("kind") != "Pack":
        fail("pack.kind must be Pack")

    metadata = pack.get("metadata")
    if not isinstance(metadata, dict):
        fail("pack.metadata must be an object")
    if not metadata.get("id"):
        fail("pack.metadata.id is required")
    if not metadata.get("version"):
        fail("pack.metadata.version is required")

    validate_topics(pack)
    validate_resources(pack)
    validate_overlays(pack)
    validate_prompt_pii_policy(pack)
    validate_simulations(pack)

    print("[pack-verify] OK: pack metadata, resources, overlays, and simulations are valid")


if __name__ == "__main__":
    main()
