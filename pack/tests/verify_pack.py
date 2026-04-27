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
REQUIRED_OPENCLAW_TOPICS = {
    "job.openclaw.tool_call",
    "job.openclaw.prompt_build",
    "job.openclaw.agent_start",
    "job.openclaw.message_write",
    "job.openclaw.cron_fire",
    "job.openclaw.result_gating",
}
REQUIRED_OPENCLAW_PRIMITIVES = {
    "tool_allow",
    "tool_deny",
    "mcp_server_allow",
    "channel_action_allow",
    "exec_command_allow",
    "file_path_scope",
    "url_domain_allow",
    "prompt_pii_redact",
    "cron_origin_check",
    "result_gating",
}
OPENCLAW_POLICY_FILE = "policies/openclaw-safety.yaml"
OPENCLAW_POOLS_FILE = "pools.d/openclaw.yaml"


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
    seen = set()
    for idx, topic in enumerate(topics):
        if not isinstance(topic, dict):
            fail(f"pack.topics[{idx}] must be an object")
        for key in ("name", "capability", "riskTags"):
            if key not in topic:
                fail(f"pack.topics[{idx}] missing '{key}'")
        if not isinstance(topic["riskTags"], list):
            fail(f"pack.topics[{idx}].riskTags must be a list")
        name = str(topic.get("name"))
        if name in seen:
            fail(f"pack.topics contains duplicate topic: {name}")
        seen.add(name)

    missing = REQUIRED_OPENCLAW_TOPICS - seen
    if missing:
        fail(f"pack.topics missing required OpenClaw topics: {sorted(missing)}")


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

    validate_openclaw_pool_config(pack)


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
        if "enforce" in rule and not isinstance(rule["enforce"], bool):
            fail(f"{path.relative_to(ROOT)} rules[{idx}].enforce must be a boolean when present")
        match = rule.get("match")
        if match is not None:
            validate_no_description_keys(match, path, f"rules[{idx}].match")
        constraints = rule.get("constraints")
        if constraints is not None:
            validate_no_description_keys(constraints, path, f"rules[{idx}].constraints")


def validate_no_description_keys(value: object, path: Path, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "description":
                fail(f"{path.relative_to(ROOT)} {label} must not contain description")
            validate_no_description_keys(child, path, f"{label}.{key}")
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            validate_no_description_keys(child, path, f"{label}[{idx}]")


def validate_openclaw_pool_config(pack: dict) -> None:
    pools_path = PACK_DIR / OPENCLAW_POOLS_FILE
    expect_file(pools_path)
    pools_doc = load_yaml(pools_path)
    validate_no_description_keys(pools_doc, pools_path, "root")

    overlay_paths = {
        str(entry.get("path"))
        for entry in pack.get("overlays", {}).get("config", [])
        if isinstance(entry, dict) and entry.get("path")
    }
    if "overlays/pools.patch.yaml" not in overlay_paths:
        fail("pack.overlays.config must register overlays/pools.patch.yaml")

    overlay_doc = load_yaml(PACK_DIR / "overlays" / "pools.patch.yaml")
    topics_map = {}
    for label, doc in (
        (OPENCLAW_POOLS_FILE, pools_doc),
        ("overlays/pools.patch.yaml", overlay_doc),
    ):
        raw_topics = doc.get("topics")
        if not isinstance(raw_topics, dict):
            fail(f"{label} topics must be an object")
        raw_pools = doc.get("pools")
        if not isinstance(raw_pools, dict):
            fail(f"{label} pools must be an object")
        for topic in REQUIRED_OPENCLAW_TOPICS:
            pool_name = raw_topics.get(topic)
            if not isinstance(pool_name, str) or not pool_name.strip():
                fail(f"{label} missing pool mapping for {topic}")
            if pool_name not in raw_pools:
                fail(f"{label} maps {topic} to missing pool {pool_name}")
            pool = raw_pools[pool_name]
            if not isinstance(pool, dict):
                fail(f"{label} pool {pool_name} must be an object")
            if not isinstance(pool.get("requires", []), list):
                fail(f"{label} pool {pool_name}.requires must be a list")
            topics_map.setdefault(topic, set()).add(pool_name)


def validate_prompt_pii_policy(pack: dict) -> None:
    policy_overlays = pack.get("overlays", {}).get("policy", [])
    registered = {}
    for entry in policy_overlays:
        if isinstance(entry, dict) and entry.get("path"):
            registered[str(entry.get("path"))] = entry
    if OPENCLAW_POLICY_FILE not in registered:
        fail(f"pack.overlays.policy must register {OPENCLAW_POLICY_FILE}")
    if registered[OPENCLAW_POLICY_FILE].get("strategy") != "bundle_fragment":
        fail(f"pack.overlays.policy entry for {OPENCLAW_POLICY_FILE} must use strategy=bundle_fragment")

    schema_entries = pack.get("resources", {}).get("schemas", [])
    schema_ids = {
        str(entry.get("id"))
        for entry in schema_entries
        if isinstance(entry, dict) and entry.get("id")
    }
    if "cordclaw/PromptPIIRedact" not in schema_ids:
        fail("pack.resources.schemas must register cordclaw/PromptPIIRedact")

    policy_path = PACK_DIR / OPENCLAW_POLICY_FILE
    expect_file(policy_path)
    policy = load_yaml(policy_path)
    if str(policy.get("version")) != "1":
        fail(f"{OPENCLAW_POLICY_FILE} must set version: \"1\"")
    if policy.get("default_tenant") != "default":
        fail(f"{OPENCLAW_POLICY_FILE} must set default_tenant: default")

    primitive = policy.get("prompt_pii_redact")
    if not isinstance(primitive, dict):
        fail(f"{OPENCLAW_POLICY_FILE} must contain prompt_pii_redact object")

    if primitive.get("action") not in DLP_ACTIONS:
        fail(f"prompt_pii_redact.action must be one of {sorted(DLP_ACTIONS)}")
    if not isinstance(primitive.get("reason"), str) or not primitive["reason"].strip():
        fail("prompt_pii_redact.reason is required")
    if "description" in primitive:
        fail("prompt_pii_redact must not contain top-level description; use reason/comments")
    validate_no_description_keys(primitive, policy_path, "prompt_pii_redact")

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

    validate_openclaw_policy_rules(policy, policy_path)


def validate_openclaw_policy_rules(policy: dict, policy_path: Path) -> None:
    rules = assert_non_empty_list(policy.get("rules"), f"{OPENCLAW_POLICY_FILE}.rules")
    validate_policy_rules_shape(policy, policy_path)

    found_primitives = set()
    found_topics = set()
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            fail(f"{OPENCLAW_POLICY_FILE} rules[{idx}] must be an object")
        rule_id = str(rule.get("id", ""))
        if rule_id.startswith("openclaw-"):
            found_primitives.update(primitive for primitive in REQUIRED_OPENCLAW_PRIMITIVES if primitive in rule_id)
        primitive = rule.get("primitive")
        if isinstance(primitive, str):
            found_primitives.add(primitive)
        match = rule.get("match")
        if isinstance(match, dict):
            for topic in match.get("topics", []) or []:
                if topic in REQUIRED_OPENCLAW_TOPICS:
                    found_topics.add(topic)
            labels = match.get("label_allowlist")
            if isinstance(labels, dict):
                for primitive_name, label_name in (
                    ("mcp_server_allow", "mcp_server"),
                    ("channel_action_allow", "channel_action"),
                    ("exec_command_allow", "command_family"),
                    ("file_path_scope", "path_scope"),
                    ("url_domain_allow", "url_domain"),
                ):
                    if label_name in labels:
                        found_primitives.add(primitive_name)
        constraints = rule.get("constraints")
        if isinstance(constraints, dict):
            if "prompt_pii_redact" in constraints or constraints.get("kind") == "prompt_pii_redact":
                found_primitives.add("prompt_pii_redact")
            if "max_output_bytes" in constraints or "budgets" in constraints or constraints.get("kind") == "result_gating":
                found_primitives.add("result_gating")

        if "tool_deny" in rule_id or ("tool" in rule_id and str(rule.get("decision", "")).lower() == "deny"):
            found_primitives.add("tool_deny")
        if "tool_allow" in rule_id or ("tool" in rule_id and str(rule.get("decision", "")).lower() == "allow"):
            found_primitives.add("tool_allow")
        if "cron_origin" in rule_id or "cron-origin" in str(rule.get("reason", "")):
            found_primitives.add("cron_origin_check")

    missing_topics = REQUIRED_OPENCLAW_TOPICS - found_topics
    if missing_topics:
        fail(f"{OPENCLAW_POLICY_FILE} rules missing required OpenClaw topics: {sorted(missing_topics)}")

    missing_primitives = REQUIRED_OPENCLAW_PRIMITIVES - found_primitives
    if missing_primitives:
        fail(f"{OPENCLAW_POLICY_FILE} rules missing primitive coverage: {sorted(missing_primitives)}")


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
