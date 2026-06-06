from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any

from .. import __version__
from .schema import SCHEMA_KINDS, validate_schema_path


QUALITY_GATE_VERSION = 3
QUALITY_GATE_EXIT_CODE_ON_FAILURE = 2
QUALITY_GATE_REQUIRED_CHECKS = (
    "package.metadata",
    "version.consistency",
    "quality_gate.contract",
    "cli.help_registry",
    "cli.short_options",
    "cli.short_options.docs",
    "cli.console_contract",
    "cli.completion_contract",
    "docs.cli_sync",
    "schema.catalog",
    "fixtures.json",
    "fixtures.lab_profiles",
    "fixtures.lab_corpus",
    "fixtures.execution_modules",
    "fixtures.opsec_policies",
    "fixtures.evidence_report",
    "fixtures.lab_matrix",
    "fixtures.lab_determinism",
    "fixtures.lab_provenance",
    "fixtures.lab_stability",
    "fixtures.lab_differential",
    "enterprise.matrix",
    "docs.enterprise_ci",
    "docs.integration_tests",
    "tutorial.examples",
    "ci.workflows",
)
QUALITY_GATE_STABLE_FIELDS = (
    "name",
    "version",
    "schema_version",
    "tool",
    "tool_version",
    "status",
    "summary",
    "checks",
)

_REQUIRED_SCHEMA_KINDS = {
    "result",
    "evidence",
    "lab-profile",
    "lab-corpus",
    "lab-provenance",
    "lab-stability",
    "lab-differential",
    "evidence-report",
    "execution-record",
    "module-manifest",
    "opsec-policy",
    "route-report",
    "opengraph",
    "jsonl",
    "csv",
    "bundle-manifest",
    "quality-gate",
}


def run_quality_gate(project_root: str | Path = ".") -> dict[str, Any]:
    root = Path(project_root)
    checks: list[dict[str, Any]] = []
    _check_package_metadata(checks, root)
    _check_version_consistency(checks, root)
    _check_cli_help_registry(checks)
    _check_cli_short_options(checks)
    _check_cli_short_option_docs(checks, root)
    _check_cli_console_contract(checks)
    _check_cli_completion_contract(checks)
    _check_schema_catalog(checks)
    _check_fixture_json(checks, root)
    _check_schema_fixture_dirs(checks, root)
    _check_evidence_report(checks, root)
    _check_lab_matrix(checks, root)
    _check_lab_determinism(checks, root)
    _check_lab_provenance(checks, root)
    _check_lab_stability(checks, root)
    _check_lab_differential(checks, root)
    _check_enterprise_matrix(checks, root)
    _check_docs(checks, root)
    _check_cli_docs_sync(checks, root)
    _check_integration_docs(checks, root)
    _check_tutorial_examples(checks, root)
    _check_ci_workflows(checks, root)
    _check_quality_gate_contract(checks)

    failed = [check for check in checks if check["status"] == "fail"]
    warnings = [check for check in checks if check["status"] == "warn"]
    return {
        "name": "RelayX quality gate",
        "version": QUALITY_GATE_VERSION,
        "schema_version": 1,
        "tool": "RelayX",
        "tool_version": __version__,
        "contract": {
            "required_checks": list(QUALITY_GATE_REQUIRED_CHECKS),
            "stable_fields": list(QUALITY_GATE_STABLE_FIELDS),
            "exit_code_on_failure": QUALITY_GATE_EXIT_CODE_ON_FAILURE,
            "release_automation_ready": not failed,
        },
        "status": "fail" if failed else "pass",
        "summary": {
            "checks": len(checks),
            "passed": sum(1 for check in checks if check["status"] == "pass"),
            "failed": len(failed),
            "warnings": len(warnings),
        },
        "checks": checks,
    }


def quality_gate_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


def render_quality_gate(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "RelayX Quality Gate",
        "",
        f"Version     : {report.get('tool_version', '')}",
        f"Status      : {report['status']}",
        f"Checks      : {summary['passed']}/{summary['checks']} passed",
        f"Issues      : {summary['failed']} failures, {summary['warnings']} warnings",
        "",
        "Checks:",
    ]
    for check in report["checks"]:
        lines.append(f"  - {check['status']}: {check['name']} - {check['message']}")
    return "\n".join(lines)


def _check_package_metadata(checks: list[dict[str, Any]], root: Path) -> None:
    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.exists():
        _add_check(checks, "package.metadata", "fail", "pyproject.toml is missing.")
        return
    try:
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        _add_check(checks, "package.metadata", "fail", "pyproject.toml could not be parsed.", {"error": str(exc)})
        return
    project = data.get("project") or {}
    scripts = project.get("scripts") or {}
    version = str(project.get("version", ""))
    package_includes = (data.get("tool") or {}).get("hatch", {}).get("build", {}).get("targets", {}).get("sdist", {}).get("include", [])
    failures = []
    if version != __version__:
        failures.append(f"pyproject version {version!r} does not match relayx.__version__ {__version__!r}")
    if scripts.get("relayx") != "relayx.cli:main":
        failures.append("console script relayx must point to relayx.cli:main")
    if "README.md" not in package_includes or "fixtures" not in package_includes or "docs" not in package_includes:
        failures.append("sdist include list must preserve README.md, fixtures, and docs")
    _add_check(
        checks,
        "package.metadata",
        "fail" if failures else "pass",
        "; ".join(failures) if failures else "package metadata, console script, and sdist includes are aligned.",
        {"version": version, "console_script": scripts.get("relayx", ""), "sdist_includes": package_includes},
    )


def _check_schema_catalog(checks: list[dict[str, Any]]) -> None:
    missing = sorted(_REQUIRED_SCHEMA_KINDS - set(SCHEMA_KINDS))
    _add_check(
        checks,
        "schema.catalog",
        "fail" if missing else "pass",
        f"missing schema kinds: {', '.join(missing)}" if missing else "schema catalog includes enterprise and release contracts.",
        {"required": sorted(_REQUIRED_SCHEMA_KINDS), "actual": list(SCHEMA_KINDS)},
    )


def _check_version_consistency(checks: list[dict[str, Any]], root: Path) -> None:
    checked: list[str] = []
    mismatches: list[str] = []
    expected = __version__
    for rel_path in [
        "fixtures/enterprise_output_matrix.json",
        "fixtures/execution_modules/relayx_audit_record.json",
        "fixtures/execution_modules/ntlmrelayx_compat.json",
        "fixtures/execution_modules/lab_only_target_relay_fixture.json",
    ]:
        path = root / rel_path
        if not path.exists():
            mismatches.append(f"{rel_path}: missing")
            continue
        checked.append(rel_path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            mismatches.append(f"{rel_path}: {exc}")
            continue
        version = _fixture_version(data)
        if not version.startswith(expected):
            mismatches.append(f"{rel_path}: version {version!r} does not start with {expected!r}")
    corpus_root = root / "fixtures" / "lab_corpus"
    for path in sorted(corpus_root.glob("*.json")) if corpus_root.exists() else []:
        rel_path = _rel(root, path)
        checked.append(rel_path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            mismatches.append(f"{rel_path}: {exc}")
            continue
        metadata = data.get("metadata") if isinstance(data, dict) else {}
        for key in ("version", "source_result_version"):
            value = str((metadata or {}).get(key, ""))
            if value != expected:
                mismatches.append(f"{rel_path}: metadata.{key}={value!r} expected {expected!r}")
    _add_check(
        checks,
        "version.consistency",
        "fail" if mismatches else "pass",
        "; ".join(mismatches) if mismatches else f"project metadata and release fixtures are aligned on {expected}.",
        {"expected": expected, "checked": checked, "mismatches": mismatches},
    )


def _check_cli_help_registry(checks: list[dict[str, Any]]) -> None:
    from ..cli import _get_command_specs, _help_topic_names, _render_help_topic, build_parser

    parser = build_parser()
    parser_commands = set(_subparser_map(parser))
    specs = _get_command_specs()
    spec_commands = set(specs)
    failures: list[str] = []
    if parser_commands != spec_commands:
        missing_specs = sorted(parser_commands - spec_commands)
        missing_parser = sorted(spec_commands - parser_commands)
        if missing_specs:
            failures.append(f"parser commands missing specs: {', '.join(missing_specs)}")
        if missing_parser:
            failures.append(f"spec commands missing parser registrations: {', '.join(missing_parser)}")
    for name, spec in specs.items():
        if not spec.group:
            failures.append(f"{name}: missing group")
        if not spec.purpose:
            failures.append(f"{name}: missing purpose")
        if not spec.when_to_use:
            failures.append(f"{name}: missing when_to_use")
        if not spec.required_inputs:
            failures.append(f"{name}: missing required_inputs")
        if not spec.examples:
            failures.append(f"{name}: missing examples")
        if not spec.safety_notes:
            failures.append(f"{name}: missing safety_notes")
        if not spec.output_contracts:
            failures.append(f"{name}: missing output_contracts")
        payload = _render_help_topic(name)
        if payload.get("kind") != "command":
            failures.append(f"{name}: help topic does not render a command payload")
    for topic in sorted(_help_topic_names()):
        payload = _render_help_topic(topic)
        if "error" in payload:
            failures.append(f"{topic}: help topic failed to render")
    _add_check(
        checks,
        "cli.help_registry",
        "fail" if failures else "pass",
        (
            "; ".join(failures)
            if failures
            else "parser commands, CommandSpec registry, command help, and curated topics are synchronized."
        ),
        {
            "commands": sorted(spec_commands),
            "topics": sorted(_help_topic_names()),
            "failures": failures,
        },
    )


def _check_cli_short_options(checks: list[dict[str, Any]]) -> None:
    from ..cli import SHORT_OPTIONS_BY_COMMAND, build_parser

    parser = build_parser()
    command_map = _subparser_map(parser)
    missing: list[str] = []
    for command, aliases in SHORT_OPTIONS_BY_COMMAND.items():
        subparser = command_map.get(command)
        if subparser is None:
            missing.append(f"{command}: parser missing")
            continue
        for alias_entry in aliases:
            target_parser = subparser
            alias_text = alias_entry
            if ":" in alias_entry:
                nested_name, alias_text = alias_entry.split(":", 1)
                nested = _subparser_map(subparser).get(nested_name.strip())
                if nested is None:
                    missing.append(f"{command} {nested_name.strip()}: parser missing")
                    continue
                target_parser = nested
            available = {
                option
                for action in target_parser._actions
                for option in action.option_strings
            }
            for alias in alias_text.split(","):
                short = alias.split("/", 1)[0].strip()
                if short.startswith("-") and short not in available:
                    missing.append(f"{command}: {short}")
    _add_check(
        checks,
        "cli.short_options",
        "fail" if missing else "pass",
        "; ".join(missing) if missing else "documented short options are registered in argparse.",
        {"commands": sorted(SHORT_OPTIONS_BY_COMMAND), "missing": missing},
    )


def _check_cli_short_option_docs(checks: list[dict[str, Any]], root: Path) -> None:
    from ..cli import SHORT_OPTIONS_BY_COMMAND, _render_help_topic

    failures: list[str] = []
    payload = _render_help_topic("short-options")
    command_rows = {row["command"]: row["aliases"] for row in payload.get("commands", [])}
    for command, aliases in SHORT_OPTIONS_BY_COMMAND.items():
        if command_rows.get(command) != aliases:
            failures.append(f"help short-options command map mismatch for {command}")

    required_docs = {
        "README.md": ["relayx help short-options", "alias map"],
        "docs/CLI.md": ["relayx help short-options", "complete alias map"],
    }
    for rel_path, needles in required_docs.items():
        path = root / rel_path
        if not path.exists():
            failures.append(f"{rel_path}: missing")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                failures.append(f"{rel_path}: missing {needle!r}")

    _add_check(
        checks,
        "cli.short_options.docs",
        "fail" if failures else "pass",
        (
            "; ".join(failures)
            if failures
            else "CLI short-option help payload and user documentation point to the synchronized alias map."
        ),
        {
            "commands": sorted(SHORT_OPTIONS_BY_COMMAND),
            "documented_files": sorted(required_docs),
            "failures": failures,
        },
    )


def _check_cli_console_contract(checks: list[dict[str, Any]]) -> None:
    import contextlib
    import io

    from ..cli import (
        ConsoleContext,
        _console_completion_candidates,
        _console_history_recordable,
        _console_prompt,
        _handle_console_line,
    )

    failures: list[str] = []
    context = ConsoleContext(opsec_policy="strict", history_entries=["show summary"])
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc_context, exit_context = _handle_console_line("context", context)
        rc_help, exit_help = _handle_console_line("help console", context)
        rc_alias, exit_alias = _handle_console_line("?", context)
        rc_menu, exit_menu = _handle_console_line("menu", context)
        rc_next, exit_next = _handle_console_line("next", context)
        rc_discover, exit_discover = _handle_console_line("discover jsonl", context)
        rc_clear, exit_clear = _handle_console_line("clear", context, interactive=False)
        rc_history, exit_history = _handle_console_line("history 1", context)
        rc_set, _ = _handle_console_line("set scope examples/scope.txt", context)
        rc_unknown, _ = _handle_console_line("does-not-exist", context)
        rc_exit, exit_exit = _handle_console_line("exit", context)
    if rc_context != 0 or exit_context:
        failures.append("context command did not render without exiting")
    if rc_help != 0 or exit_help:
        failures.append("help console did not render in console context")
    if rc_alias != 0 or exit_alias:
        failures.append("? alias did not render help in console context")
    if rc_menu != 0 or exit_menu:
        failures.append("menu command did not render in console context")
    if rc_next != 0 or exit_next:
        failures.append("next command did not render in console context")
    if rc_discover != 0 or exit_discover:
        failures.append("discover command did not render in console context")
    if rc_clear != 0 or exit_clear:
        failures.append("clear command did not render without exiting")
    if rc_history != 0 or exit_history:
        failures.append("history command did not render without exiting")
    if rc_set != 0 or context.scope != "examples/scope.txt":
        failures.append("set scope did not update console context")
    if rc_unknown != 2:
        failures.append("unknown console command must return exit code 2")
    if rc_exit != 0 or not exit_exit:
        failures.append("exit command did not request console termination")
    prompt = _console_prompt(ConsoleContext(result="result.json", path_id="PX-0001", opsec_policy="strict"))
    for needle in ("result:result.json", "path:PX-0001", "policy:strict"):
        if needle not in prompt:
            failures.append(f"console prompt missing {needle}")
    if "summary " not in _console_completion_candidates("show s", "s"):
        failures.append("console completion candidates do not include contextual show targets")
    if _console_history_recordable("run --password RedteamN0t3s."):
        failures.append("console history policy records a secret-bearing command")
    _add_check(
        checks,
        "cli.console_contract",
        "fail" if failures else "pass",
        (
            "; ".join(failures)
            if failures
            else "local console context, discover, next, menu, help, prompt, clear, history, completion, error, and exit contracts are stable."
        ),
        {"failures": failures, "prompt": prompt},
    )


def _check_cli_completion_contract(checks: list[dict[str, Any]]) -> None:
    from ..cli import render_completion

    failures: list[str] = []
    scripts: dict[str, int] = {}
    required = {
        "bash": ["_relayx_completion", "console", "completion", "opengraph", "--opsec-policy"],
        "zsh": ["#compdef relayx", "console", "completion", "opengraph", "policies"],
        "fish": ["complete -c relayx", "console", "completion", "opengraph", "opsec-policy"],
    }
    for shell, needles in required.items():
        try:
            script = render_completion(shell)
        except ValueError as exc:
            failures.append(f"{shell}: {exc}")
            continue
        scripts[shell] = len(script)
        if len(script) < 100:
            failures.append(f"{shell}: completion script is unexpectedly short")
        for needle in needles:
            if needle not in script:
                failures.append(f"{shell}: missing {needle!r}")
    _add_check(
        checks,
        "cli.completion_contract",
        "fail" if failures else "pass",
        (
            "; ".join(failures)
            if failures
            else "bash, zsh, and fish completion scripts are generated from the command registry."
        ),
        {"script_lengths": scripts, "failures": failures},
    )


def _check_cli_docs_sync(checks: list[dict[str, Any]], root: Path) -> None:
    required = {
        "README.md": ["relayx discover", "relayx next", "relayx console", "relayx completion", "relayx help getting-started", "docs/TUTORIAL.zh-CN.md", "--no-history"],
        "docs/CLI.md": ["CommandSpec", "relayx discover", "relayx next", "relayx console", "relayx completion", "relayx help troubleshooting", "--no-color", "--no-history", "history clear", "Tab completion"],
        "docs/TUTORIAL.md": ["relayx discover", "relayx next", "relayx console", "relayx completion", "--no-color", "--no-history", "history"],
        "docs/TUTORIAL.zh-CN.md": ["RelayX 完整离线教程", "relayx discover", "relayx next", "relayx console", "relayx completion", "--no-color", "--no-history", "history"],
    }
    failures: list[str] = []
    for rel_path, needles in required.items():
        path = root / rel_path
        if not path.exists():
            failures.append(f"{rel_path}: missing")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                failures.append(f"{rel_path}: missing {needle!r}")
    _add_check(
        checks,
        "docs.cli_sync",
        "fail" if failures else "pass",
        (
            "; ".join(failures)
            if failures
            else "README, CLI docs, and bilingual tutorials describe console, completion, color controls, and registry-backed help."
        ),
        {"required": required, "failures": failures},
    )


def _check_fixture_json(checks: list[dict[str, Any]], root: Path) -> None:
    fixture_root = root / "fixtures"
    files = sorted(fixture_root.rglob("*.json")) if fixture_root.exists() else []
    invalid: list[dict[str, str]] = []
    for path in files:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            invalid.append({"path": _rel(root, path), "error": str(exc)})
    if not files:
        _add_check(checks, "fixtures.json", "fail", "fixtures directory contains no JSON files.")
        return
    _add_check(
        checks,
        "fixtures.json",
        "fail" if invalid else "pass",
        f"{len(invalid)} fixture JSON file(s) failed parsing." if invalid else f"{len(files)} fixture JSON file(s) parse cleanly.",
        {"files": len(files), "invalid": invalid},
    )


def _check_schema_fixture_dirs(checks: list[dict[str, Any]], root: Path) -> None:
    for name, rel_path, kind in (
        ("fixtures.lab_profiles", "fixtures/lab_profiles", "lab-profile"),
        ("fixtures.lab_corpus", "fixtures/lab_corpus", "lab-corpus"),
        ("fixtures.execution_modules", "fixtures/execution_modules", "module-manifest"),
        ("fixtures.opsec_policies", "fixtures/opsec_policies", "opsec-policy"),
    ):
        path = root / rel_path
        if not path.exists():
            _add_check(checks, name, "fail", f"{rel_path} is missing.")
            continue
        report = validate_schema_path(str(path), kind=kind)
        summary = report.summary
        _add_check(
            checks,
            name,
            "pass" if report.valid else "fail",
            f"{summary['valid_files']}/{summary['files']} files satisfy {kind}.",
            {"kind": kind, "summary": summary},
        )


def _check_evidence_report(checks: list[dict[str, Any]], root: Path) -> None:
    from ..io import read_result
    from .evidence_report import build_evidence_report
    from .schema import validate_schema_object

    path = root / "examples" / "tutorial" / "sample-result.json"
    if not path.exists():
        _add_check(checks, "fixtures.evidence_report", "fail", "examples/tutorial/sample-result.json is missing.")
        return
    try:
        report = build_evidence_report(read_result(str(path)))
    except (OSError, ValueError) as exc:
        _add_check(checks, "fixtures.evidence_report", "fail", "evidence report failed to build.", {"error": str(exc)})
        return
    schema_report = validate_schema_object(report, "evidence-report")
    summary = report.get("summary", {})
    categories = set((summary.get("source_categories") or {}))
    required_categories = {"wire_observation", "policy_inference", "source_model", "route_model", "control_mapping"}
    missing_categories = sorted(required_categories - categories)
    failed = report.get("status") == "fail" or not schema_report.valid or bool(missing_categories)
    _add_check(
        checks,
        "fixtures.evidence_report",
        "fail" if failed else "pass",
        (
            "tutorial evidence report satisfies the evidence-report schema and source taxonomy coverage."
            if not failed
            else "tutorial evidence report has schema errors, evidence contract failures, or missing taxonomy categories."
        ),
        {
            "status": report.get("status"),
            "summary": summary,
            "missing_categories": missing_categories,
            "schema_valid": schema_report.valid,
            "schema_issues": [issue.as_dict() for issue in schema_report.issues],
        },
    )


def _check_lab_matrix(checks: list[dict[str, Any]], root: Path) -> None:
    from .calibration import load_corpuses, verify_lab_corpus

    path = root / "fixtures" / "lab_corpus"
    if not path.exists():
        _add_check(checks, "fixtures.lab_matrix", "fail", "fixtures/lab_corpus is missing.")
        return
    try:
        report = verify_lab_corpus(load_corpuses([str(path)]))
    except (OSError, ValueError) as exc:
        _add_check(checks, "fixtures.lab_matrix", "fail", "lab corpus matrix verification failed to run.", {"error": str(exc)})
        return
    summary = report.get("summary", {})
    _add_check(
        checks,
        "fixtures.lab_matrix",
        "pass" if report.get("status") == "pass" else "fail",
        (
            f"{summary.get('passed', 0)}/{summary.get('requirements', 0)} standard lab matrix requirements covered."
            if report.get("status") == "pass"
            else "standard lab matrix coverage is incomplete."
        ),
        {
            "status": report.get("status"),
            "summary": summary,
            "missing_required": report.get("missing_required", []),
            "incomplete_required": report.get("incomplete_required", []),
        },
    )


def _check_lab_determinism(checks: list[dict[str, Any]], root: Path) -> None:
    from .calibration import standard_lab_matrix

    corpus_root = root / "fixtures" / "lab_corpus"
    if not corpus_root.exists():
        _add_check(checks, "fixtures.lab_determinism", "fail", "fixtures/lab_corpus is missing.")
        return

    requirements = {
        (row["target_family"], row["policy_state"]): row
        for row in standard_lab_matrix().get("requirements", [])
    }
    failures: list[str] = []
    signature_rows: list[dict[str, Any]] = []
    volatile_tokens = ("timestamp", "captured_at", "observed_at", "duration", "elapsed")
    for path in sorted(corpus_root.glob("*.json")):
        try:
            corpus = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{_rel(root, path)}: {exc}")
            continue
        for index, capture in enumerate(corpus.get("captures", [])):
            capture_ref = f"{_rel(root, path)}:captures[{index}]"
            expected = capture.get("expected")
            signature = capture.get("observed_signature")
            if not isinstance(expected, dict):
                failures.append(f"{capture_ref}: missing expected classification object")
                continue
            if not isinstance(signature, dict) or not signature:
                failures.append(f"{capture_ref}: missing observed_signature object")
                continue
            target_family = str(capture.get("target_family", ""))
            policy_state = str(expected.get("policy_state", ""))
            classification = str(expected.get("classification", ""))
            requirement = requirements.get((target_family, policy_state))
            if requirement is None:
                failures.append(f"{capture_ref}: expected policy_state {policy_state!r} is not in the standard lab matrix")
            else:
                missing_keys = sorted(set(requirement.get("required_signature_keys", [])) - set(signature))
                if missing_keys:
                    failures.append(f"{capture_ref}: observed_signature missing required keys {', '.join(missing_keys)}")
            if classification != str(signature.get("response_classification", "")):
                failures.append(
                    f"{capture_ref}: expected.classification {classification!r} does not match observed_signature.response_classification {signature.get('response_classification')!r}"
                )
            for key, expected_value in (
                ("target_family", target_family),
                ("protocol", str(capture.get("protocol", ""))),
                ("finding_name", str(capture.get("finding_name", ""))),
            ):
                if key in signature and str(signature.get(key, "")) != expected_value:
                    failures.append(f"{capture_ref}: observed_signature.{key} does not match capture.{key}")
            if not expected.get("calibrated_state"):
                failures.append(f"{capture_ref}: expected.calibrated_state is empty")
            if not expected.get("promotion_reason"):
                failures.append(f"{capture_ref}: expected.promotion_reason is empty")
            if not expected.get("remaining_uncertainty"):
                failures.append(f"{capture_ref}: expected.remaining_uncertainty is empty")
            volatile_keys = sorted(key for key in signature if any(token in key.lower() for token in volatile_tokens))
            if volatile_keys:
                failures.append(f"{capture_ref}: observed_signature contains volatile keys {', '.join(volatile_keys)}")
            digest = hashlib.sha256(json.dumps(signature, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            signature_rows.append(
                {
                    "corpus": _rel(root, path),
                    "finding_ref": capture.get("finding_ref", ""),
                    "target_family": target_family,
                    "policy_state": policy_state,
                    "classification": classification,
                    "signature_sha256": digest,
                }
            )

    _add_check(
        checks,
        "fixtures.lab_determinism",
        "fail" if failures else "pass",
        (
            "; ".join(failures)
            if failures
            else f"{len(signature_rows)} lab captures have deterministic signatures tied to expected classifications."
        ),
        {"captures": len(signature_rows), "signatures": signature_rows, "failures": failures},
    )


def _check_lab_provenance(checks: list[dict[str, Any]], root: Path) -> None:
    from .calibration import assess_lab_provenance, load_corpuses
    from .schema import validate_schema_object

    path = root / "fixtures" / "lab_corpus"
    if not path.exists():
        _add_check(checks, "fixtures.lab_provenance", "fail", "fixtures/lab_corpus is missing.")
        return
    try:
        report = assess_lab_provenance(load_corpuses([str(path)]))
    except (OSError, ValueError) as exc:
        _add_check(checks, "fixtures.lab_provenance", "fail", "lab corpus provenance assessment failed to run.", {"error": str(exc)})
        return
    schema_report = validate_schema_object(report, "lab-provenance")
    summary = report.get("summary", {})
    failed = report.get("status") == "fail" or not schema_report.valid
    _add_check(
        checks,
        "fixtures.lab_provenance",
        "fail" if failed else "pass",
        (
            "lab corpus provenance, endpoint build metadata, drift baselines, and review states are structured."
            if not failed
            else "lab corpus provenance assessment failed or does not satisfy schema."
        ),
        {
            "status": report.get("status"),
            "summary": summary,
            "schema_valid": schema_report.valid,
            "schema_issues": [issue.as_dict() for issue in schema_report.issues],
        },
    )


def _check_lab_stability(checks: list[dict[str, Any]], root: Path) -> None:
    from .calibration import assess_lab_stability, load_corpuses

    path = root / "fixtures" / "lab_corpus"
    if not path.exists():
        _add_check(checks, "fixtures.lab_stability", "fail", "fixtures/lab_corpus is missing.")
        return
    try:
        report = assess_lab_stability(load_corpuses([str(path)]), min_captures=1)
    except (OSError, ValueError) as exc:
        _add_check(checks, "fixtures.lab_stability", "fail", "lab corpus stability assessment failed to run.", {"error": str(exc)})
        return
    summary = report.get("summary", {})
    _add_check(
        checks,
        "fixtures.lab_stability",
        "pass" if report.get("status") == "pass" else "fail",
        (
            f"{summary.get('stable', 0)}/{summary.get('policy_states', 0)} standard lab policy states have stable fixture signatures."
            if report.get("status") == "pass"
            else "standard lab fixture signatures are missing or unstable."
        ),
        {
            "status": report.get("status"),
            "summary": summary,
            "promotion_downgrades": report.get("promotion_downgrades", []),
        },
    )


def _check_lab_differential(checks: list[dict[str, Any]], root: Path) -> None:
    from .calibration import assess_lab_differentials, load_corpuses

    path = root / "fixtures" / "lab_corpus"
    if not path.exists():
        _add_check(checks, "fixtures.lab_differential", "fail", "fixtures/lab_corpus is missing.")
        return
    try:
        report = assess_lab_differentials(load_corpuses([str(path)]), min_captures=1)
    except (OSError, ValueError) as exc:
        _add_check(checks, "fixtures.lab_differential", "fail", "lab corpus differential assessment failed to run.", {"error": str(exc)})
        return
    summary = report.get("summary", {})
    _add_check(
        checks,
        "fixtures.lab_differential",
        "pass" if report.get("status") == "pass" else "fail",
        (
            f"{summary.get('differential', 0)}/{summary.get('pairs', 0)} standard lab policy pairs expose response differentials."
            if report.get("status") == "pass"
            else "standard lab response differentials are missing, unstable, or indistinguishable."
        ),
        {
            "status": report.get("status"),
            "summary": summary,
        },
    )


def _check_enterprise_matrix(checks: list[dict[str, Any]], root: Path) -> None:
    path = root / "fixtures" / "enterprise_output_matrix.json"
    try:
        matrix = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _add_check(checks, "enterprise.matrix", "fail", "enterprise output matrix could not be parsed.", {"error": str(exc)})
        return
    commands = set(matrix.get("commands") or [])
    export_formats = set(matrix.get("export_formats") or [])
    release = matrix.get("release") or {}
    quality_contract = matrix.get("quality_gate_contract") or {}
    missing_commands = sorted({"export", "bundle", "quality-gate", "diff", "simulate-fixes", "schema"} - commands)
    missing_formats = sorted({"opengraph", "jsonl", "csv", "html", "mermaid", "markdown"} - export_formats)
    missing_quality_checks = sorted(set(QUALITY_GATE_REQUIRED_CHECKS) - set(quality_contract.get("checks") or []))
    failures = []
    if missing_commands:
        failures.append(f"missing commands: {', '.join(missing_commands)}")
    if missing_formats:
        failures.append(f"missing formats: {', '.join(missing_formats)}")
    if missing_quality_checks:
        failures.append(f"quality gate contract missing checks: {', '.join(missing_quality_checks)}")
    if quality_contract.get("exit_code_on_failure") != QUALITY_GATE_EXIT_CODE_ON_FAILURE:
        failures.append("quality gate contract exit_code_on_failure is not aligned")
    if release.get("version") != __version__:
        failures.append(f"release matrix version {release.get('version')!r} does not match {__version__!r}")
    _add_check(
        checks,
        "enterprise.matrix",
        "fail" if failures else "pass",
        "; ".join(failures) if failures else "enterprise matrix covers exports, bundle, quality gate, and release version.",
        {
            "commands": sorted(commands),
            "export_formats": sorted(export_formats),
            "release": release,
            "missing_quality_checks": missing_quality_checks,
        },
    )


def _check_docs(checks: list[dict[str, Any]], root: Path) -> None:
    required = {
        "README.md": ["relayx bundle", "relayx quality-gate", "relayx lab-provenance", "relayx lab-stability", "relayx lab-diff", "relayx evidence-report", "bundle-manifest", "quality-gate", "evidence-report", "short-options", "docs/TUTORIAL.md", "docs/TUTORIAL.zh-CN.md"],
        "docs/CLI.md": ["relayx bundle", "relayx quality-gate", "relayx lab-provenance", "relayx lab-stability", "relayx lab-diff", "relayx evidence-report", "Short Options"],
        "docs/ENTERPRISE_OUTPUTS.md": ["Enterprise Bundle", "Quality Gate", "field contract", "residual exposure"],
        "docs/SCHEMA.md": ["bundle-manifest", "quality-gate", "lab-provenance", "lab-stability", "lab-differential", "evidence-report", "source taxonomy", "field_contract_version"],
        "docs/TUTORIAL.md": ["Complete Offline Tutorial", "examples/tutorial/sample-result.json", "calibrate", "validate", "bundle", "simulate-fixes", "lab-provenance", "lab-stability", "lab-diff", "evidence-report"],
        "docs/TUTORIAL.zh-CN.md": ["RelayX 完整离线教程", "examples/tutorial/sample-result.json", "calibrate", "validate", "bundle", "simulate-fixes", "lab-provenance", "lab-stability", "lab-diff", "evidence-report"],
        "docs/INTEGRATION_TESTS.md": ["Authorized Integration Test Expectations", "Active Directory", "IIS", "AD CS", "MSSQL"],
    }
    missing: list[str] = []
    for rel_path, needles in required.items():
        path = root / rel_path
        if not path.exists():
            missing.append(f"{rel_path}: missing")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                missing.append(f"{rel_path}: missing {needle!r}")
    _add_check(
        checks,
        "docs.enterprise_ci",
        "fail" if missing else "pass",
        "; ".join(missing) if missing else "documentation covers bundle, quality gate, and schema contracts.",
        {"missing": missing},
    )


def _check_integration_docs(checks: list[dict[str, Any]], root: Path) -> None:
    rel_path = "docs/INTEGRATION_TESTS.md"
    path = root / rel_path
    required = [
        "Authorized Integration Test Expectations",
        "Scope And Authorization",
        "Active Directory",
        "IIS",
        "AD CS",
        "MSSQL",
        "LDAP signing",
        "LDAPS CBT",
        "HTTP/IIS EPA",
        "AD CS Web Enrollment EPA",
        "MSSQL encryption/EPA",
        "Expected Telemetry",
        "Rollback",
        "OPSEC",
        "lab corpus",
        "quality-gate",
    ]
    missing: list[str] = []
    if not path.exists():
        missing.append(f"{rel_path}: missing")
    else:
        text = path.read_text(encoding="utf-8")
        for needle in required:
            if needle not in text:
                missing.append(f"{rel_path}: missing {needle!r}")
    _add_check(
        checks,
        "docs.integration_tests",
        "fail" if missing else "pass",
        (
            "; ".join(missing)
            if missing
            else "authorized AD/IIS/AD CS/MSSQL integration-test expectations are documented."
        ),
        {"required": required, "missing": missing},
    )


def _check_tutorial_examples(checks: list[dict[str, Any]], root: Path) -> None:
    required_files = [
        "docs/TUTORIAL.md",
        "docs/TUTORIAL.zh-CN.md",
        "examples/tutorial/README.md",
        "examples/tutorial/targets.txt",
        "examples/tutorial/scope.txt",
        "examples/tutorial/sources.json",
        "examples/tutorial/baseline-result.json",
        "examples/tutorial/sample-result.json",
    ]
    failures: list[str] = []
    missing = [rel_path for rel_path in required_files if not (root / rel_path).exists()]
    failures.extend(f"{rel_path}: missing" for rel_path in missing)

    schema_reports: dict[str, dict[str, Any]] = {}
    for rel_path in ("examples/tutorial/baseline-result.json", "examples/tutorial/sample-result.json"):
        path = root / rel_path
        if not path.exists():
            continue
        report = validate_schema_path(str(path), kind="result")
        schema_reports[rel_path] = report.summary
        if not report.valid:
            failures.append(f"{rel_path}: does not satisfy result schema")

    sources_path = root / "examples" / "tutorial" / "sources.json"
    if sources_path.exists():
        try:
            source_data = json.loads(sources_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"examples/tutorial/sources.json: {exc}")
        else:
            source_rows = source_data.get("sources", source_data) if isinstance(source_data, dict) else source_data
            if not isinstance(source_rows, list) or not source_rows:
                failures.append("examples/tutorial/sources.json: expected a non-empty source list")
            else:
                if not any(isinstance(row, dict) and row.get("route_hops") for row in source_rows):
                    failures.append("examples/tutorial/sources.json: expected at least one structured route_hops entry")
                if not any(
                    isinstance(row, dict)
                    and isinstance(row.get("capabilities"), dict)
                    and any(bool(value) for value in row["capabilities"].values())
                    for row in source_rows
                ):
                    failures.append("examples/tutorial/sources.json: expected modeled source capabilities")

    _add_check(
        checks,
        "tutorial.examples",
        "fail" if failures else "pass",
        "; ".join(failures) if failures else "offline tutorial fixtures and result schemas are ready.",
        {"required_files": required_files, "schema_reports": schema_reports, "failures": failures},
    )


def _check_ci_workflows(checks: list[dict[str, Any]], root: Path) -> None:
    required = {
        ".github/workflows/ci.yml": ["quality-gate", "unittest", "pip wheel"],
        ".github/workflows/release.yml": ["quality-gate", "python -m build", "v*"],
    }
    missing: list[str] = []
    for rel_path, needles in required.items():
        path = root / rel_path
        if not path.exists():
            missing.append(f"{rel_path}: missing")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                missing.append(f"{rel_path}: missing {needle!r}")
    _add_check(
        checks,
        "ci.workflows",
        "fail" if missing else "pass",
        "; ".join(missing) if missing else "CI and release workflows enforce tests, quality gate, and package builds.",
        {"missing": missing},
    )


def _check_quality_gate_contract(checks: list[dict[str, Any]]) -> None:
    actual = {check["name"] for check in checks} | {"quality_gate.contract"}
    missing = sorted(set(QUALITY_GATE_REQUIRED_CHECKS) - actual)
    stable_fields = set(QUALITY_GATE_STABLE_FIELDS)
    required_fields = {"name", "version", "schema_version", "tool", "tool_version", "status", "summary", "checks"}
    field_missing = sorted(required_fields - stable_fields)
    failures = [*missing, *(f"stable field missing: {field}" for field in field_missing)]
    _add_check(
        checks,
        "quality_gate.contract",
        "fail" if failures else "pass",
        (
            "; ".join(failures)
            if failures
            else "quality-gate check list, stable fields, and failure exit code are release-automation ready."
        ),
        {
            "version": QUALITY_GATE_VERSION,
            "required_checks": list(QUALITY_GATE_REQUIRED_CHECKS),
            "stable_fields": list(QUALITY_GATE_STABLE_FIELDS),
            "exit_code_on_failure": QUALITY_GATE_EXIT_CODE_ON_FAILURE,
            "missing": missing,
        },
    )


def _add_check(
    checks: list[dict[str, Any]],
    name: str,
    status: str,
    message: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    checks.append(
        {
            "name": name,
            "status": status,
            "message": message,
            "evidence": evidence or {},
        }
    )


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _fixture_version(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    release = data.get("release")
    if isinstance(release, dict):
        return str(release.get("version", ""))
    return str(data.get("version", ""))


def _subparser_map(parser: Any) -> dict[str, Any]:
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            return dict(choices)
    return {}
