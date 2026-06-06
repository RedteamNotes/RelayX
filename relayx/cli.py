from __future__ import annotations

import argparse
import difflib
import glob
import json
import os
import random
import re
import shlex
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

try:
    import readline as _READLINE
except ImportError:  # pragma: no cover - platform dependent
    _READLINE = None

from . import __version__
from .engine.calibration import (
    assess_lab_provenance,
    assess_lab_differentials,
    assess_lab_stability,
    apply_calibration_to_result,
    build_signature_corpus,
    calibrate_result,
    compare_baseline,
    corpus_to_profile,
    load_corpuses,
    load_profiles,
    render_baseline_comparison,
    render_calibration,
    render_corpus_index,
    render_generated_profile,
    render_lab_differentials,
    render_lab_matrix,
    render_lab_provenance,
    render_lab_stability,
    render_lab_verification,
    render_signature_corpus,
    summarize_corpuses,
    standard_lab_matrix,
    verify_lab_corpus,
)
from .engine.enterprise import (
    ENTERPRISE_BUNDLE_FORMATS,
    ENTERPRISE_EXPORT_FORMATS,
    bundle_manifest_to_json,
    diff_results,
    diff_to_json,
    export_result,
    render_bundle_manifest,
    render_diff,
    render_simulation,
    simulate_fixes,
    simulation_to_json,
    write_enterprise_bundle,
)
from .engine.evidence_report import (
    build_evidence_report,
    evidence_report_to_json,
    render_evidence_report,
)
from .engine.quality import quality_gate_to_json, render_quality_gate, run_quality_gate
from .engine.validation import (
    ValidationRequest,
    render_validation,
    validate_path,
    validation_to_json,
)
from .engine.profiles import (
    list_profiles,
    load_profile,
    profile_bool,
    profile_value,
    profiles_to_json,
    render_profiles,
)
from .engine.execution import (
    ExecutionRequest,
    apply_execution_to_result,
    execute_path,
    execution_to_json,
    render_execution,
)
from .engine.modules import (
    build_module_plan,
    load_module_registry,
    module_inventory,
    module_inventory_to_json,
    module_plan_to_json,
    render_module_inventory,
    render_module_plan,
)
from .engine.opsec_policy import (
    list_opsec_policies,
    load_opsec_policy,
    opsec_policies_to_json,
    opsec_policy_to_json,
    render_opsec_policies,
    render_opsec_policy,
)
from .engine.operation_control import (
    OperationControl,
    OperationControlError,
    enforce_operation_window,
    operation_control_guardrails,
)
from .engine.routes import (
    assess_route_matrix,
    render_route_report,
    route_report_to_json,
)
from .engine.source_validation import (
    SourceCheckRequest,
    build_source_plan,
    check_sources,
    render_source_checks,
    render_source_plan,
    source_checks_to_json,
    source_plan_to_json,
)
from .engine.scope import load_scope
from .engine.schema import (
    SCHEMA_KINDS,
    render_schema_contracts,
    render_schema_validation,
    schema_contracts_to_json,
    schema_validation_to_json,
    validate_schema_path,
)
from .engine.path import build_paths
from .io import load_sources, load_targets, read_result, write_result
from .models import NoiseLevel, ScanResult, Status
from .outputs import (
    render_calculus,
    render_controls,
    render_explain,
    render_fixes,
    render_matrix,
    render_plan,
    render_plan_json,
    render_paths,
    render_report,
    render_sources,
    render_summary,
)
from .scanners import assess_targets


ANSI_STYLES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}


@dataclass(frozen=True)
class CommandSpec:
    name: str
    group: str
    purpose: str
    when_to_use: tuple[str, ...]
    required_inputs: tuple[str, ...]
    examples: tuple[str, ...]
    short_options: tuple[str, ...]
    safety_notes: tuple[str, ...]
    output_contracts: tuple[str, ...]
    common_mistakes: tuple[str, ...]
    see_also: tuple[str, ...]


COMMAND_GROUPS = {
    "Assessment": ["scan", "assess", "summary", "matrix", "sources", "paths", "rank", "explain"],
    "Evidence": ["calculus", "controls", "fixes", "plan", "evidence-report"],
    "Calibration": [
        "calibrate",
        "compare-baseline",
        "lab-matrix",
        "lab-corpus",
        "lab-verify",
        "lab-provenance",
        "lab-stability",
        "lab-diff",
        "lab-index",
        "lab-profile",
    ],
    "Route/Pivot": ["routes", "source-check", "source-plan"],
    "Validation": ["validate"],
    "Controlled Execution": ["modules", "module-plan", "run"],
    "Enterprise": ["profiles", "report", "export", "bundle", "diff", "simulate-fixes"],
    "Admin": ["help", "discover", "next", "completion", "console", "opsec", "schema", "quality-gate"],
}


SHORT_OPTION_GUIDE = {
    "Common": [
        ("-f, --format", "Select text/json/csv/html/markdown/mermaid output where the command supports formats."),
        ("-o, --out", "Write command output to a file instead of stdout."),
        ("-r, --result", "Read a RelayX result JSON file for commands that need one."),
        ("-q, --no-banner", "Suppress the banner for compact or scripted human-readable output."),
        ("--no-color", "Disable ANSI color in human-readable help and console output."),
        ("-V, --version", "Print the installed RelayX version."),
    ],
    "Assessment": [
        ("-t, --targets", "Target file, comma-separated targets, or one host."),
        ("-s, --sources", "Source profile file, comma-separated source hosts, or source metadata for path modeling."),
        ("-S, --scope", "Scope file, CIDR, host, or comma-separated scope entries."),
        ("-n, --max-noise", "Maximum source capability noise allowed in modeled paths."),
        ("-A, --auth-validation", "Enable synthetic authentication validation where supported; may create failed-logon telemetry."),
        ("-Q, --rate-limit", "Maximum target or route-check starts per minute."),
        ("-D, --delay", "Minimum delay between active starts."),
        ("-J, --jitter", "Random delay added to active start spacing."),
        ("-U, --start-after", "ISO-8601 operation window start for active assessment work."),
        ("-Z, --stop-before", "ISO-8601 operation window end for active assessment work."),
    ],
    "Validation And Execution": [
        ("-p, --path-id", "Path identifier such as PX-0001."),
        ("-m, --mode", "State-machine mode: dry-run, armed, or confirmed."),
        ("-y, --confirm", "Required with confirmed mode; intentionally not implied by any other option."),
        ("-O, --operator", "Operator identity stored in audit records."),
        ("-R, --reason", "Authorization or operational reason stored in audit records."),
        ("-A, --audit-log", "JSONL audit log path for confirmed validation or execution."),
        ("-P, --opsec-policy", "Built-in policy name or external OPSEC policy JSON."),
        ("-Q, --rate-limit", "Maximum validation action starts per minute."),
        ("-D, --delay", "Pre-action delay for confirmed validation reprobes."),
        ("-J, --jitter", "Random delay added to validation action spacing."),
        ("-L, --listener-host", "Planned listener host for source-plan or execution scope checks."),
        ("-K, --callback-host", "Planned callback host for source-plan or execution scope checks."),
    ],
    "Enterprise": [
        ("-F, --formats", "Comma-separated bundle formats for relayx bundle."),
        ("-d, --out-dir", "Directory for bundle artifacts."),
        ("-C, --project-root", "Project root for relayx quality-gate."),
        ("-k, --kind", "Schema kind for relayx schema validate."),
    ],
}


SHORT_OPTIONS_BY_COMMAND = {
    "help": ["-f/--format", "-o/--out"],
    "discover": ["-g/--group", "-f/--format", "-o/--out"],
    "next": ["-r/--result", "-p/--path-id", "-f/--format", "-o/--out"],
    "completion": ["-o/--out"],
    "console": ["-r/--result", "-p/--path-id", "-P/--opsec-policy", "-S/--scope", "-s/--script", "-H/--history-file", "-N/--no-history", "-C/--no-completion"],
    "scan": ["-p/--profile", "-t/--targets", "-s/--sources", "-S/--scope", "-o/--out", "-T/--timeout", "-w/--workers", "-n/--max-noise", "-A/--auth-validation", "-Q/--rate-limit", "-D/--delay", "-J/--jitter", "-U/--start-after", "-Z/--stop-before"],
    "routes": ["-r/--result", "-s/--sources", "-t/--targets", "-S/--scope", "-P/--target-protocol", "-O/--target-port", "-c/--connect-check", "-T/--timeout", "-Q/--rate-limit", "-D/--delay", "-J/--jitter", "-U/--start-after", "-Z/--stop-before", "-f/--format", "-o/--out"],
    "source-check": ["-s/--sources", "-S/--scope", "-n/--max-noise", "-c/--connect-check", "-T/--timeout", "-P/--opsec-policy", "-f/--format", "-o/--out"],
    "source-plan": ["-s/--sources", "-H/--source", "-c/--capability", "-S/--scope", "-L/--listener-host", "-K/--callback-host", "-n/--max-noise", "-P/--opsec-policy", "-f/--format", "-o/--out"],
    "validate": ["-r/--result", "-p/--path-id", "-m/--mode", "-y/--confirm", "-O/--operator", "-R/--reason", "-S/--scope", "-n/--max-noise", "-B/--timebox", "-A/--audit-log", "-e/--reprobe", "-u/--auth-validation", "-P/--opsec-policy", "-Q/--rate-limit", "-D/--delay", "-J/--jitter", "-U/--start-after", "-Z/--stop-before"],
    "run": ["-r/--result", "-p/--path-id", "-m/--mode", "-y/--confirm", "-O/--operator", "-R/--reason", "-S/--scope", "-L/--listener-host", "-K/--callback-host", "-M/--module", "-F/--manifests", "-P/--opsec-policy", "-A/--audit-log", "-N/--accept-non-ready"],
    "export": ["-r/--result", "-f/--format", "-o/--out"],
    "bundle": ["-r/--result", "-d/--out-dir", "-F/--formats", "-R/--no-routes", "-f/--format", "-o/--out"],
    "quality-gate": ["-C/--project-root", "-f/--format", "-o/--out"],
    "schema": ["list: -f/--format, -o/--out", "validate: -k/--kind, -f/--format, -o/--out"],
    "modules": ["-F/--manifests", "-M/--module", "-D/--no-defaults", "-f/--format", "-o/--out"],
    "module-plan": ["-r/--result", "-p/--path-id", "-F/--manifests", "-M/--module", "-D/--no-defaults", "-m/--mode", "-N/--accept-non-ready", "-f/--format", "-o/--out"],
    "evidence-report": ["-r/--result", "-f/--format", "-o/--out"],
    "lab-matrix": ["-t/--target-family", "-f/--format", "-o/--out"],
    "lab-verify": ["-c/--corpus", "-t/--target-family", "-m/--min-captures", "-f/--format", "-o/--out"],
    "lab-provenance": ["-c/--corpus", "-t/--target-family", "-f/--format", "-o/--out"],
    "lab-stability": ["-c/--corpus", "-t/--target-family", "-m/--min-captures", "-T/--stable-threshold", "-f/--format", "-o/--out"],
    "lab-diff": ["-c/--corpus", "-t/--target-family", "-m/--min-captures", "-T/--stable-threshold", "-p/--pair", "-f/--format", "-o/--out"],
}


BANNERS = [
    """
┳┓  ┓    ┏┓┏┓
┣┫┏┓┃┏┓┓┏ ┃┃
┛┗┗ ┗┗┻┗┫┗┛┗┛
        ┛
""",
    """
┌─┐┌─╴╷  ┌─┐╷ ╷╷ ╷
├┬┘├╴ │  ├─┤└┬┘┌┼┘
╵└╴└─╴└─╴╵ ╵ ╵ ╵ ╵
""",
    """
 _ __      _         _   ,
' )  )    //        ' \\ /
 /--' _  // __.  __  , X
/  \\_</_</_(_/|_/ (_/_/ \\_
                   /
                  '
""",
    """
  _
 |_)  _  |  _.    \\/
 | \\ (/_ | (_| \\/ /\\
               /
""",
    """
  ^    ^    ^    ^    ^    ^
 /R\\  /e\\  /l\\  /a\\  /y\\  /X\\
<___><___><___><___><___><___>
""",
]

COMMAND_GUIDE = {
    "help": {
        "group": "Admin",
        "purpose": "Show curated command, workflow, OPSEC, completion, and troubleshooting help.",
        "examples": [
            "relayx help",
            "relayx help getting-started",
            "relayx help run",
            "relayx help discover",
            "relayx help commands --format json",
        ],
        "notes": [
            "Human-readable help is operator-oriented; JSON help is intended for docs checks and automation.",
            "Command help uses the same CommandSpec registry that backs quality-gate checks.",
        ],
        "see_also": ["discover", "next", "commands", "workflows", "short-options", "completion"],
    },
    "discover": {
        "group": "Admin",
        "purpose": "Search RelayX commands and help topics by workflow, protocol, output format, or keyword.",
        "examples": [
            "relayx discover",
            "relayx discover epa",
            "relayx discover route --group Route/Pivot",
            "relayx discover jsonl --format json",
        ],
        "notes": [
            "Discovery is read-only and uses the same CommandSpec registry as help, completion, and quality-gate.",
            "Use this when you know the task but do not remember the exact command name.",
        ],
        "see_also": ["help", "commands", "next", "completion"],
    },
    "next": {
        "group": "Admin",
        "purpose": "Suggest the next useful RelayX commands from a result file and optional selected path.",
        "examples": [
            "relayx next",
            "relayx next --result result.json",
            "relayx next --result result.json --path-id PX-0001",
            "relayx next -r examples/tutorial/sample-result.json -p PX-0001 --format json",
        ],
        "notes": [
            "Next-step guidance is read-only. It does not perform validation, execution, export, or probing.",
            "When a result is supplied, RelayX ranks suggested commands around the current path, evidence, calibration, route, and enterprise handoff workflow.",
        ],
        "see_also": ["console", "paths", "explain", "validate", "export", "bundle"],
    },
    "completion": {
        "group": "Admin",
        "purpose": "Print shell completion scripts generated from the RelayX command registry.",
        "examples": [
            "relayx completion bash",
            "relayx completion zsh",
            "relayx completion fish",
            "relayx completion zsh --out relayx.zsh",
        ],
        "notes": [
            "Completion covers commands, help topics, common flags, output formats, schema kinds, export formats, and OPSEC policies.",
            "The generated scripts do not change command behavior; confirmed operations still require the same guardrails.",
        ],
        "see_also": ["help", "short-options", "commands"],
    },
    "console": {
        "group": "Admin",
        "purpose": "Start a local operator console with RelayX context prompts and command shortcuts.",
        "examples": [
            "relayx console",
            "relayx console --result result.json --path-id PX-0001 --opsec-policy strict",
            "relayx console --script console.txt",
            "relayx console --history-file ~/.relayx/history",
        ],
        "notes": [
            "The console is a local operator shell for repeated RelayX workflows with remembered result, path, OPSEC policy, and scope context.",
            "Console commands call existing RelayX CLI handlers and use the same validation, execution, scope, audit, and OPSEC guardrails.",
            "Interactive sessions support readline history, Up/Down navigation, Tab completion, clear/cls, history, and Ctrl-L where the terminal readline backend provides it.",
            "Use 'use result <file>', 'use path <id>', 'set opsec-policy <policy>', 'show summary', 'show paths', 'explain', 'validate', 'run', 'export', 'bundle', 'clear', 'history', and 'exit'.",
            "Use --no-history for sensitive terminals; commands that start with a space or include obvious secret-bearing flags are not persisted.",
        ],
        "see_also": ["getting-started", "run", "validate", "completion"],
    },
    "scan": {
        "group": "Assessment",
        "purpose": "Assess targets, optionally combine source profiles, and write a RelayX result JSON.",
        "examples": [
            "relayx scan --targets examples/targets.txt --out result.json",
            "relayx scan -t examples/targets.txt -o result.json",
            "relayx scan --profile enterprise --targets examples/targets.txt --sources examples/sources.csv --scope examples/scope.txt --out result.json",
            "relayx scan --targets dc01,ca01 --auth-validation --out lab-validation.json",
            "relayx scan -t examples/targets.txt -o result.json --rate-limit 120 --stop-before 2030-01-01T18:00:00+08:00",
        ],
        "notes": [
            "Default probes are readiness oriented and avoid credential relay.",
            "Sources model where authentication can originate. They do not execute source-side coercion by themselves.",
            "Scope filters targets and sources before path construction; --strict-scope fails instead of silently filtering.",
            "Use --auth-validation only when failed-logon telemetry is acceptable and explicitly authorized.",
            "--rate-limit, --delay, --jitter, --start-after, and --stop-before are recorded in result metadata and applied before target assessment starts.",
        ],
        "see_also": ["summary", "paths", "calculus", "export"],
    },
    "validate": {
        "group": "Validation",
        "purpose": "Run the guarded validation state machine for one path.",
        "examples": [
            "relayx validate --result result.json --path-id PX-0001 --mode dry-run",
            "relayx validate -r result.json -p PX-0001 -m dry-run",
            "relayx validate --result result.json --path-id PX-0001 --mode confirmed --confirm --operator redpen --reason \"authorized target reprobe\" --audit-log audit.jsonl --scope filesrv01 --reprobe",
            "relayx validate -r result.json -p PX-0001 -m confirmed -y -O redpen -R \"authorized target reprobe\" -A audit.jsonl --scope filesrv01 -e --stop-before 2030-01-01T18:00:00+08:00",
        ],
        "notes": [
            "dry-run explains guardrails and expected telemetry without probing. armed records intent without confirmed action. confirmed requires explicit confirmation, operator, reason, and audit log.",
            "Target re-probes do not execute source-side triggers or credential relay.",
            "Synthetic auth validation is separate from challenge-flow evidence and may create failed-logon telemetry.",
            "Operation windows are fail-closed for confirmed reprobes and warning-only for dry-run planning.",
        ],
        "see_also": ["run", "source-plan", "calibrate"],
    },
    "run": {
        "group": "Validation",
        "purpose": "Run the controlled execution state machine or safe offline audit adapter.",
        "examples": [
            "relayx run --result result.json --path-id PX-0001 --mode dry-run",
            "relayx run -r result.json -p PX-0001 -m dry-run",
            "relayx run --result result.json --path-id PX-0001 --module relayx_audit_record --mode confirmed --confirm --operator redpen --reason \"authorized offline audit record\" --audit-log audit.jsonl --scope filesrv01",
            "relayx run -r result.json -p PX-0001 -m dry-run -L listener01 -K callback01 -S examples/scope.txt",
        ],
        "notes": [
            "The built-in supported adapter is offline audit recording only.",
            "Execution Adapter SDK guardrails block unregistered adapters, unsafe credential policies, and unsafe listener policies.",
            "Live relay adapters remain unavailable by default.",
            "Confirmed execution requires explicit --scope in addition to confirmation, operator, reason, and audit log.",
            "--accept-non-ready changes planning eligibility only; it does not bypass confirmed-mode operator, scope, audit, or adapter guardrails.",
            "--listener-host and --callback-host are planning inputs for scope checks; they do not start listeners.",
        ],
        "see_also": ["modules", "module-plan", "validate"],
    },
    "evidence-report": {
        "group": "Analysis",
        "purpose": "Audit result evidence completeness, source taxonomy, protocol judgement fields, confidence, and remaining uncertainty.",
        "examples": [
            "relayx evidence-report --result result.json",
            "relayx evidence-report -r examples/tutorial/sample-result.json -f json -o evidence-report.json",
            "relayx schema validate -k evidence-report evidence-report.json",
        ],
        "notes": [
            "This command is offline. It reads an existing RelayX result and does not scan, validate, relay, or modify the file.",
            "Candidate or relayable records without evidence are reported as failures.",
            "Protocol judgement records are expected to expose response classification, policy inference, and remaining uncertainty so operators can see what is proven and what is not.",
            "The report classifies evidence sources as wire observation, policy inference, lab calibration, source model, route model, control mapping, operator context, error, or unsupported boundary.",
            "Use evidence-report before lab profile promotion, enterprise handoff, or release-quality fixture review.",
        ],
        "see_also": ["schema", "explain", "lab-diff", "calibrate"],
    },
    "export": {
        "group": "Enterprise",
        "purpose": "Export RelayX results for graph tools, SIEM, reporting, or automation.",
        "examples": [
            "relayx export --result result.json --format opengraph --out relayx-opengraph.json",
            "relayx export -r result.json -f jsonl -o relayx-events.jsonl",
            "relayx export --result result.json --format jsonl --out relayx-events.jsonl",
            "relayx export --result result.json --format csv --out relayx.csv",
        ],
        "notes": [
            "OpenGraph uses RelayX custom node and edge kinds, deterministic edge IDs, and in-artifact mapping.",
            "JSONL and CSV include stable field contract versions for blue-team, SIEM, and spreadsheet ingestion.",
            "HTML reports include offline filters for status, severity, protocol, source capability, target family, and defensive control.",
        ],
        "see_also": ["bundle", "report", "diff", "simulate-fixes"],
    },
    "bundle": {
        "group": "Enterprise",
        "purpose": "Write a validated enterprise handoff bundle with manifest, hashes, and schema status.",
        "examples": [
            "relayx bundle --result result.json --out-dir relayx-bundle",
            "relayx bundle -r result.json -d relayx-bundle -F opengraph,jsonl,csv",
            "relayx bundle --result result.json --out-dir relayx-bundle --formats opengraph,jsonl,csv",
        ],
        "notes": [
            "The bundle manifest records artifact paths, SHA256 hashes, sizes, schema kinds, and validation results.",
            "Route reports are included when the result contains source assets and findings.",
            "--format controls the manifest summary printed by the command; --formats controls which artifacts are written into the bundle.",
        ],
        "see_also": ["export", "schema", "quality-gate"],
    },
    "quality-gate": {
        "group": "Enterprise",
        "purpose": "Run the local CI and release quality gate over package metadata, fixtures, docs, and workflows.",
        "examples": [
            "relayx quality-gate --project-root .",
            "relayx quality-gate -C . -f json -o relayx-quality-gate.json",
            "relayx quality-gate --project-root . --format json --out relayx-quality-gate.json",
        ],
        "notes": [
            "A failed quality gate returns exit code 2.",
            "The command is designed for GitHub Actions and local release checks.",
            "The gate checks package metadata, schema coverage, fixture validity, documentation coverage, workflow presence, version consistency, and short-option coverage.",
        ],
        "see_also": ["schema", "bundle"],
    },
    "diff": {
        "group": "Enterprise",
        "purpose": "Compare two RelayX result files and show added, removed, or changed exposure.",
        "examples": [
            "relayx diff old-result.json new-result.json",
            "relayx diff old-result.json new-result.json --format json --out relayx-diff.json",
        ],
        "notes": [
            "Paths are matched by stable source, transport, target, and target service fingerprints.",
            "JSON output includes exposure trend, score delta, control trends, remediation regressions, and improvements.",
        ],
        "see_also": ["export", "simulate-fixes"],
    },
    "simulate-fixes": {
        "group": "Enterprise",
        "purpose": "Estimate path and score reduction if specific fixes or controls are implemented.",
        "examples": [
            "relayx simulate-fixes result.json --control smb_signing",
            "relayx simulate-fixes result.json --fix \"Enable EPA on AD CS Web Enrollment\" --format json",
        ],
        "notes": [
            "Simulation is read-only and does not mutate the RelayX result file.",
            "JSON output includes control dependencies, remaining controls, remaining target families, and estimated residual exposure.",
        ],
        "see_also": ["fixes", "controls", "diff"],
    },
    "lab-corpus": {
        "group": "Analysis",
        "purpose": "Extract lab calibration signatures from a RelayX result file.",
        "examples": [
            "relayx lab-corpus result.json --label iis-epa-required --policy-state epa_required --expected-state epa_or_cbt_enforcement_signal --promotion promote --reason \"stable EPA diagnostic in lab\" --format json --out corpus.json",
            "relayx lab-corpus result.json --format json",
        ],
        "notes": [
            "This command is offline: it records observed signatures from an existing result file.",
            "Use repeated lab captures before promoting generated profile states.",
            "Expected fields describe the known lab policy state, not a live target claim. Treat generated profiles as drafts until reviewed.",
        ],
        "see_also": ["calibrate", "compare-baseline", "lab-profile"],
    },
    "lab-matrix": {
        "group": "Analysis",
        "purpose": "Print the standard RelayX lab policy matrix and capture plan.",
        "examples": [
            "relayx lab-matrix",
            "relayx lab-matrix --target-family mssql_epa --format json --out lab-matrix.json",
        ],
        "notes": [
            "This command is offline and emits the policy states RelayX expects a serious lab corpus to cover.",
            "The matrix is a planning and coverage contract; it does not scan the network or promote findings.",
        ],
        "see_also": ["lab-verify", "lab-corpus", "lab-profile"],
    },
    "lab-verify": {
        "group": "Analysis",
        "purpose": "Verify lab signature corpuses against the standard RelayX lab matrix.",
        "examples": [
            "relayx lab-verify --corpus fixtures/lab_corpus",
            "relayx lab-verify -c fixtures/lab_corpus -t ldaps_cbt -m 2 -f json",
        ],
        "notes": [
            "A missing required policy state fails verification. A state with too few captures or missing signature keys returns a warning.",
            "Coverage verification does not promote findings by itself; it only checks whether the corpus is ready to support calibration review.",
        ],
        "see_also": ["lab-matrix", "lab-stability", "lab-index", "compare-baseline"],
    },
    "lab-provenance": {
        "group": "Analysis",
        "purpose": "Audit lab corpus provenance, endpoint build metadata, drift baseline, and operator review readiness.",
        "examples": [
            "relayx lab-provenance --corpus fixtures/lab_corpus",
            "relayx lab-provenance -c fixtures/lab_corpus -t mssql_epa -f json -o lab-provenance.json",
            "relayx schema validate -k lab-provenance lab-provenance.json",
        ],
        "notes": [
            "This command is offline. It does not scan, authenticate, relay, or mutate corpus files.",
            "Synthetic fixtures can satisfy the structure contract, but RelayX marks them as not real lab promotion evidence.",
            "Non-synthetic promote or block hints require provenance, endpoint build metadata, drift baseline metadata, and capture-level operator review before they are promotion-ready.",
            "Use lab-provenance before lab-profile when real lab captures are being considered for promotion.",
        ],
        "see_also": ["lab-corpus", "lab-stability", "lab-diff", "schema"],
    },
    "lab-stability": {
        "group": "Analysis",
        "purpose": "Assess repeat-capture stability, drift, and promotion downgrade gates for lab corpuses.",
        "examples": [
            "relayx lab-stability --corpus fixtures/lab_corpus",
            "relayx lab-stability -c fixtures/lab_corpus -t mssql_epa -m 3 -T 0.9 -f json",
        ],
        "notes": [
            "This command is offline. It compares recorded lab signatures for the same target family and policy state.",
            "consistency_score is the dominant stable-signature ratio. A score below --stable-threshold or any changed stable discriminator is treated as drift.",
            "Promotion hints are downgraded to retain when captures are missing, below --min-captures, missing required signature keys, or unstable.",
        ],
        "see_also": ["lab-verify", "lab-diff", "lab-profile", "compare-baseline"],
    },
    "lab-diff": {
        "group": "Analysis",
        "purpose": "Compare stable lab policy-state signatures and report response discriminators that support calibration.",
        "examples": [
            "relayx lab-diff --corpus fixtures/lab_corpus",
            "relayx lab-diff -c fixtures/lab_corpus -t http_iis_epa -p epa_off:epa_required -m 2 -f json",
        ],
        "notes": [
            "This command is offline. It compares dominant stable signatures already recorded in lab corpuses.",
            "Use lab-diff to review policy-state response differences; use compare-baseline when comparing two RelayX result files.",
            "Protocol, target family, finding name, raw HTTP status, and auth-validation presence are treated as context, not policy proof by themselves.",
            "Unmatched --pair filters are reported as warnings so typos do not silently produce an empty pass report.",
        ],
        "see_also": ["lab-stability", "compare-baseline", "lab-profile"],
    },
    "lab-profile": {
        "group": "Analysis",
        "purpose": "Generate a calibration profile draft from one or more lab signature corpuses.",
        "examples": [
            "relayx lab-profile --corpus corpus.json --profile-id http_iis_epa_lab --target-family http_iis_epa --service http --format json --out profile.json",
            "relayx lab-profile --corpus fixtures/lab_corpus --profile-id mssql_epa_lab --target-family mssql_epa",
        ],
        "notes": [
            "Generated profiles are drafts and should be reviewed before promotion decisions rely on them.",
            "The profile generator keeps stable response discriminators and avoids host-specific fields.",
        ],
        "see_also": ["lab-corpus", "calibrate"],
    },
    "lab-index": {
        "group": "Analysis",
        "purpose": "Summarize lab signature corpuses by target family, policy state, promotion, and signature group.",
        "examples": [
            "relayx lab-index --corpus fixtures/lab_corpus",
            "relayx lab-index --corpus fixtures/lab_corpus --target-family mssql_epa --format json",
        ],
        "notes": [
            "This command is offline and never generates network traffic.",
            "Use it to audit coverage before generating or promoting lab profiles.",
        ],
        "see_also": ["lab-corpus", "lab-profile", "calibrate"],
    },
    "modules": {
        "group": "Modules",
        "purpose": "List built-in and manifest-backed execution modules.",
        "examples": [
            "relayx modules",
            "relayx modules --manifests fixtures/execution_modules --format json",
        ],
        "notes": ["Unsupported modules describe future boundaries and are not executed."],
        "see_also": ["module-plan", "run"],
    },
    "module-plan": {
        "group": "Modules",
        "purpose": "Evaluate whether execution modules fit a specific RelayX path.",
        "examples": [
            "relayx module-plan --result result.json --path-id PX-0001 --module relayx_audit_record",
            "relayx module-plan --result result.json --path-id PX-0001 --manifests fixtures/execution_modules --format json",
        ],
        "notes": ["Module planning explains applicability, readiness, required inputs, artifacts, and warnings."],
        "see_also": ["modules", "run"],
    },
    "profiles": {
        "group": "Enterprise",
        "purpose": "List bundled profile defaults for repeatable team workflows.",
        "examples": [
            "relayx profiles",
            "relayx scan --profile enterprise --targets examples/targets.txt --sources examples/sources.csv --scope examples/scope.txt --out result.json",
        ],
        "notes": ["Command-line options override profile defaults."],
        "see_also": ["scan", "export"],
    },
    "source-plan": {
        "group": "Validation",
        "purpose": "Create a single-source source-trigger validation plan without executing the trigger.",
        "examples": [
            "relayx source-plan --sources examples/sources.json --source ws01 --capability webclient",
            "relayx source-plan -s examples/sources.json -H ws01 -c webclient -S examples/scope.txt -L listener01 -K callback01 -f json -o source-plan.json",
        ],
        "notes": [
            "The plan records preconditions, expected telemetry, rollback, forbidden actions, route context, scope contract, and OPSEC policy outcomes.",
            "--listener-host and --callback-host are planning inputs only; RelayX does not start listeners or execute source-side triggers.",
            "When listener or callback hosts are supplied, RelayX requires them to be inside the supplied scope.",
        ],
        "see_also": ["source-check", "validate", "opsec"],
    },
    "routes": {
        "group": "Assessment",
        "purpose": "Assess source-to-target route and pivot reachability from source profiles.",
        "examples": [
            "relayx routes --sources examples/sources.json --targets examples/targets.txt",
            "relayx routes --result result.json --format json --out relayx-routes.json",
            "relayx routes -s examples/sources.json -t examples/targets.txt -P ldap --connect-check --rate-limit 60 -f json -o relayx-routes.json",
        ],
        "notes": [
            "Route awareness is model-driven by default and does not open pivot sessions.",
            "--connect-check performs authorized direct TCP checks from the operator runtime only; it does not start, prove, or operate a pivot session.",
            "Structured route_hops and source subnets produce higher-confidence reachability than free-form route labels.",
        ],
        "see_also": ["sources", "scan", "paths"],
    },
    "schema": {
        "group": "Contracts",
        "purpose": "List and validate RelayX result, evidence, lab, execution, and export contracts.",
        "examples": [
            "relayx schema list",
            "relayx schema validate result.json",
            "relayx schema validate --kind lab-profile fixtures/lab_profiles --format json",
            "relayx schema validate --kind opengraph relayx-opengraph.json",
            "relayx schema validate --kind route-report relayx-routes.json",
            "relayx schema validate --kind opsec-policy fixtures/opsec_policies",
        ],
        "notes": [
            "Use --kind auto for inference, or pin a kind when validating a directory.",
            "Invalid files return exit code 2 and include path-level issue details.",
            "Directory validation only scans files with the suffix expected by the selected kind: JSON for most artifacts, JSONL for event streams, and CSV for spreadsheet exports.",
        ],
        "see_also": ["scan", "lab-corpus", "export", "run"],
    },
    "opsec": {
        "group": "Policy",
        "purpose": "List and inspect OPSEC policies used by validation, execution, and source planning.",
        "examples": [
            "relayx opsec list",
            "relayx opsec show --policy strict",
            "relayx validate --result result.json --path-id PX-0001 --opsec-policy strict --mode dry-run",
        ],
        "notes": [
            "Policy outcomes are embedded into validation, execution, source-check, and source-plan JSON.",
            "External JSON policy files are accepted anywhere --opsec-policy is available.",
        ],
        "see_also": ["validate", "run", "source-plan", "schema"],
    },
}

HELP_TOPICS = {
    "overview": {
        "title": "RelayX Help",
        "body": [
            "RelayX is an OPSEC-aware NTLM relay exposure assessment, lab-calibrated validation, and controlled execution orchestration tool for authorized red teaming.",
            "",
            "Common workflows:",
            "  1. Find a command      relayx discover epa",
            "  2. Assess targets      relayx scan --targets examples/targets.txt --out result.json",
            "  3. Ask what is next    relayx next --result result.json",
            "  4. Review paths        relayx paths result.json",
            "  5. Explain a path      relayx explain result.json PX-0001",
            "  6. Plan validation     relayx validate --result result.json --path-id PX-0001 --mode dry-run",
            "  7. Export enterprise   relayx export --result result.json --format jsonl --out relayx-events.jsonl",
            "",
            "Short options are available for common flags. Use 'relayx help short-options' for the alias map.",
            "",
            "Use 'relayx discover <keyword>' when you know the task but not the command.",
            "Use 'relayx help commands' for grouped commands or 'relayx help <command>' for examples.",
        ],
    },
    "commands": {
        "title": "RelayX Commands",
        "body": [],
    },
    "workflows": {
        "title": "RelayX Workflows",
        "body": [
            "Readiness:",
            "  relayx scan --targets examples/targets.txt --out result.json",
            "  relayx summary result.json",
            "  relayx matrix result.json",
            "",
            "Path analysis:",
            "  relayx paths result.json",
            "  relayx routes --result result.json",
            "  relayx calculus result.json",
            "  relayx evidence-report --result result.json",
            "  relayx controls result.json",
            "  relayx plan result.json PX-0001 --format json",
            "",
            "Lab calibration:",
            "  relayx calibrate result.json --profiles fixtures/lab_profiles",
            "  relayx lab-corpus result.json --label iis-epa-required --policy-state epa_required --format json --out corpus.json",
            "  relayx lab-index --corpus fixtures/lab_corpus",
            "  relayx lab-provenance --corpus fixtures/lab_corpus",
            "  relayx lab-stability --corpus fixtures/lab_corpus --min-captures 2",
            "  relayx lab-diff --corpus fixtures/lab_corpus --target-family http_iis_epa",
            "  relayx lab-profile --corpus corpus.json --profile-id http_iis_epa_lab --target-family http_iis_epa --format json --out profile.json",
            "",
            "Validation and controlled execution:",
            "  relayx validate --result result.json --path-id PX-0001 --mode dry-run",
            "  relayx run --result result.json --path-id PX-0001 --module relayx_audit_record --mode confirmed --confirm --operator redpen --reason \"authorized offline audit record\" --audit-log audit.jsonl --scope filesrv01",
            "",
            "Enterprise handoff:",
            "  relayx export --result result.json --format opengraph --out relayx-opengraph.json",
            "  relayx export --result result.json --format jsonl --out relayx-events.jsonl",
            "  relayx bundle --result result.json --out-dir relayx-bundle",
            "  relayx diff old-result.json new-result.json",
            "  relayx simulate-fixes result.json --control smb_signing",
            "  relayx quality-gate --project-root .",
            "",
            "Schema and evidence contracts:",
            "  relayx schema list",
            "  relayx schema validate result.json",
            "  relayx schema validate --kind lab-profile fixtures/lab_profiles",
            "  relayx schema validate --kind opsec-policy fixtures/opsec_policies",
            "  relayx schema validate --kind route-report relayx-routes.json",
        ],
    },
    "exports": {
        "title": "RelayX Enterprise Exports",
        "body": [
            "Best-fit formats:",
            "  opengraph   Graph tooling with RelayX mapping, control nodes, and deterministic edge IDs",
            "  jsonl       SIEM and blue-team pipelines with stable event contracts",
            "  csv         Spreadsheets and quick triage with a stable header contract",
            "  html        Offline report with status/severity/protocol/source/target/control filters",
            "  mermaid     Lightweight path diagrams",
            "  markdown    Text reports and documentation",
            "",
            "Examples:",
            "  relayx export --result result.json --format opengraph --out graph.json",
            "  relayx export --result result.json --format jsonl --out events.jsonl",
            "  relayx bundle --result result.json --out-dir relayx-bundle",
        ],
    },
    "short-options": {
        "title": "RelayX Short Options",
        "body": [],
    },
    "safety": {
        "title": "RelayX Safety Boundary",
        "body": [
            "RelayX is intended for systems you own or are explicitly authorized to assess.",
            "",
            "Defaults:",
            "  - No credential relay by default.",
            "  - No source-side coercion by default.",
            "  - Challenge-flow probes stop at Type2 unless --auth-validation is explicitly enabled.",
            "  - Confirmed validation and execution require operator, reason, confirmation, and audit logs; confirmed execution also requires explicit scope.",
            "  - Execution Adapter SDK blocks unregistered adapters, lab-only modules in confirmed mode, and unsafe credential or listener policies.",
            "  - Route awareness is model-driven by default; optional --connect-check uses direct TCP only and does not open pivot sessions.",
        ],
    },
    "getting-started": {
        "title": "RelayX Getting Started",
        "body": [
            "Start with a result file, then move from exposure review to evidence, routes, validation planning, and enterprise handoff.",
            "",
            "1. Assess targets:",
            "  relayx scan --targets examples/targets.txt --sources examples/sources.json --scope examples/scope.txt --out result.json",
            "",
            "2. Review the operator picture:",
            "  relayx summary result.json",
            "  relayx paths result.json",
            "  relayx routes --result result.json",
            "",
            "3. Explain evidence before acting:",
            "  relayx explain result.json PX-0001",
            "  relayx evidence-report --result result.json",
            "",
            "4. Keep active work guarded:",
            "  relayx validate --result result.json --path-id PX-0001 --mode dry-run",
            "  relayx run --result result.json --path-id PX-0001 --mode dry-run",
            "",
            "5. Hand off stable outputs:",
            "  relayx bundle --result result.json --out-dir relayx-bundle",
        ],
    },
    "calibration": {
        "title": "RelayX Calibration Workflow",
        "body": [
            "Calibration upgrades judgement only when lab profiles, baseline differences, or explicit protocol diagnostics support the promotion.",
            "",
            "Core commands:",
            "  relayx lab-matrix",
            "  relayx lab-corpus result.json --format json --out corpus.json",
            "  relayx lab-verify --corpus fixtures/lab_corpus",
            "  relayx lab-provenance --corpus fixtures/lab_corpus",
            "  relayx lab-stability --corpus fixtures/lab_corpus",
            "  relayx lab-diff --corpus fixtures/lab_corpus",
            "  relayx lab-profile --corpus corpus.json --profile-id http_iis_epa_lab --target-family http_iis_epa",
            "  relayx calibrate result.json --profiles fixtures/lab_profiles",
            "",
            "Invalid-credential rejection remains evidence of enforcement behavior only; it is not treated as proof of relayability.",
        ],
    },
    "execution": {
        "title": "RelayX Controlled Execution Workflow",
        "body": [
            "Controlled execution is a guarded state machine. The built-in supported adapter records offline audit evidence only.",
            "",
            "Dry-run first:",
            "  relayx module-plan --result result.json --path-id PX-0001 --module relayx_audit_record",
            "  relayx run --result result.json --path-id PX-0001 --mode dry-run",
            "",
            "Confirmed execution requires explicit operator identity, reason, confirmation, scope, audit log, acceptable OPSEC noise, and an allowed adapter.",
            "",
            "Live relay adapters, source-side trigger execution, listener-backed modules, and credential forwarding remain unavailable by default.",
        ],
    },
    "enterprise": {
        "title": "RelayX Enterprise Workflow",
        "body": [
            "Enterprise outputs are designed to let operators, defenders, and reporting teams consume the same result file.",
            "",
            "Common outputs:",
            "  relayx export --result result.json --format opengraph --out relayx-opengraph.json",
            "  relayx export --result result.json --format jsonl --out relayx-events.jsonl",
            "  relayx export --result result.json --format csv --out relayx.csv",
            "  relayx report result.json --format html --out relayx-report.html",
            "  relayx bundle --result result.json --out-dir relayx-bundle",
            "",
            "Use relayx diff and relayx simulate-fixes to track remediation movement and residual exposure.",
        ],
    },
    "troubleshooting": {
        "title": "RelayX Troubleshooting",
        "body": [
            "Start by validating the artifact and the command boundary.",
            "",
            "Schema and result checks:",
            "  relayx schema validate result.json",
            "  relayx evidence-report --result result.json",
            "  relayx quality-gate --project-root .",
            "",
            "Common causes:",
            "  - A command requires --result while the console context has not selected one.",
            "  - Confirmed validation or execution is missing --confirm, --operator, --reason, --scope, or --audit-log.",
            "  - A lab corpus is structurally valid but synthetic, unstable, or missing operator-reviewed provenance.",
            "  - Machine-readable output should be requested with --format json/csv/jsonl or --no-banner for compact text.",
        ],
    },
}


class RelayXHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=30, width=100)


class RelayXArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        suggestion = _parser_error_suggestion(message)
        self.print_usage(sys.stderr)
        if suggestion:
            self.exit(2, f"{self.prog}: error: {message}\n{suggestion}\n")
        self.exit(2, f"{self.prog}: error: {message}\n")


def _suggest_terms(term: str, candidates: set[str] | list[str] | tuple[str, ...], *, limit: int = 5) -> list[str]:
    normalized = term.strip().lower()
    if not normalized:
        return []
    pool = sorted({str(candidate) for candidate in candidates if str(candidate)})
    prefix = [candidate for candidate in pool if candidate.lower().startswith(normalized)]
    contains = [candidate for candidate in pool if normalized in candidate.lower() and candidate not in prefix]
    fuzzy = [
        candidate
        for candidate in difflib.get_close_matches(normalized, [candidate.lower() for candidate in pool], n=limit, cutoff=0.6)
    ]
    lower_to_original = {candidate.lower(): candidate for candidate in pool}
    ordered: list[str] = []
    for candidate in [*prefix, *contains, *(lower_to_original.get(item, item) for item in fuzzy)]:
        if candidate not in ordered:
            ordered.append(candidate)
        if len(ordered) >= limit:
            break
    return ordered


def _parser_error_suggestion(message: str) -> str:
    match = re.search(r"invalid choice: '([^']+)'", message)
    if not match:
        return ""
    term = match.group(1)
    candidates = _all_known_commands() | _help_topic_names()
    suggestions = _suggest_terms(term, candidates)
    if not suggestions:
        return "Try 'relayx discover <keyword>' or 'relayx help commands'."
    rendered = ", ".join(suggestions)
    return f"Did you mean: {rendered}? Try 'relayx discover {term}' for related commands."


def _format_banner() -> str:
    banner = random.choice(BANNERS).strip("\n")
    return f"{banner}\nRelayX {__version__} - https://github.com/RedteamNotes/RelayX"


def _color_enabled(no_color: bool = False) -> bool:
    return not no_color and "NO_COLOR" not in os.environ


def _ansi(text: str, *styles: str, enabled: bool = True) -> str:
    if not enabled or not styles:
        return text
    prefix = "".join(ANSI_STYLES[style] for style in styles if style in ANSI_STYLES)
    return f"{prefix}{text}{ANSI_STYLES['reset']}" if prefix else text


def _ansi_cell(text: str, width: int, *styles: str, enabled: bool = True) -> str:
    return _ansi(text, *styles, enabled=enabled) + (" " * max(width - len(text), 0))


def _has_no_banner(argv: list[str]) -> bool:
    return "--no-banner" in argv or "-q" in argv


def _has_no_color(argv: list[str]) -> bool:
    return "--no-color" in argv


def _strip_human_output_flags(argv: list[str]) -> tuple[list[str], bool, bool]:
    requested = _has_no_banner(argv)
    no_color = _has_no_color(argv)
    return [item for item in argv if item not in {"--no-banner", "-q", "--no-color"}], requested, no_color


def _argv_requests_argparse_help(argv: list[str]) -> bool:
    return any(item in {"-h", "--help"} for item in argv)


def _add_no_banner_arg(parser: argparse.ArgumentParser, *, visible: bool = False) -> None:
    parser.add_argument(
        "-q",
        "--no-banner",
        action="store_true",
        default=argparse.SUPPRESS if not visible else False,
        help="Suppress RelayX banner output." if visible else argparse.SUPPRESS,
    )


def _add_no_color_arg(parser: argparse.ArgumentParser, *, visible: bool = False) -> None:
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS if not visible else False,
        help="Disable ANSI color in human-readable help and console output." if visible else argparse.SUPPRESS,
    )


def _add_operation_control_args(parser: argparse.ArgumentParser, *, subject: str) -> None:
    parser.add_argument(
        "-Q",
        "--rate-limit",
        type=int,
        default=0,
        help=f"Maximum {subject} starts per minute. Zero means no explicit rate limit.",
    )
    parser.add_argument(
        "-D",
        "--delay",
        type=float,
        default=0.0,
        help=f"Minimum delay in seconds between {subject} starts.",
    )
    parser.add_argument(
        "-J",
        "--jitter",
        type=float,
        default=0.0,
        help="Optional random jitter in seconds added to configured delays.",
    )
    parser.add_argument(
        "-U",
        "--start-after",
        default="",
        help="ISO-8601 operation window start. Naive values use local timezone.",
    )
    parser.add_argument(
        "-Z",
        "--stop-before",
        default="",
        help="ISO-8601 operation window end. Active work is blocked after this time.",
    )


def _operation_control_from_args(args: argparse.Namespace) -> OperationControl:
    return OperationControl.from_values(
        rate_limit_per_minute=getattr(args, "rate_limit", 0),
        delay_seconds=getattr(args, "delay", 0.0),
        jitter_seconds=getattr(args, "jitter", 0.0),
        start_after=getattr(args, "start_after", ""),
        stop_before=getattr(args, "stop_before", ""),
    )


def _should_emit_banner(args: argparse.Namespace) -> bool:
    if getattr(args, "no_banner", False):
        return False
    command = getattr(args, "command", "")
    fmt = str(getattr(args, "format", "text") or "text").lower()
    if fmt in {"json", "csv", "html", "markdown", "md", "mermaid", "mmd"}:
        return False
    if command in {"export", "report", "completion"}:
        return False
    if command == "console" and getattr(args, "script", ""):
        return False
    return True


def _add_common_result_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("result", help="RelayX JSON result file")


def _top_level_epilog() -> str:
    return textwrap.dedent(
        """
        Operator workflows:
          Assessment          scan, summary, matrix, paths, explain
          Evidence            evidence-report, calculus, controls, fixes
          Calibration         lab-matrix, lab-corpus, lab-verify, lab-profile
          Route/Pivot         routes, source-check, source-plan
          Validation          validate
          Controlled Execution modules, module-plan, run
          Enterprise          export, bundle, diff, simulate-fixes
          Admin               help, discover, next, console, completion, opsec, schema

        Help:
          relayx discover epa          Search commands and topics by task
          relayx next --result result.json  Show what to do after a scan
          relayx help getting-started  First result-to-handoff workflow
          relayx help commands         Grouped command index
          relayx help short-options    Short flag aliases and caveats
          relayx help opsec            OPSEC policy and guardrail workflow
          relayx help completion       Shell completion setup
          relayx help <command>        Contextual command guide

        Common starts:
          relayx scan --targets examples/targets.txt --out result.json
          relayx next --result result.json
          relayx console --result result.json
          relayx paths result.json
          relayx export --result result.json --format jsonl --out relayx-events.jsonl
          relayx bundle --result result.json --out-dir relayx-bundle
          relayx quality-gate --project-root .
        """
    ).strip()


def _render_help_topic(topic: str) -> dict:
    normalized = topic.strip().lower() if topic else "overview"
    if normalized in {"overview", "intro", "start"}:
        return _topic_payload("overview", HELP_TOPICS["overview"]["title"], HELP_TOPICS["overview"]["body"])
    if normalized in {"commands", "command"}:
        return _commands_payload()
    if normalized in {"short-options", "short", "aliases", "options"}:
        return _short_options_payload()
    if normalized in HELP_TOPICS:
        data = HELP_TOPICS[normalized]
        return _topic_payload(normalized, data["title"], data["body"])
    command_specs = _get_command_specs()
    if normalized in command_specs:
        return _command_spec_payload(command_specs[normalized])
    return {
        "topic": normalized,
        "title": "Unknown Help Topic",
        "error": f"No help topic or command matched {topic!r}.",
        "available_topics": sorted(_help_topic_names()),
        "available_commands": sorted(command_specs),
    }


def _topic_payload(topic: str, title: str, body: list[str]) -> dict:
    return {"topic": topic, "title": title, "body": body}


def _commands_payload() -> dict:
    command_specs = _get_command_specs()
    rows = []
    for group, commands in COMMAND_GROUPS.items():
        rows.append(
            {
                "group": group,
                "commands": [
                    {
                        "name": command,
                        "purpose": command_specs[command].purpose,
                    }
                    for command in commands
                ],
            }
        )
    return {
        "topic": "commands",
        "title": "RelayX Commands",
        "groups": rows,
    }


def _short_options_payload() -> dict:
    command_specs = _get_command_specs()
    return {
        "topic": "short-options",
        "title": "RelayX Short Options",
        "groups": [
            {
                "group": group,
                "options": [{"option": option, "meaning": meaning} for option, meaning in rows],
            }
            for group, rows in SHORT_OPTION_GUIDE.items()
        ],
        "commands": [
            {
                "command": command,
                "aliases": list(command_specs[command].short_options),
            }
            for command in sorted(SHORT_OPTIONS_BY_COMMAND)
        ],
        "notes": [
            "Short options are aliases for the corresponding long options; long options remain the clearest form in scripts and documentation.",
            "Short options are scoped per command. The same short flag may have a different meaning in a different command when the command context is unambiguous.",
            "Safety-critical options such as --confirm and --auth-validation still require explicit operator intent; aliases do not weaken guardrails.",
        ],
    }


def _all_known_commands() -> set[str]:
    return set(_get_command_specs())


def _command_group(command: str) -> str:
    for group, commands in COMMAND_GROUPS.items():
        if command in commands:
            return group
    return "General"


def _fallback_command_purpose(command: str) -> str:
    fallback = {
        "help": "Show curated help, workflows, examples, and safety notes.",
        "discover": "Search RelayX commands and help topics by workflow, protocol, output format, or keyword.",
        "next": "Suggest next useful RelayX commands from a result file and optional selected path.",
        "completion": "Print shell completion scripts generated from the RelayX command registry.",
        "console": "Start a local operator console with RelayX context prompts and command shortcuts.",
        "assess": "Alias for scan.",
        "summary": "Summarize findings and paths.",
        "matrix": "Show readiness by host and protocol.",
        "sources": "Show modeled source assets.",
        "routes": "Assess route and pivot reachability from source profiles.",
        "paths": "List relay candidate paths.",
        "rank": "Rank paths by RelayX score.",
        "explain": "Explain one host or path ID.",
        "calculus": "Show RelayX rule decisions and hardening gates.",
        "controls": "Show defensive control priorities.",
        "evidence-report": "Audit evidence completeness, source taxonomy, and protocol judgement fields.",
        "fixes": "Show remediation priorities.",
        "plan": "Create an OPSEC-aware dry-run plan for one path.",
        "calibrate": "Apply lab calibration profiles.",
        "compare-baseline": "Compare lab baseline and candidate signatures.",
        "lab-stability": "Assess repeat-capture lab signature stability and drift.",
        "lab-provenance": "Audit lab corpus provenance, endpoint build metadata, drift baselines, and operator review readiness.",
        "lab-diff": "Compare stable lab policy-state response differentials.",
        "source-check": "Check modeled source capabilities without triggers.",
        "source-plan": "Create a source-trigger validation plan without executing it.",
        "report": "Render report artifacts.",
    }
    return fallback.get(command, "RelayX command.")


REQUIRED_INPUTS_BY_COMMAND = {
    "scan": ("--targets or profile targets",),
    "assess": ("--targets or profile targets",),
    "summary": ("result",),
    "matrix": ("result",),
    "sources": ("result",),
    "routes": ("--result or --sources plus --targets",),
    "source-check": ("--sources",),
    "source-plan": ("--sources", "--source", "--capability"),
    "paths": ("result",),
    "calculus": ("result",),
    "controls": ("result",),
    "calibrate": ("result", "--profiles when using external calibration profiles"),
    "compare-baseline": ("--baseline", "--candidate"),
    "lab-corpus": ("result",),
    "lab-index": ("--corpus",),
    "lab-verify": ("--corpus",),
    "lab-provenance": ("--corpus",),
    "lab-stability": ("--corpus",),
    "lab-diff": ("--corpus",),
    "lab-profile": ("--corpus", "--profile-id", "--target-family"),
    "validate": ("--result", "--path-id"),
    "rank": ("result",),
    "explain": ("result", "host or path ID"),
    "fixes": ("result",),
    "plan": ("result", "path_id"),
    "evidence-report": ("--result",),
    "report": ("result",),
    "export": ("--result", "--format"),
    "bundle": ("--result", "--out-dir"),
    "diff": ("old result", "new result"),
    "simulate-fixes": ("result", "--fix or --control"),
    "opsec": ("list or show action",),
    "schema": ("list or validate action",),
    "modules": ("optional --manifests",),
    "module-plan": ("--result", "--path-id"),
    "run": ("--result", "--path-id"),
    "completion": ("shell: bash, zsh, or fish",),
    "console": ("optional --result and --path-id context",),
    "discover": ("optional search query", "optional --group filter"),
    "next": ("optional --result", "optional --path-id"),
}


OUTPUT_CONTRACTS_BY_COMMAND = {
    "scan": ("RelayX result JSON", "human summary"),
    "assess": ("RelayX result JSON", "human summary"),
    "report": ("json", "markdown", "html", "mermaid", "csv"),
    "export": tuple(sorted(ENTERPRISE_EXPORT_FORMATS)),
    "bundle": ("enterprise bundle manifest", "json or text manifest summary"),
    "diff": ("text", "json"),
    "simulate-fixes": ("text", "json"),
    "quality-gate": ("quality-gate schema", "text or json"),
    "schema": ("schema catalog", "schema validation report"),
    "completion": ("bash", "zsh", "fish"),
    "console": ("interactive text", "scripted text"),
    "discover": ("text", "json"),
    "next": ("text", "json"),
}


COMMON_MISTAKES_BY_COMMAND = {
    "validate": (
        "Using confirmed mode without --confirm, --operator, --reason, --scope, or --audit-log.",
        "Treating synthetic auth rejection as proof of relayability.",
    ),
    "run": (
        "Expecting the built-in adapter to perform live relay; it records offline audit evidence only.",
        "Using --accept-non-ready as a bypass. It changes planning eligibility only.",
    ),
    "source-plan": (
        "Assuming listener or callback planning inputs start infrastructure. They are scope-check inputs only.",
    ),
    "routes": (
        "Treating --connect-check as pivot validation. It performs direct TCP checks from the operator runtime only.",
    ),
    "lab-profile": (
        "Promoting synthetic, unstable, or unreviewed corpus data into authoritative policy judgement.",
    ),
    "completion": (
        "Expecting completion to imply authorization or safety approval. It only suggests syntax.",
    ),
    "console": (
        "Running a contextual console command before selecting the required result or path.",
    ),
    "discover": (
        "Searching only exact command names. Use workflow terms such as epa, route, jsonl, lab, opsec, or execution.",
    ),
    "next": (
        "Treating next-step guidance as execution. It only prints suggested commands.",
    ),
}


SAFETY_NOTES_BY_GROUP = {
    "Assessment": ("Default assessment avoids credential relay and source-side coercion.",),
    "Evidence": ("Evidence commands are offline unless they read an already-produced result file.",),
    "Calibration": ("Calibration promotion requires reviewed lab evidence or explicit protocol diagnostics.",),
    "Route/Pivot": ("Route awareness is model-driven by default and does not open pivot sessions.",),
    "Validation": ("Confirmed validation requires explicit operator intent and audit context.",),
    "Controlled Execution": ("Live relay adapters and listener-backed execution remain unavailable by default.",),
    "Enterprise": ("Enterprise outputs remain machine-clean and banner-free for structured formats.",),
    "Admin": ("Administrative commands do not weaken validation, execution, scope, or audit guardrails.",),
}


def _help_topic_names() -> set[str]:
    return {*HELP_TOPICS, "commands", "short-options"}


def _get_command_specs() -> dict[str, CommandSpec]:
    specs: dict[str, CommandSpec] = {}
    for group, commands in COMMAND_GROUPS.items():
        for command in commands:
            guide = COMMAND_GUIDE.get(command, {})
            purpose = str(guide.get("purpose") or _fallback_command_purpose(command))
            examples = tuple(guide.get("examples") or (f"relayx {command} -h",))
            notes = tuple(guide.get("notes") or ())
            see_also = tuple(guide.get("see_also") or ())
            specs[command] = CommandSpec(
                name=command,
                group=group,
                purpose=purpose,
                when_to_use=_when_to_use(command, group, purpose),
                required_inputs=tuple(REQUIRED_INPUTS_BY_COMMAND.get(command, ("Use relayx help " + command + " or relayx " + command + " -h.",))),
                examples=examples,
                short_options=tuple(SHORT_OPTIONS_BY_COMMAND.get(command, ())),
                safety_notes=tuple(notes or SAFETY_NOTES_BY_GROUP.get(group, ())),
                output_contracts=tuple(OUTPUT_CONTRACTS_BY_COMMAND.get(command, _default_output_contracts(command))),
                common_mistakes=tuple(COMMON_MISTAKES_BY_COMMAND.get(command, _default_common_mistakes(command, group))),
                see_also=see_also or _default_see_also(command, group),
            )
    return specs


def _when_to_use(command: str, group: str, purpose: str) -> tuple[str, ...]:
    if command == "console":
        return ("Use when you want a local operator workflow with remembered result, path, policy, and scope context.",)
    if command == "completion":
        return ("Use during workstation setup so shells can suggest RelayX commands, flags, formats, policies, and help topics.",)
    if group == "Calibration":
        return ("Use when judgement quality depends on lab corpus coverage, provenance, stability, or response differentials.",)
    if group == "Controlled Execution":
        return ("Use after assessment and evidence review, while preserving explicit scope, audit, and OPSEC guardrails.",)
    if group == "Enterprise":
        return ("Use when the same RelayX result needs to support operators, defenders, reporting, or automation.",)
    return (purpose.rstrip("."),)


def _default_output_contracts(command: str) -> tuple[str, ...]:
    if command in SHORT_OPTIONS_BY_COMMAND:
        return ("text", "json where -f/--format is available")
    if command in {"summary", "matrix", "sources", "paths", "rank", "explain", "fixes", "calculus", "controls"}:
        return ("human-readable text",)
    return ("See relayx " + command + " -h for supported outputs.",)


def _default_common_mistakes(command: str, group: str) -> tuple[str, ...]:
    if group in {"Validation", "Controlled Execution"}:
        return ("Skipping dry-run review before armed or confirmed work.",)
    if group == "Calibration":
        return ("Confusing structural fixture validity with operator-reviewed lab promotion readiness.",)
    if command == "schema":
        return ("Relying on auto inference for mixed directories; pin --kind when validating a directory.",)
    return ("Using the command without first checking the required input boundary.",)


def _default_see_also(command: str, group: str) -> tuple[str, ...]:
    defaults = {
        "Assessment": ("paths", "evidence-report", "routes"),
        "Evidence": ("explain", "calibrate", "schema"),
        "Calibration": ("lab-matrix", "lab-verify", "lab-profile"),
        "Route/Pivot": ("sources", "source-plan", "paths"),
        "Validation": ("plan", "run", "opsec"),
        "Controlled Execution": ("validate", "opsec", "schema"),
        "Enterprise": ("schema", "quality-gate", "completion"),
        "Admin": ("commands", "short-options", "troubleshooting"),
    }
    return tuple(item for item in defaults.get(group, ()) if item != command)


def _command_spec_payload(spec: CommandSpec) -> dict:
    return {
        "topic": spec.name,
        "kind": "command",
        "title": f"relayx {spec.name}",
        "group": spec.group,
        "purpose": spec.purpose,
        "when_to_use": list(spec.when_to_use),
        "required_inputs": list(spec.required_inputs),
        "examples": list(spec.examples),
        "short_options": list(spec.short_options),
        "safety_notes": list(spec.safety_notes),
        "output_contracts": list(spec.output_contracts),
        "common_mistakes": list(spec.common_mistakes),
        "see_also": list(spec.see_also),
    }


def _format_help_payload(payload: dict, *, color: bool = False) -> str:
    if "error" in payload:
        lines = [_ansi(payload["title"], "bold", "red", enabled=color), "", _ansi(payload["error"], "red", enabled=color), ""]
        lines.append("Available topics: " + ", ".join(payload["available_topics"]))
        lines.append("Available commands: " + ", ".join(payload["available_commands"]))
        return "\n".join(lines)
    if payload["topic"] == "commands":
        lines = [_ansi(payload["title"], "bold", "cyan", enabled=color), ""]
        for group in payload["groups"]:
            lines.append(_ansi(f"{group['group']}:", "bold", "yellow", enabled=color))
            for command in group["commands"]:
                lines.append(f"  {_ansi_cell(command['name'], 18, 'green', enabled=color)} {command['purpose']}")
            lines.append("")
        lines.append(_ansi("Use 'relayx help <command>' for focused examples.", "dim", enabled=color))
        return "\n".join(lines).rstrip()
    if payload["topic"] == "short-options":
        lines = [_ansi(payload["title"], "bold", "cyan", enabled=color), ""]
        for group in payload["groups"]:
            lines.append(_ansi(f"{group['group']}:", "bold", "yellow", enabled=color))
            for row in group["options"]:
                lines.append(f"  {_ansi_cell(row['option'], 24, 'green', enabled=color)} {row['meaning']}")
            lines.append("")
        lines.append(_ansi("Notes:", "bold", "yellow", enabled=color))
        for note in payload.get("notes", []):
            _append_wrapped(lines, note, initial="  - ", subsequent="    ")
        lines.extend(["", _ansi("Command Alias Map:", "bold", "yellow", enabled=color)])
        for row in payload.get("commands", []):
            aliases = ", ".join(row.get("aliases", []))
            lines.append(f"  {_ansi_cell(row['command'], 18, 'green', enabled=color)} {aliases}")
        return "\n".join(lines).rstrip()
    if payload.get("kind") == "command":
        lines = [_ansi(payload["title"], "bold", "cyan", enabled=color), ""]
        lines.append(f"{_ansi('Group:', 'bold', 'yellow', enabled=color)} {payload['group']}")
        lines.extend(["", _ansi("What it does:", "bold", "yellow", enabled=color)])
        _append_wrapped(lines, payload["purpose"], initial="  ", subsequent="  ")
        lines.extend(["", _ansi("When to use:", "bold", "yellow", enabled=color)])
        for item in payload.get("when_to_use", []):
            _append_wrapped(lines, item, initial="  - ", subsequent="    ")
        lines.extend(["", _ansi("Required inputs:", "bold", "yellow", enabled=color)])
        for item in payload.get("required_inputs", []):
            _append_wrapped(lines, item, initial="  - ", subsequent="    ")
        if payload.get("safety_notes"):
            lines.extend(["", _ansi("Safety notes:", "bold", "yellow", enabled=color)])
            for note in payload["safety_notes"]:
                _append_wrapped(lines, note, initial="  - ", subsequent="    ")
        lines.extend(["", _ansi("Examples:", "bold", "yellow", enabled=color)])
        for example in payload["examples"]:
            lines.append(f"  {_ansi(example, 'green', enabled=color)}")
        if payload.get("short_options"):
            lines.extend(["", _ansi("Short options:", "bold", "yellow", enabled=color)])
            for option in payload["short_options"]:
                lines.append(f"  {_ansi(option, 'green', enabled=color)}")
        if payload.get("output_contracts"):
            lines.extend(["", _ansi("Output formats and contracts:", "bold", "yellow", enabled=color)])
            for item in payload["output_contracts"]:
                _append_wrapped(lines, item, initial="  - ", subsequent="    ")
        if payload.get("common_mistakes"):
            lines.extend(["", _ansi("Common mistakes:", "bold", "yellow", enabled=color)])
            for item in payload["common_mistakes"]:
                _append_wrapped(lines, item, initial="  - ", subsequent="    ")
        if payload.get("see_also"):
            links = ", ".join(f"relayx help {item}" for item in payload["see_also"])
            lines.extend(["", f"{_ansi('Next steps:', 'bold', 'yellow', enabled=color)} {links}"])
        return "\n".join(lines)
    return "\n".join([_ansi(payload["title"], "bold", "cyan", enabled=color), "", *payload["body"]])


def _append_wrapped(lines: list[str], text: str, *, initial: str, subsequent: str, width: int = 100) -> None:
    wrapped = textwrap.wrap(text, width=width, initial_indent=initial, subsequent_indent=subsequent)
    lines.extend(wrapped or [initial.rstrip()])


def _write_or_print(output: str, path: str | None) -> None:
    if path:
        Path(path).write_text(output, encoding="utf-8")
        print(f"Wrote {path}")
    else:
        print(output)


def _split_csv_arg(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _words(values: list[str] | tuple[str, ...] | set[str]) -> str:
    return " ".join(sorted(str(value) for value in values if str(value)))


def _completion_option_words() -> list[str]:
    options = {"-h", "--help", "-V", "--version", "-q", "--no-banner", "--no-color"}
    for spec in _get_command_specs().values():
        for entry in spec.short_options:
            for option in entry.replace(",", " ").split():
                if "/" in option:
                    options.update(part for part in option.split("/") if part.startswith("-"))
                elif option.startswith("-"):
                    options.add(option)
    return sorted(options)


def _completion_model() -> dict[str, list[str]]:
    specs = _get_command_specs()
    policies = [str(row.get("name")) for row in list_opsec_policies()]
    formats = {"text", "json", "csv", "html", "markdown", "md", "mermaid", "mmd", *ENTERPRISE_EXPORT_FORMATS}
    return {
        "commands": sorted(specs),
        "topics": sorted(_help_topic_names() | set(specs)),
        "options": _completion_option_words(),
        "formats": sorted(formats),
        "schema_kinds": ["auto", *SCHEMA_KINDS],
        "export_formats": sorted(ENTERPRISE_EXPORT_FORMATS),
        "opsec_policies": sorted(policies),
    }


def render_completion(shell: str) -> str:
    model = _completion_model()
    commands = _words(model["commands"])
    topics = _words(model["topics"])
    options = _words(model["options"])
    formats = _words(model["formats"])
    schema_kinds = _words(model["schema_kinds"])
    export_formats = _words(model["export_formats"])
    policies = _words(model["opsec_policies"])
    if shell == "bash":
        return textwrap.dedent(
            f"""
            # RelayX completion generated from the CommandSpec registry.
            _relayx_completion() {{
              local cur prev command
              COMPREPLY=()
              cur="${{COMP_WORDS[COMP_CWORD]}}"
              prev="${{COMP_WORDS[COMP_CWORD-1]}}"
              command="${{COMP_WORDS[1]}}"
              if [[ "$command" == "export" && ("$prev" == "--format" || "$prev" == "-f") ]]; then
                COMPREPLY=($(compgen -W "{export_formats}" -- "$cur")); return 0
              fi
              case "$prev" in
                relayx) COMPREPLY=($(compgen -W "{commands}" -- "$cur")); return 0 ;;
                help) COMPREPLY=($(compgen -W "{topics}" -- "$cur")); return 0 ;;
                completion) COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")); return 0 ;;
                --format|-f) COMPREPLY=($(compgen -W "{formats}" -- "$cur")); return 0 ;;
                --kind|-k) COMPREPLY=($(compgen -W "{schema_kinds}" -- "$cur")); return 0 ;;
                --opsec-policy|-P|--policy) COMPREPLY=($(compgen -W "{policies}" -- "$cur")); return 0 ;;
              esac
              if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "{options}" -- "$cur")); return 0
              fi
              COMPREPLY=($(compgen -W "{commands}" -- "$cur"))
              return 0
            }}
            complete -F _relayx_completion relayx
            """
        ).strip()
    if shell == "zsh":
        return textwrap.dedent(
            f"""
            #compdef relayx
            # RelayX completion generated from the CommandSpec registry.
            _relayx() {{
              local -a commands topics options formats schema_kinds export_formats policies
              commands=({commands})
              topics=({topics})
              options=({options})
              formats=({formats})
              schema_kinds=({schema_kinds})
              export_formats=({export_formats})
              policies=({policies})
              case "$words[2]" in
                help) _describe 'RelayX help topics' topics ;;
                completion) _values 'shell' bash zsh fish ;;
                export)
                  if [[ "$words[CURRENT-1]" == "--format" || "$words[CURRENT-1]" == "-f" ]]; then
                    _describe 'RelayX export formats' export_formats
                  else
                    _describe 'RelayX options' options
                  fi ;;
                schema)
                  if [[ "$words[CURRENT-1]" == "--kind" || "$words[CURRENT-1]" == "-k" ]]; then
                    _describe 'RelayX schema kinds' schema_kinds
                  else
                    _describe 'RelayX options' options
                  fi ;;
                *)
                  if [[ "$words[CURRENT-1]" == "--opsec-policy" || "$words[CURRENT-1]" == "-P" || "$words[CURRENT-1]" == "--policy" ]]; then
                    _describe 'RelayX OPSEC policies' policies
                  elif [[ "$words[CURRENT]" == -* ]]; then
                    _describe 'RelayX options' options
                  else
                    _describe 'RelayX commands' commands
                  fi ;;
              esac
            }}
            _relayx "$@"
            """
        ).strip()
    if shell == "fish":
        lines = [
            "# RelayX completion generated from the CommandSpec registry.",
            "complete -c relayx -f",
        ]
        for command in model["commands"]:
            spec = _get_command_specs()[command]
            lines.append(f"complete -c relayx -n '__fish_use_subcommand' -a {shlex.quote(command)} -d {shlex.quote(spec.purpose)}")
        for topic in model["topics"]:
            lines.append(f"complete -c relayx -n '__fish_seen_subcommand_from help' -a {shlex.quote(topic)}")
        for shell_name in ("bash", "zsh", "fish"):
            lines.append(f"complete -c relayx -n '__fish_seen_subcommand_from completion' -a {shell_name}")
        for fmt in model["formats"]:
            lines.append(f"complete -c relayx -n '__fish_seen_argument -l format -s f' -a {fmt}")
        for kind in model["schema_kinds"]:
            lines.append(f"complete -c relayx -n '__fish_seen_argument -l kind -s k' -a {kind}")
        for policy in model["opsec_policies"]:
            lines.append(f"complete -c relayx -n '__fish_seen_argument -l opsec-policy -s P; or __fish_seen_argument -l policy' -a {policy}")
        return "\n".join(lines)
    raise ValueError(f"Unsupported completion shell: {shell}")


def _discover_payload(query: str = "", *, group: str = "") -> dict:
    normalized_query = query.strip().lower()
    normalized_group = group.strip().lower()
    command_specs = _get_command_specs()
    rows: list[dict[str, object]] = []
    for spec in command_specs.values():
        if normalized_group and spec.group.lower() != normalized_group:
            continue
        if normalized_query and spec.name == "discover" and normalized_query not in {"discover", "search", "find"}:
            continue
        searchable = " ".join(
            [
                spec.name,
                spec.group,
                spec.purpose,
                " ".join(spec.examples),
                " ".join(spec.safety_notes),
                " ".join(spec.output_contracts),
                " ".join(spec.see_also),
            ]
        ).lower()
        score = _discovery_score(normalized_query, spec.name, searchable)
        if normalized_query:
            output_text = " ".join(spec.output_contracts).lower()
            example_text = " ".join(spec.examples).lower()
            purpose_text = spec.purpose.lower()
            if normalized_query in output_text:
                score = max(score, 90)
            elif normalized_query in example_text:
                score = max(score, 55)
            elif normalized_query in purpose_text:
                score = max(score, 50)
            if spec.name == "export" and normalized_query in ENTERPRISE_EXPORT_FORMATS:
                score = max(score, 100)
        if normalized_query and score == 0:
            continue
        rows.append(
            {
                "kind": "command",
                "name": spec.name,
                "group": spec.group,
                "purpose": spec.purpose,
                "example": _best_discovery_example(spec.examples, normalized_query) if spec.examples else f"relayx help {spec.name}",
                "see_also": list(spec.see_also),
                "score": score,
            }
        )
    for topic in sorted(_help_topic_names() - set(command_specs)):
        if normalized_group:
            continue
        payload = _render_help_topic(topic)
        body = " ".join(str(item) for item in payload.get("body", []))
        searchable = f"{topic} {payload.get('title', '')} {body}".lower()
        score = _discovery_score(normalized_query, topic, searchable)
        if normalized_query and score == 0:
            continue
        rows.append(
            {
                "kind": "topic",
                "name": topic,
                "group": "Help",
                "purpose": str(payload.get("title", topic)),
                "example": f"relayx help {topic}",
                "see_also": [],
                "score": score,
            }
        )
    rows.sort(key=lambda row: (-int(row["score"]), str(row["group"]), str(row["name"])))
    return {
        "query": query,
        "group": group,
        "matches": rows,
        "suggestions": _suggest_terms(query, set(command_specs) | _help_topic_names()) if query else [],
    }


def _discovery_score(query: str, name: str, searchable: str) -> int:
    if not query:
        return 1
    lowered_name = name.lower()
    if lowered_name == query:
        return 100
    if lowered_name.startswith(query):
        return 80
    if query in lowered_name:
        return 70
    if query in searchable:
        return 40
    query_terms = [term for term in re.split(r"[^a-z0-9_-]+", query) if term]
    if query_terms and all(term in searchable for term in query_terms):
        return 30
    return 0


def _best_discovery_example(examples: tuple[str, ...], query: str) -> str:
    if query:
        for example in examples:
            if query in example.lower():
                return example
    return examples[0]


def render_discovery(payload: dict, *, color: bool = False) -> str:
    query = str(payload.get("query") or "")
    group = str(payload.get("group") or "")
    matches = list(payload.get("matches") or [])
    title = "RelayX Command Discovery"
    if query:
        title += f" - {query}"
    lines = [_ansi(title, "bold", "cyan", enabled=color)]
    if group:
        lines.append(f"{_ansi('Group filter:', 'bold', 'yellow', enabled=color)} {group}")
    lines.append("")
    if not matches:
        lines.append("No matching commands or topics.")
        suggestions = payload.get("suggestions") or []
        if suggestions:
            lines.append("Did you mean: " + ", ".join(str(item) for item in suggestions))
        lines.append("Try: relayx discover route, relayx discover epa, relayx discover jsonl, or relayx help commands")
        return "\n".join(lines)
    for row in matches[:20]:
        label = f"{row['name']} ({row['kind']}, {row['group']})"
        lines.append(_ansi(label, "bold", "green", enabled=color))
        _append_wrapped(lines, str(row["purpose"]), initial="  ", subsequent="  ")
        lines.append(f"  try: {_ansi(str(row['example']), 'cyan', enabled=color)}")
        if row.get("see_also"):
            lines.append(f"  see also: {', '.join(str(item) for item in row['see_also'])}")
        lines.append("")
    if len(matches) > 20:
        lines.append(f"... {len(matches) - 20} more match(es). Narrow with a keyword or --group.")
    lines.append("Use 'relayx help <command>' for full syntax, or 'relayx next --result result.json' after a scan.")
    return "\n".join(lines).rstrip()


def _next_payload(result_path: str = "", *, path_id: str = "") -> dict:
    if not result_path:
        return {
            "result": "",
            "path_id": path_id,
            "state": "no_result",
            "summary": "No result selected yet.",
            "steps": [
                _next_step("discover", "Find the right workflow", "relayx discover epa"),
                _next_step("scan", "Create a RelayX result", "relayx scan --targets examples/targets.txt --out result.json"),
                _next_step("console", "Use an interactive workflow", "relayx console --result result.json"),
                _next_step("help", "Read the first-run workflow", "relayx help getting-started"),
            ],
        }
    result = read_result(result_path)
    paths = sorted(result.paths, key=lambda item: item.score, reverse=True)
    selected = next((item for item in paths if item.id == path_id), None) if path_id else None
    status_counts: dict[str, int] = {}
    for path in paths:
        status_counts[path.status.value] = status_counts.get(path.status.value, 0) + 1
    if path_id and not selected:
        return {
            "result": result_path,
            "path_id": path_id,
            "state": "path_not_found",
            "summary": f"Path {path_id} was not found in {result_path}.",
            "status_counts": status_counts,
            "top_paths": [_path_summary(path) for path in paths[:5]],
            "steps": [
                _next_step("paths", "List available path IDs", f"relayx paths {result_path}"),
                _next_step("rank", "Rank available paths", f"relayx rank {result_path}"),
                _next_step("console", "Select a path interactively", f"relayx console --result {shlex.quote(result_path)}"),
            ],
        }
    if selected:
        return {
            "result": result_path,
            "path_id": path_id,
            "state": "path_selected",
            "summary": f"{selected.id}: {selected.summary}",
            "selected_path": _path_summary(selected),
            "status_counts": status_counts,
            "steps": [
                _next_step("explain", "Understand why RelayX made this judgement", f"relayx explain {shlex.quote(result_path)} {selected.id}"),
                _next_step("plan", "Generate a dry-run validation plan", f"relayx plan {shlex.quote(result_path)} {selected.id}"),
                _next_step("evidence-report", "Audit evidence completeness before promotion", f"relayx evidence-report --result {shlex.quote(result_path)}"),
                _next_step("routes", "Review route and pivot context", f"relayx routes --result {shlex.quote(result_path)}"),
                _next_step("validate", "Run guarded dry-run validation", f"relayx validate --result {shlex.quote(result_path)} --path-id {selected.id} --mode dry-run"),
                _next_step("module-plan", "Review controlled execution adapter readiness", f"relayx module-plan --result {shlex.quote(result_path)} --path-id {selected.id}"),
                _next_step("export", "Prepare enterprise JSONL output", f"relayx export --result {shlex.quote(result_path)} --format jsonl --out relayx-events.jsonl"),
            ],
        }
    if paths:
        top = paths[0]
        return {
            "result": result_path,
            "path_id": "",
            "state": "result_loaded",
            "summary": f"{len(paths)} path(s) found. Top path is {top.id} with score {top.score:.1f}.",
            "status_counts": status_counts,
            "top_paths": [_path_summary(path) for path in paths[:5]],
            "steps": [
                _next_step("summary", "Review scan summary", f"relayx summary {shlex.quote(result_path)}"),
                _next_step("paths", "List candidate paths", f"relayx paths {shlex.quote(result_path)}"),
                _next_step("explain", f"Explain the top path {top.id}", f"relayx explain {shlex.quote(result_path)} {top.id}"),
                _next_step("next", f"Focus next-step guidance on {top.id}", f"relayx next --result {shlex.quote(result_path)} --path-id {top.id}"),
                _next_step("console", "Continue in the operator console", f"relayx console --result {shlex.quote(result_path)} --path-id {top.id}"),
                _next_step("bundle", "Build enterprise handoff artifacts", f"relayx bundle --result {shlex.quote(result_path)} --out-dir relayx-bundle"),
            ],
        }
    return {
        "result": result_path,
        "path_id": "",
        "state": "no_paths",
        "summary": "The result has no modeled relay paths yet.",
        "status_counts": status_counts,
        "steps": [
            _next_step("matrix", "Review host/protocol readiness", f"relayx matrix {shlex.quote(result_path)}"),
            _next_step("sources", "Check whether source assets were modeled", f"relayx sources {shlex.quote(result_path)}"),
            _next_step("routes", "Review route context or source/target reachability", f"relayx routes --result {shlex.quote(result_path)}"),
            _next_step("scan", "Re-run scan with source metadata if needed", "relayx scan --targets examples/targets.txt --sources examples/sources.json --out result.json"),
        ],
    }


def _next_step(command: str, why: str, run: str) -> dict[str, str]:
    return {"command": command, "why": why, "run": run}


def _path_summary(path) -> dict:
    return {
        "id": path.id,
        "status": path.status.value,
        "impact": path.impact.value,
        "confidence": path.confidence.value,
        "score": path.score,
        "source": path.source,
        "target": path.target,
        "target_service": path.target_service,
        "summary": path.summary,
    }


def render_next_steps(payload: dict, *, color: bool = False) -> str:
    lines = [_ansi("RelayX Next Steps", "bold", "cyan", enabled=color), ""]
    lines.append(str(payload.get("summary", "")))
    if payload.get("status_counts"):
        counts = ", ".join(f"{key}={value}" for key, value in sorted(payload["status_counts"].items()))
        lines.append(f"Path status: {counts}")
    if payload.get("top_paths"):
        lines.extend(["", _ansi("Top Paths:", "bold", "yellow", enabled=color)])
        for path in payload["top_paths"]:
            lines.append(
                f"  {_ansi_cell(path['id'], 8, 'green', enabled=color)} "
                f"{path['status']} score={float(path['score']):.1f} {path['target']} {path['target_service']}"
            )
    if payload.get("selected_path"):
        path = payload["selected_path"]
        lines.extend(["", _ansi("Selected Path:", "bold", "yellow", enabled=color)])
        lines.append(f"  {path['id']} {path['status']} score={float(path['score']):.1f} {path['source']} -> {path['target']} {path['target_service']}")
    lines.extend(["", _ansi("Suggested Commands:", "bold", "yellow", enabled=color)])
    for index, step in enumerate(payload.get("steps", []), start=1):
        lines.append(f"  {index}. {step['why']}")
        lines.append(f"     {_ansi(step['run'], 'green', enabled=color)}")
    lines.extend(["", "Use 'relayx discover <keyword>' to find other workflows."])
    return "\n".join(lines).rstrip()


CONSOLE_CONTEXTUAL_COMMANDS = {
    "summary",
    "matrix",
    "sources",
    "paths",
    "calculus",
    "controls",
    "rank",
    "fixes",
    "explain",
    "plan",
    "evidence-report",
    "routes",
    "validate",
    "module-plan",
    "run",
    "export",
    "bundle",
    "discover",
    "next",
}
CONSOLE_BUILTIN_COMMANDS = {
    "?",
    "back",
    "clear",
    "cls",
    "context",
    "exit",
    "help",
    "history",
    "menu",
    "quit",
    "set",
    "show",
    "use",
}
CONSOLE_SHOW_COMMANDS = ("summary", "paths", "matrix", "sources")
CONSOLE_USE_TARGETS = ("result", "path")
CONSOLE_SET_KEYS = ("opsec-policy", "scope")
CONSOLE_SECRET_HISTORY_OPTIONS = (
    "--api-key",
    "--apikey",
    "--cert-password",
    "--credential",
    "--credentials",
    "--hash",
    "--keytab",
    "--nt-hash",
    "--password",
    "--private-key",
    "--secret",
    "--token",
)
CONSOLE_HISTORY_LIMIT = 1000


@dataclass
class ConsoleContext:
    result: str = ""
    path_id: str = ""
    opsec_policy: str = "standard"
    scope: str = ""
    no_color: bool = False
    history_file: str = ""
    history_enabled: bool = True
    completion_enabled: bool = True
    readline_enabled: bool = False
    history_entries: list[str] = field(default_factory=list)


def _console_prompt(context: ConsoleContext) -> str:
    parts = []
    if context.result:
        parts.append(f"result:{Path(context.result).name}")
    if context.path_id:
        parts.append(f"path:{context.path_id}")
    if context.opsec_policy:
        parts.append(f"policy:{context.opsec_policy}")
    if context.scope:
        parts.append("scope:set")
    prompt = "relayx[" + " ".join(parts) + "]> " if parts else "relayx> "
    return _ansi(prompt, "bold", "cyan", enabled=_color_enabled(context.no_color))


def _console_context_text(context: ConsoleContext) -> str:
    color = _color_enabled(context.no_color)
    return "\n".join(
        [
            _ansi("RelayX Console Context", "bold", "cyan", enabled=color),
            f"  {_ansi_cell('result', 12, 'yellow', enabled=color)}: {context.result or _ansi('(unset)', 'dim', enabled=color)}",
            f"  {_ansi_cell('path_id', 12, 'yellow', enabled=color)}: {context.path_id or _ansi('(unset)', 'dim', enabled=color)}",
            f"  {_ansi_cell('opsec_policy', 12, 'yellow', enabled=color)}: {context.opsec_policy or _ansi('(unset)', 'dim', enabled=color)}",
            f"  {_ansi_cell('scope', 12, 'yellow', enabled=color)}: {context.scope or _ansi('(unset)', 'dim', enabled=color)}",
        ]
    )


def _console_menu_text(context: ConsoleContext) -> str:
    color = _color_enabled(context.no_color)
    lines = [
        _ansi("RelayX Console Menu", "bold", "cyan", enabled=color),
        "",
        _ansi("Navigation:", "bold", "yellow", enabled=color),
        "  menu                         Show this menu",
        "  next                         Suggest what to do from current context",
        "  discover <keyword>           Find commands by task, protocol, or output",
        "  help <command|topic>          Show focused help",
        "  context                      Show selected result, path, policy, and scope",
        "",
        _ansi("Context:", "bold", "yellow", enabled=color),
        "  use result <file>             Select a result JSON",
        "  use path <id>                 Select a path such as PX-0001",
        "  set opsec-policy <policy>     Set policy for validate/run shortcuts",
        "  set scope <scope>             Set scope text or scope file",
        "",
        _ansi("Review:", "bold", "yellow", enabled=color),
        "  show summary                  Summarize current result",
        "  show paths                    List paths from current result",
        "  explain                       Explain selected path",
        "  evidence-report               Audit evidence completeness",
        "  routes                        Review route and pivot context",
        "",
        _ansi("Action Planning:", "bold", "yellow", enabled=color),
        "  validate --mode dry-run       Plan guarded validation",
        "  module-plan                   Review execution adapter readiness",
        "  run --mode dry-run            Dry-run controlled execution",
        "",
        _ansi("Enterprise:", "bold", "yellow", enabled=color),
        "  export --format jsonl         Emit SIEM-ready events",
        "  bundle --out-dir relayx-bundle Build handoff package",
        "",
        _ansi("Terminal:", "bold", "yellow", enabled=color),
        "  clear | cls                   Clear the screen",
        "  history [limit]               Show recent commands",
        "  history clear                 Clear console history",
        "  back                          Clear path first, then result",
        "  exit                          Leave the console",
    ]
    if not context.result:
        lines.extend(["", "Start with: use result examples/tutorial/sample-result.json"])
    elif not context.path_id:
        lines.extend(["", "Tip: run 'show paths', then 'use path PX-0001', then 'next'."])
    else:
        lines.extend(["", f"Tip: run 'next' for {context.path_id}, then 'validate --mode dry-run'."])
    return "\n".join(lines)


def _truthy_env(name: str) -> bool:
    value = os.environ.get(name, "")
    return value.lower() in {"1", "true", "yes", "on"}


def _default_console_history_file() -> str:
    explicit = os.environ.get("RELAYX_HISTORY_FILE", "")
    if explicit:
        return str(Path(explicit).expanduser())
    state_home = os.environ.get("XDG_STATE_HOME", "")
    if state_home:
        return str(Path(state_home).expanduser() / "relayx" / "console_history")
    return str(Path.home() / ".relayx" / "history")


def _console_history_allowed(context: ConsoleContext) -> bool:
    return context.history_enabled and not _truthy_env("RELAYX_NO_HISTORY")


def _console_history_recordable(raw_line: str) -> bool:
    if raw_line.startswith(" "):
        return False
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return False
    try:
        tokens = shlex.split(line)
    except ValueError:
        return False
    if not tokens or tokens[0] in {"exit", "quit"}:
        return False
    for token in tokens:
        lowered = token.lower()
        for option in CONSOLE_SECRET_HISTORY_OPTIONS:
            if lowered == option or lowered.startswith(option + "="):
                return False
    return True


def _readline_last_history_item() -> str | None:
    if _READLINE is None:
        return None
    try:
        length = _READLINE.get_current_history_length()
        return _READLINE.get_history_item(length) if length else None
    except (AttributeError, OSError):
        return None


def _discard_auto_recorded_history(raw_line: str, context: ConsoleContext) -> None:
    if _READLINE is None or not context.readline_enabled:
        return
    line = raw_line.strip()
    if not line or _readline_last_history_item() != line:
        return
    try:
        _READLINE.remove_history_item(_READLINE.get_current_history_length() - 1)
    except (AttributeError, OSError, ValueError):
        return


def _record_console_history(raw_line: str, context: ConsoleContext) -> None:
    if not _console_history_allowed(context) or not _console_history_recordable(raw_line):
        _discard_auto_recorded_history(raw_line, context)
        return
    line = raw_line.strip()
    if context.history_entries and context.history_entries[-1] == line:
        _discard_auto_recorded_history(raw_line, context)
        return
    context.history_entries.append(line)
    if _READLINE is None or not context.readline_enabled:
        return
    try:
        last = _readline_last_history_item()
        if last != line:
            _READLINE.add_history(line)
    except (AttributeError, OSError):
        return


def _format_console_history(context: ConsoleContext, *, limit: int = 30) -> str:
    entries = context.history_entries[-limit:]
    if not entries:
        return "No console history recorded in this session."
    start = len(context.history_entries) - len(entries) + 1
    width = len(str(start + len(entries) - 1))
    return "\n".join(f"{index:>{width}}  {entry}" for index, entry in enumerate(entries, start=start))


def _clear_console_history(context: ConsoleContext) -> None:
    context.history_entries.clear()
    if _READLINE is not None and context.readline_enabled:
        try:
            _READLINE.clear_history()
        except AttributeError:
            pass
    if context.history_file:
        try:
            Path(context.history_file).expanduser().unlink(missing_ok=True)
        except OSError:
            pass


def _clear_console_screen(context: ConsoleContext, *, interactive: bool) -> None:
    if not interactive:
        return
    color = _color_enabled(context.no_color)
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")
    else:
        print(_ansi("[clear]", "dim", enabled=color))


def _console_path_candidates(prefix: str) -> list[str]:
    raw = prefix or ""
    expanded = os.path.expanduser(raw)
    pattern = expanded + "*"
    candidates: list[str] = []
    for match in sorted(glob.glob(pattern)):
        display = match
        home = str(Path.home())
        if raw.startswith("~") and display.startswith(home):
            display = "~" + display[len(home):]
        if Path(match).is_dir():
            display += "/"
        candidates.append(shlex.quote(display))
    return candidates[:50]


def _console_completion_candidates(line: str, text: str = "") -> list[str]:
    stripped = line.lstrip()
    if not stripped:
        return [f"{command} " for command in sorted(CONSOLE_BUILTIN_COMMANDS | CONSOLE_CONTEXTUAL_COMMANDS)]
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        tokens = stripped.split()
    if stripped.endswith(" "):
        tokens.append("")
    active = tokens[-1] if tokens else text
    command = tokens[0] if tokens else ""
    if len(tokens) <= 1:
        pool = sorted(CONSOLE_BUILTIN_COMMANDS | CONSOLE_CONTEXTUAL_COMMANDS)
        return [f"{candidate} " for candidate in pool if candidate.startswith(active)]
    if command in {"help", "?"}:
        pool = sorted(_help_topic_names() | set(_get_command_specs()))
        return [f"{candidate} " for candidate in pool if candidate.startswith(active)]
    if command == "show":
        return [f"{candidate} " for candidate in CONSOLE_SHOW_COMMANDS if candidate.startswith(active)]
    if command == "use":
        if len(tokens) == 2:
            return [f"{candidate} " for candidate in CONSOLE_USE_TARGETS if candidate.startswith(active)]
        if tokens[1] == "result":
            return _console_path_candidates(active)
        return []
    if command == "set":
        if len(tokens) == 2:
            return [f"{candidate} " for candidate in CONSOLE_SET_KEYS if candidate.startswith(active)]
        if tokens[1] == "opsec-policy":
            policies = sorted(str(row.get("name")) for row in list_opsec_policies())
            return [f"{candidate} " for candidate in policies if candidate.startswith(active)]
    return []


class ConsoleReadlineSession:
    def __init__(self, context: ConsoleContext):
        self.context = context
        self.available = _READLINE is not None
        self._previous_completer = None
        self._previous_delims = ""
        self._history_path: Path | None = None

    def __enter__(self) -> "ConsoleReadlineSession":
        if not self.available:
            return self
        self.context.readline_enabled = True
        self._previous_completer = _READLINE.get_completer()
        self._previous_delims = _READLINE.get_completer_delims()
        try:
            _READLINE.set_history_length(CONSOLE_HISTORY_LIMIT)
        except AttributeError:
            pass
        if _console_history_allowed(self.context):
            self._history_path = Path(self.context.history_file or _default_console_history_file()).expanduser()
            self.context.history_file = str(self._history_path)
            try:
                self._history_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if self._history_path.exists():
                    _READLINE.read_history_file(str(self._history_path))
            except OSError as exc:
                print(f"Console history warning: {exc}", file=sys.stderr)
        if self.context.completion_enabled:
            _READLINE.set_completer(self._complete)
            _READLINE.set_completer_delims(" \t\n")
            binding = "bind ^I rl_complete" if "libedit" in (_READLINE.__doc__ or "") else "tab: complete"
            try:
                _READLINE.parse_and_bind(binding)
            except (AttributeError, OSError):
                pass
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self.available:
            return
        if _console_history_allowed(self.context) and self._history_path is not None:
            try:
                _READLINE.write_history_file(str(self._history_path))
                self._history_path.chmod(0o600)
            except OSError as err:
                print(f"Console history warning: {err}", file=sys.stderr)
        try:
            _READLINE.set_completer(self._previous_completer)
            _READLINE.set_completer_delims(self._previous_delims)
        except (AttributeError, OSError):
            pass
        self.context.readline_enabled = False

    def _complete(self, text: str, state: int) -> str | None:
        line = _READLINE.get_line_buffer() if _READLINE is not None else text
        matches = _console_completion_candidates(line, text)
        if state < len(matches):
            return matches[state]
        return None


def _has_any_option(tokens: list[str], options: set[str]) -> bool:
    return any(token in options or any(token.startswith(option + "=") for option in options if option.startswith("--")) for token in tokens)


def _contextual_argv(command: str, tokens: list[str], context: ConsoleContext) -> tuple[list[str], str]:
    argv = [command, *tokens]
    if command in {"summary", "matrix", "sources", "paths", "calculus", "controls", "rank", "fixes"}:
        if not context.result:
            return [], "No result selected. Use 'use result <file>' or pass a result path."
        if len(tokens) == 0:
            argv.append(context.result)
    if command in {"explain", "plan"}:
        if not context.result:
            return [], "No result selected. Use 'use result <file>'."
        if len(tokens) == 0 and command == "explain":
            if not context.path_id:
                return [], "No path selected. Use 'use path <id>' or pass a query."
            argv.extend([context.result, context.path_id])
        elif len(tokens) == 0 and command == "plan":
            if not context.path_id:
                return [], "No path selected. Use 'use path <id>' or pass a path ID."
            argv.extend([context.result, context.path_id])
        elif len(tokens) == 1:
            argv.insert(1, context.result)
    if command in {"validate", "run", "module-plan"}:
        if not context.result:
            return [], "No result selected. Use 'use result <file>'."
        if not context.path_id:
            return [], "No path selected. Use 'use path <id>'."
        if not _has_any_option(tokens, {"-r", "--result"}):
            argv.extend(["--result", context.result])
        if not _has_any_option(tokens, {"-p", "--path-id"}):
            argv.extend(["--path-id", context.path_id])
        if context.opsec_policy and command in {"validate", "run"} and not _has_any_option(tokens, {"-P", "--opsec-policy"}):
            argv.extend(["--opsec-policy", context.opsec_policy])
        if context.scope and command in {"validate", "run"} and not _has_any_option(tokens, {"-S", "--scope"}):
            argv.extend(["--scope", context.scope])
    if command in {"export", "bundle", "evidence-report", "routes"}:
        if not context.result:
            return [], "No result selected. Use 'use result <file>'."
        if not _has_any_option(tokens, {"-r", "--result"}):
            argv.extend(["--result", context.result])
    if command == "next":
        if context.result and not _has_any_option(tokens, {"-r", "--result"}):
            argv.extend(["--result", context.result])
        if context.path_id and not _has_any_option(tokens, {"-p", "--path-id"}):
            argv.extend(["--path-id", context.path_id])
    return argv, ""


def _handle_console_line(raw_line: str, context: ConsoleContext, *, interactive: bool = False) -> tuple[int, bool]:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return 0, False
    try:
        tokens = shlex.split(line)
    except ValueError as exc:
        print(f"Console parse error: {exc}", file=sys.stderr)
        return 2, False
    command, args = tokens[0], tokens[1:]
    if command == "?":
        command = "help"
    if command in {"exit", "quit"}:
        return 0, True
    if command in {"clear", "cls"}:
        _clear_console_screen(context, interactive=interactive)
        return 0, False
    if command == "history":
        if args and args[0] == "clear":
            _clear_console_history(context)
            print("Console history cleared.")
            return 0, False
        if len(args) > 1 or (args and not args[0].isdigit()):
            print("Usage: history [limit] | history clear", file=sys.stderr)
            return 2, False
        limit = int(args[0]) if args else 30
        print(_format_console_history(context, limit=max(1, limit)))
        return 0, False
    if command == "back":
        if context.path_id:
            context.path_id = ""
        elif context.result:
            context.result = ""
        print(_console_context_text(context))
        return 0, False
    if command == "context":
        print(_console_context_text(context))
        return 0, False
    if command == "menu":
        print(_console_menu_text(context))
        return 0, False
    if command == "use":
        if len(args) < 2 or args[0] not in {"result", "path"}:
            print("Usage: use result <file> | use path <id>", file=sys.stderr)
            return 2, False
        if args[0] == "result":
            if not Path(args[1]).exists():
                print(f"Result file not found: {args[1]}", file=sys.stderr)
                return 2, False
            context.result = args[1]
            context.path_id = ""
        else:
            context.path_id = args[1]
        print(_console_context_text(context))
        return 0, False
    if command == "set":
        if len(args) < 2 or args[0] not in {"opsec-policy", "scope"}:
            print("Usage: set opsec-policy <policy> | set scope <scope>", file=sys.stderr)
            return 2, False
        if args[0] == "opsec-policy":
            context.opsec_policy = args[1]
        else:
            context.scope = args[1]
        print(_console_context_text(context))
        return 0, False
    if command == "show":
        if not args or args[0] not in {"summary", "paths", "matrix", "sources"}:
            print("Usage: show summary | show paths | show matrix | show sources", file=sys.stderr)
            return 2, False
        command = args[0]
        args = args[1:]
    if command == "help":
        topic = args[0] if args else "overview"
        payload = _render_help_topic(topic)
        print(_format_help_payload(payload, color=_color_enabled(context.no_color)))
        return (2 if "error" in payload else 0), False
    if command not in CONSOLE_CONTEXTUAL_COMMANDS:
        suggestions = _suggest_terms(command, CONSOLE_BUILTIN_COMMANDS | CONSOLE_CONTEXTUAL_COMMANDS)
        if suggestions:
            print(f"Unknown console command: {command}. Did you mean: {', '.join(suggestions)}?", file=sys.stderr)
        else:
            print(f"Unknown console command: {command}. Use 'menu' or 'help console' for supported commands.", file=sys.stderr)
        return 2, False
    argv, error = _contextual_argv(command, args, context)
    if error:
        print(error, file=sys.stderr)
        return 2, False
    relayx_argv = ["--no-banner", *argv]
    if context.no_color:
        relayx_argv.insert(1, "--no-color")
    return main(relayx_argv), False


def run_console(context: ConsoleContext, *, script: str = "") -> int:
    if script:
        if script == "-":
            lines = sys.stdin.read().splitlines()
        else:
            try:
                lines = Path(script).read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                print(str(exc), file=sys.stderr)
                return 2
        for line in lines:
            rc, should_exit = _handle_console_line(line, context)
            if rc != 0 or should_exit:
                return rc
        return 0
    color = _color_enabled(context.no_color)
    with ConsoleReadlineSession(context) as line_session:
        intro = (
            _ansi("RelayX local operator console.", "bold", "cyan", enabled=color)
            + " Type 'help console', 'clear', or 'exit'."
        )
        print(intro)
        if not line_session.available:
            print(_ansi("Line editing, command history, and Tab completion are unavailable in this Python build.", "dim", enabled=color))
        while True:
            try:
                raw_line = input(_console_prompt(context))
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            _record_console_history(raw_line, context)
            rc, should_exit = _handle_console_line(raw_line, context, interactive=True)
            if should_exit:
                return rc


def build_parser() -> argparse.ArgumentParser:
    parser = RelayXArgumentParser(
        prog="relayx",
        description="RelayX: An OPSEC-aware NTLM relay exposure assessment, lab-calibrated validation, and controlled execution orchestration tool for authorized red teaming",
        epilog=_top_level_epilog(),
        formatter_class=RelayXHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"RelayX {__version__}")
    _add_no_banner_arg(parser, visible=True)
    _add_no_color_arg(parser, visible=True)
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND", parser_class=RelayXArgumentParser)

    help_cmd = sub.add_parser(
        "help",
        help="Show curated help, workflows, examples, and safety notes",
        formatter_class=RelayXHelpFormatter,
    )
    help_cmd.add_argument("topic", nargs="?", default="overview", help="Topic or command name")
    help_cmd.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Help output format")
    help_cmd.add_argument("-o", "--out", help="Output path. Defaults to stdout.")
    _add_no_banner_arg(help_cmd)
    _add_no_color_arg(help_cmd)

    discover = sub.add_parser("discover", help="Search RelayX commands and help topics")
    discover.add_argument("query", nargs="?", default="", help="Keyword such as epa, route, jsonl, opsec, lab, or execution")
    discover.add_argument("-g", "--group", default="", help="Optional command group filter, e.g. Assessment, Calibration, Enterprise")
    discover.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Discovery output format")
    discover.add_argument("-o", "--out", help="Output path. Defaults to stdout.")
    _add_no_banner_arg(discover)
    _add_no_color_arg(discover)

    next_cmd = sub.add_parser("next", help="Suggest next useful RelayX commands")
    next_cmd.add_argument("-r", "--result", default="", help="RelayX result JSON. Omit for first-run guidance.")
    next_cmd.add_argument("-p", "--path-id", default="", help="Optional path ID such as PX-0001")
    next_cmd.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Next-step output format")
    next_cmd.add_argument("-o", "--out", help="Output path. Defaults to stdout.")
    _add_no_banner_arg(next_cmd)
    _add_no_color_arg(next_cmd)

    completion = sub.add_parser("completion", help="Print shell completion scripts")
    completion.add_argument("shell", choices=["bash", "zsh", "fish"], help="Shell to generate completion for")
    completion.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    console = sub.add_parser("console", help="Start a local RelayX operator console")
    console.add_argument("-r", "--result", default="", help="Initial RelayX result JSON context")
    console.add_argument("-p", "--path-id", default="", help="Initial path ID context, e.g. PX-0001")
    console.add_argument("-P", "--opsec-policy", default="standard", help="Initial OPSEC policy name or JSON file")
    console.add_argument("-S", "--scope", default="", help="Initial scope file, CIDR, host, or comma-separated scope entries")
    console.add_argument("-s", "--script", default="", help="Read console commands from a file. Use '-' for stdin.")
    console.add_argument("-H", "--history-file", default="", help="Console history file. Defaults to RELAYX_HISTORY_FILE or ~/.relayx/history.")
    console.add_argument("-N", "--no-history", action="store_true", help="Disable console history loading, recording, and persistence.")
    console.add_argument("-C", "--no-completion", action="store_true", help="Disable interactive console Tab completion.")
    _add_no_banner_arg(console)
    _add_no_color_arg(console)

    scan = sub.add_parser("scan", help="Assess targets and write a RelayX result file")
    scan.add_argument("-p", "--profile", help="RelayX profile name or JSON file")
    scan.add_argument("-t", "--targets", help="Target file, comma-separated list, or single host")
    scan.add_argument("-o", "--out", default="relayx-result.json", help="Output JSON path")
    scan.add_argument("-T", "--timeout", type=float, help="Per-probe timeout in seconds")
    scan.add_argument("-w", "--workers", type=int, help="Concurrent target workers")
    scan.add_argument("-s", "--sources", help="Source asset file or comma-separated source hosts for path modeling")
    scan.add_argument("-S", "--scope", help="Scope file, CIDR, host, or comma-separated scope entries")
    scan.add_argument("-X", "--strict-scope", action="store_true", help="Fail if any target or source is outside scope")
    scan.add_argument(
        "-n",
        "--max-noise",
        choices=[level.value for level in NoiseLevel],
        help="Maximum OPSEC noise level allowed for modeled source capabilities",
    )
    scan.add_argument(
        "-C",
        "--no-challenge-flow",
        action="store_true",
        help="Skip NTLM Type1/Type2 challenge-flow probes.",
    )
    scan.add_argument(
        "-L",
        "--no-mssql-tls",
        action="store_true",
        help="Do not request TDS-wrapped TLS for MSSQL CBT evidence.",
    )
    scan.add_argument(
        "-A",
        "--auth-validation",
        action="store_true",
        help="Send synthetic NTLM Authenticate messages for explicit enforcement validation.",
    )
    scan.add_argument(
        "-a",
        "--active",
        action="store_true",
        help="Reserved for future active validation. MVP still avoids coercion/relay.",
    )
    _add_operation_control_args(scan, subject="target")

    assess = sub.add_parser("assess", help="Alias for scan")
    assess.add_argument("-p", "--profile", help="RelayX profile name or JSON file")
    assess.add_argument("-t", "--targets", help="Target file, comma-separated list, or single host")
    assess.add_argument("-o", "--out", default="relayx-result.json", help="Output JSON path")
    assess.add_argument("-T", "--timeout", type=float, help="Per-probe timeout in seconds")
    assess.add_argument("-w", "--workers", type=int, help="Concurrent target workers")
    assess.add_argument("-s", "--sources", help="Source asset file or comma-separated source hosts for path modeling")
    assess.add_argument("-S", "--scope", help="Scope file, CIDR, host, or comma-separated scope entries")
    assess.add_argument("-X", "--strict-scope", action="store_true", help="Fail if any target or source is outside scope")
    assess.add_argument(
        "-n",
        "--max-noise",
        choices=[level.value for level in NoiseLevel],
        help="Maximum OPSEC noise level allowed for modeled source capabilities",
    )
    assess.add_argument(
        "-C",
        "--no-challenge-flow",
        action="store_true",
        help="Skip NTLM Type1/Type2 challenge-flow probes.",
    )
    assess.add_argument(
        "-L",
        "--no-mssql-tls",
        action="store_true",
        help="Do not request TDS-wrapped TLS for MSSQL CBT evidence.",
    )
    assess.add_argument(
        "-A",
        "--auth-validation",
        action="store_true",
        help="Send synthetic NTLM Authenticate messages for explicit enforcement validation.",
    )
    assess.add_argument(
        "-a",
        "--active",
        action="store_true",
        help="Reserved for future active validation. MVP still avoids coercion/relay.",
    )
    _add_operation_control_args(assess, subject="target")

    summary = sub.add_parser("summary", help="Summarize findings and candidate paths")
    _add_common_result_arg(summary)

    matrix = sub.add_parser("matrix", help="Show relay readiness matrix by host and protocol")
    _add_common_result_arg(matrix)

    sources = sub.add_parser("sources", help="Show source assets and modeled capabilities")
    _add_common_result_arg(sources)

    routes = sub.add_parser("routes", help="Assess source route and pivot reachability")
    routes.add_argument("-r", "--result", help="RelayX result JSON. Uses result sources and finding hosts.")
    routes.add_argument("-s", "--sources", help="Source asset file or comma-separated source hosts")
    routes.add_argument("-t", "--targets", help="Target file, comma-separated list, or single host")
    routes.add_argument("-S", "--scope", help="Scope file, CIDR, host, or comma-separated scope entries")
    routes.add_argument("-P", "--target-protocol", default="", help="Optional target protocol label for route context")
    routes.add_argument("-O", "--target-port", type=int, default=0, help="Optional target port for reachability checks")
    routes.add_argument(
        "-c",
        "--connect-check",
        action="store_true",
        help="Perform authorized direct TCP reachability checks from the operator runtime. No pivot session is opened.",
    )
    routes.add_argument("-T", "--timeout", type=float, default=3.0, help="TCP reachability timeout in seconds")
    _add_operation_control_args(routes, subject="route check")
    routes.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Output format")
    routes.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    source_check = sub.add_parser("source-check", help="Check modeled source capabilities without executing triggers")
    source_check.add_argument("-s", "--sources", required=True, help="Source asset file or comma-separated source hosts")
    source_check.add_argument("-S", "--scope", help="Scope file, CIDR, host, or comma-separated scope entries")
    source_check.add_argument(
        "-n",
        "--max-noise",
        choices=[level.value for level in NoiseLevel],
        default=NoiseLevel.HIGH.value,
        help="Maximum OPSEC noise allowed for source checks",
    )
    source_check.add_argument(
        "-c",
        "--connect-check",
        action="store_true",
        help="Perform low-noise TCP reachability checks for supported source surfaces. No source trigger is executed.",
    )
    source_check.add_argument("-T", "--timeout", type=float, default=3.0, help="TCP reachability timeout in seconds")
    source_check.add_argument("-P", "--opsec-policy", help="OPSEC policy name or JSON file. Defaults to standard.")
    source_check.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Output format")
    source_check.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    source_plan = sub.add_parser("source-plan", help="Create a single-source source-trigger validation plan")
    source_plan.add_argument("-s", "--sources", required=True, help="Source asset file or comma-separated source hosts")
    source_plan.add_argument("-H", "--source", required=True, help="Source host to plan")
    source_plan.add_argument("-c", "--capability", required=True, help="Source capability, e.g. webclient, spooler, mssql_outbound")
    source_plan.add_argument("-S", "--scope", help="Scope file, CIDR, host, or comma-separated scope entries")
    source_plan.add_argument("-L", "--listener-host", default="", help="Planned listener host for future-active source validation")
    source_plan.add_argument("-K", "--callback-host", default="", help="Planned callback target for future-active source validation")
    source_plan.add_argument(
        "-n",
        "--max-noise",
        choices=[level.value for level in NoiseLevel],
        default=NoiseLevel.HIGH.value,
        help="Maximum OPSEC noise allowed for this source plan",
    )
    source_plan.add_argument("-P", "--opsec-policy", help="OPSEC policy name or JSON file. Defaults to standard.")
    source_plan.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Output format")
    source_plan.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    paths = sub.add_parser("paths", help="List relay candidate paths")
    _add_common_result_arg(paths)
    paths.add_argument("-b", "--include-blocked", action="store_true", help="Show blocked paths too")

    calculus = sub.add_parser("calculus", help="Show RelayX rule decisions and hardening gates")
    _add_common_result_arg(calculus)

    controls = sub.add_parser("controls", help="Show defensive control priorities from RelayX calculus")
    _add_common_result_arg(controls)

    profiles = sub.add_parser("profiles", help="List bundled RelayX profiles")
    profiles.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Profile output format")
    profiles.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    calibrate = sub.add_parser("calibrate", help="Apply lab calibration profiles to a RelayX result")
    _add_common_result_arg(calibrate)
    calibrate.add_argument("-p", "--profiles", help="Calibration profile JSON file or directory")
    calibrate.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Calibration output format")
    calibrate.add_argument("-o", "--out", help="Output path for calibration report. Defaults to stdout.")
    calibrate.add_argument("-a", "--annotate-out", help="Write a RelayX result annotated with lab calibration evidence")

    compare = sub.add_parser("compare-baseline", help="Compare baseline and candidate lab result signatures")
    compare.add_argument("-b", "--baseline", required=True, help="Baseline RelayX result JSON")
    compare.add_argument("-c", "--candidate", required=True, help="Candidate RelayX result JSON")
    compare.add_argument("-p", "--profiles", help="Calibration profile JSON file or directory")
    compare.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Comparison output format")
    compare.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    lab_matrix = sub.add_parser("lab-matrix", help="Print the standard RelayX lab policy matrix")
    lab_matrix.add_argument("-t", "--target-family", default="", help="Optional target family filter, e.g. mssql_epa")
    lab_matrix.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Matrix output format")
    lab_matrix.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    lab_corpus = sub.add_parser("lab-corpus", help="Extract lab calibration signatures from a RelayX result")
    _add_common_result_arg(lab_corpus)
    lab_corpus.add_argument("-l", "--label", default="", help="Human label for this lab capture")
    lab_corpus.add_argument("-e", "--environment", default="", help="Lab environment label, e.g. win2022-iis")
    lab_corpus.add_argument("-P", "--policy-state", default="", help="Known lab policy state for this capture")
    lab_corpus.add_argument("-C", "--expected-classification", default="", help="Expected RelayX classification for this capture")
    lab_corpus.add_argument("-E", "--expected-state", default="", help="Expected calibrated state for generated profiles")
    lab_corpus.add_argument("-Q", "--expected-confidence", default="medium", help="Expected confidence for generated profile states")
    lab_corpus.add_argument(
        "-p",
        "--promotion",
        choices=["retain", "promote", "block"],
        default="retain",
        help="Profile promotion hint for generated states",
    )
    lab_corpus.add_argument("-R", "--reason", default="", help="Promotion or retention rationale")
    lab_corpus.add_argument(
        "-u",
        "--uncertainty",
        action="append",
        default=[],
        help="Remaining uncertainty or limitation to preserve in the corpus. Can be repeated.",
    )
    lab_corpus.add_argument("-N", "--note", action="append", default=[], help="Operator note to store in the corpus. Can be repeated.")
    lab_corpus.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Corpus output format")
    lab_corpus.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    lab_index = sub.add_parser("lab-index", help="Summarize lab signature corpuses")
    lab_index.add_argument("-c", "--corpus", action="append", required=True, help="Corpus JSON file or directory. Can be repeated.")
    lab_index.add_argument("-t", "--target-family", default="", help="Optional target family filter, e.g. mssql_epa")
    lab_index.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Index output format")
    lab_index.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    lab_verify = sub.add_parser("lab-verify", help="Verify lab corpuses against the standard RelayX lab matrix")
    lab_verify.add_argument("-c", "--corpus", action="append", required=True, help="Corpus JSON file or directory. Can be repeated.")
    lab_verify.add_argument("-t", "--target-family", default="", help="Optional target family filter, e.g. ldaps_cbt")
    lab_verify.add_argument("-m", "--min-captures", type=int, default=1, help="Minimum captures required for each required policy state.")
    lab_verify.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Verification output format")
    lab_verify.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    lab_provenance = sub.add_parser("lab-provenance", help="Audit lab corpus provenance and operator review readiness")
    lab_provenance.add_argument("-c", "--corpus", action="append", required=True, help="Corpus JSON file or directory. Can be repeated.")
    lab_provenance.add_argument("-t", "--target-family", default="", help="Optional target family filter, e.g. mssql_epa")
    lab_provenance.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Provenance output format")
    lab_provenance.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    lab_stability = sub.add_parser("lab-stability", help="Assess repeat-capture lab signature stability and drift")
    lab_stability.add_argument("-c", "--corpus", action="append", required=True, help="Corpus JSON file or directory. Can be repeated.")
    lab_stability.add_argument("-t", "--target-family", default="", help="Optional target family filter, e.g. mssql_epa")
    lab_stability.add_argument(
        "-m",
        "--min-captures",
        type=int,
        default=2,
        help="Minimum repeated captures required for a policy state to be considered stable.",
    )
    lab_stability.add_argument(
        "-T",
        "--stable-threshold",
        type=float,
        default=0.85,
        help="Dominant stable-signature ratio required for promotion gates. Defaults to 0.85.",
    )
    lab_stability.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Stability output format")
    lab_stability.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    lab_diff = sub.add_parser("lab-diff", help="Compare stable lab policy-state response differentials")
    lab_diff.add_argument("-c", "--corpus", action="append", required=True, help="Corpus JSON file or directory. Can be repeated.")
    lab_diff.add_argument("-t", "--target-family", default="", help="Optional target family filter, e.g. http_iis_epa")
    lab_diff.add_argument(
        "-m",
        "--min-captures",
        type=int,
        default=2,
        help="Minimum repeated captures required before a policy-state signature is considered stable.",
    )
    lab_diff.add_argument(
        "-T",
        "--stable-threshold",
        type=float,
        default=0.85,
        help="Dominant stable-signature ratio required before response differences are trusted.",
    )
    lab_diff.add_argument(
        "-p",
        "--pair",
        action="append",
        default=[],
        help="Optional policy-state pair filter such as epa_off:epa_required or http_iis_epa/epa_off:epa_required. Can be repeated.",
    )
    lab_diff.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Differential output format")
    lab_diff.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    lab_profile = sub.add_parser("lab-profile", help="Generate a lab calibration profile draft from corpuses")
    lab_profile.add_argument("-c", "--corpus", action="append", required=True, help="Corpus JSON file or directory. Can be repeated.")
    lab_profile.add_argument("-i", "--profile-id", required=True, help="Profile ID for the generated calibration profile")
    lab_profile.add_argument("-t", "--target-family", required=True, help="Target family, e.g. http_iis_epa, ldaps_cbt, mssql_epa")
    lab_profile.add_argument("-s", "--service", default="", help="Service label for the generated profile")
    lab_profile.add_argument("-d", "--description", default="", help="Profile description")
    lab_profile.add_argument(
        "-n",
        "--min-captures",
        type=int,
        default=1,
        help="Minimum matching captures required before a generated state may preserve promotion=promote.",
    )
    lab_profile.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Profile output format")
    lab_profile.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    validate = sub.add_parser("validate", help="Run the guarded active validation harness")
    validate.add_argument("-r", "--result", required=True, help="RelayX result JSON")
    validate.add_argument("-p", "--path-id", required=True, help="Path ID, e.g. PX-0001")
    validate.add_argument(
        "-m",
        "--mode",
        choices=["dry-run", "armed", "confirmed"],
        default="dry-run",
        help="Validation state-machine mode",
    )
    validate.add_argument("-y", "--confirm", action="store_true", help="Required for confirmed validation")
    validate.add_argument("-O", "--operator", default="", help="Operator identity for audit logs")
    validate.add_argument("-R", "--reason", default="", help="Validation reason for audit logs")
    validate.add_argument("-S", "--scope", help="Scope file, CIDR, host, or comma-separated scope entries")
    validate.add_argument(
        "-n",
        "--max-noise",
        choices=[level.value for level in NoiseLevel],
        default=NoiseLevel.HIGH.value,
        help="Maximum OPSEC noise allowed for this validation run",
    )
    validate.add_argument("-B", "--timebox", type=int, default=300, help="Validation timebox in seconds")
    validate.add_argument("-A", "--audit-log", help="JSONL audit log path")
    validate.add_argument(
        "-e",
        "--reprobe",
        action="store_true",
        help="In confirmed mode, run a target-side protocol reprobe. No source trigger or relay is executed.",
    )
    validate.add_argument(
        "-u",
        "--auth-validation",
        action="store_true",
        help="With confirmed --reprobe, include synthetic authenticate validation where supported.",
    )
    validate.add_argument("-T", "--timeout", type=float, default=3.0, help="Per-probe timeout in seconds")
    validate.add_argument("-P", "--opsec-policy", help="OPSEC policy name or JSON file. Defaults to standard.")
    _add_operation_control_args(validate, subject="validation action")
    validate.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Validation output format")
    validate.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    rank = sub.add_parser("rank", help="Rank paths by RelayX score")
    _add_common_result_arg(rank)
    rank.add_argument("-n", "--top", type=int, default=20, help="Maximum paths to show")

    explain = sub.add_parser("explain", help="Explain one host or path ID")
    _add_common_result_arg(explain)
    explain.add_argument("query", help="Host or path ID, e.g. DC01 or PX-0001")

    fixes = sub.add_parser("fixes", help="Show remediation priorities")
    _add_common_result_arg(fixes)
    fixes.add_argument("-n", "--top", type=int, default=10, help="Maximum fixes to show")

    plan = sub.add_parser("plan", help="Create an OPSEC-aware dry-run plan for one path")
    _add_common_result_arg(plan)
    plan.add_argument("path_id", help="Path ID, e.g. PX-0001")
    plan.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Plan output format")
    plan.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    evidence_report = sub.add_parser("evidence-report", help="Audit evidence completeness, source taxonomy, and protocol judgement fields")
    evidence_report.add_argument("-r", "--result", required=True, help="RelayX result JSON")
    evidence_report.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Evidence report output format")
    evidence_report.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    report = sub.add_parser("report", help="Export JSON, Markdown, HTML, Mermaid, or CSV")
    _add_common_result_arg(report)
    report.add_argument("-f", "--format", default="markdown", choices=["json", "markdown", "md", "html", "mermaid", "mmd", "csv"])
    report.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    export = sub.add_parser("export", help="Export enterprise-friendly RelayX artifacts")
    export.add_argument("-r", "--result", required=True, help="RelayX result JSON")
    export.add_argument(
        "-f",
        "--format",
        required=True,
        choices=sorted(ENTERPRISE_EXPORT_FORMATS),
        help="Export format",
    )
    export.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    bundle = sub.add_parser("bundle", help="Write a validated enterprise handoff bundle")
    bundle.add_argument("-r", "--result", required=True, help="RelayX result JSON")
    bundle.add_argument("-d", "--out-dir", required=True, help="Directory to write bundle artifacts")
    bundle.add_argument(
        "-F",
        "--formats",
        default=",".join(ENTERPRISE_BUNDLE_FORMATS),
        help="Comma-separated bundle formats. Defaults to all enterprise bundle formats.",
    )
    bundle.add_argument("-R", "--no-routes", action="store_true", help="Do not include a route report in the bundle")
    bundle.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Manifest output format")
    bundle.add_argument("-o", "--out", help="Write the manifest summary to a separate file. Defaults to stdout.")

    diff = sub.add_parser("diff", help="Compare two RelayX result files")
    diff.add_argument("old", help="Old RelayX result JSON")
    diff.add_argument("new", help="New RelayX result JSON")
    diff.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Diff output format")
    diff.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    simulate = sub.add_parser("simulate-fixes", help="Simulate remediation impact on RelayX paths")
    simulate.add_argument("result", help="RelayX result JSON")
    simulate.add_argument("-x", "--fix", action="append", default=[], help="Fix text to simulate. Can be repeated.")
    simulate.add_argument("-c", "--control", action="append", default=[], help="RelayX control key to simulate, e.g. smb_signing")
    simulate.add_argument("-n", "--top", type=int, default=10, help="Maximum simulated fixes to show")
    simulate.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Simulation output format")
    simulate.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    quality_gate = sub.add_parser("quality-gate", help="Run local CI and release quality gates")
    quality_gate.add_argument("-C", "--project-root", default=".", help="Project root to validate. Defaults to current directory.")
    quality_gate.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Quality gate output format")
    quality_gate.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    opsec = sub.add_parser("opsec", help="List or inspect RelayX OPSEC policies")
    opsec_sub = opsec.add_subparsers(dest="opsec_action", required=True, metavar="ACTION")
    opsec_list = opsec_sub.add_parser("list", help="List built-in OPSEC policies")
    opsec_list.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Policy output format")
    opsec_list.add_argument("-o", "--out", help="Output path. Defaults to stdout.")
    opsec_show = opsec_sub.add_parser("show", help="Show one built-in or external OPSEC policy")
    opsec_show.add_argument("-p", "--policy", default="standard", help="Policy name or JSON file. Defaults to standard.")
    opsec_show.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Policy output format")
    opsec_show.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    schema = sub.add_parser("schema", help="List or validate RelayX schema and evidence contracts")
    schema_sub = schema.add_subparsers(dest="schema_action", required=True, metavar="ACTION")
    schema_list = schema_sub.add_parser("list", help="List RelayX schema contracts")
    schema_list.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Schema catalog output format")
    schema_list.add_argument("-o", "--out", help="Output path. Defaults to stdout.")
    schema_validate = schema_sub.add_parser("validate", help="Validate a file or directory against RelayX schema contracts")
    schema_validate.add_argument("path", help="RelayX artifact file or directory to validate")
    schema_validate.add_argument(
        "-k",
        "--kind",
        choices=["auto", *SCHEMA_KINDS],
        default="auto",
        help="Schema kind. Defaults to auto inference.",
    )
    schema_validate.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Validation output format")
    schema_validate.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    modules = sub.add_parser("modules", help="List execution module manifests")
    modules.add_argument("-F", "--manifests", help="Execution module manifest JSON file or directory")
    modules.add_argument("-M", "--module", default="", help="Show one module key")
    modules.add_argument("-D", "--no-defaults", action="store_true", help="Do not include built-in module manifests")
    modules.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Module inventory output format")
    modules.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    module_plan = sub.add_parser("module-plan", help="Evaluate execution modules for one path")
    module_plan.add_argument("-r", "--result", required=True, help="RelayX result JSON")
    module_plan.add_argument("-p", "--path-id", required=True, help="Path ID, e.g. PX-0001")
    module_plan.add_argument("-F", "--manifests", help="Execution module manifest JSON file or directory")
    module_plan.add_argument("-M", "--module", default="", help="Evaluate one module key. Defaults to all modules.")
    module_plan.add_argument("-D", "--no-defaults", action="store_true", help="Do not include built-in module manifests")
    module_plan.add_argument(
        "-m",
        "--mode",
        choices=["dry-run", "armed", "confirmed"],
        default="confirmed",
        help="Execution mode to evaluate",
    )
    module_plan.add_argument(
        "-N",
        "--accept-non-ready",
        action="store_true",
        help="Evaluate non-ready paths as explicitly accepted for planning.",
    )
    module_plan.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Module plan output format")
    module_plan.add_argument("-o", "--out", help="Output path. Defaults to stdout.")

    run = sub.add_parser("run", help="Run the controlled execution state machine")
    run.add_argument("-r", "--result", help="RelayX result JSON")
    run.add_argument("-p", "--path-id", help="Path ID, e.g. PX-0001")
    run.add_argument("--plan", help=argparse.SUPPRESS)
    run.add_argument(
        "-m",
        "--mode",
        choices=["dry-run", "armed", "confirmed"],
        default="dry-run",
        help="Execution state-machine mode",
    )
    run.add_argument("-y", "--confirm", action="store_true", help="Required for confirmed execution")
    run.add_argument("-O", "--operator", default="", help="Operator identity for audit logs")
    run.add_argument("-R", "--reason", default="", help="Execution reason for audit logs")
    run.add_argument("-S", "--scope", help="Scope file, CIDR, host, or comma-separated scope entries")
    run.add_argument("-L", "--listener-host", default="", help="Planned listener host for scoped execution modules")
    run.add_argument("-K", "--callback-host", default="", help="Planned callback target for scoped execution modules")
    run.add_argument(
        "-n",
        "--max-noise",
        choices=[level.value for level in NoiseLevel],
        default=NoiseLevel.HIGH.value,
        help="Maximum OPSEC noise allowed for this execution run",
    )
    run.add_argument("-B", "--timebox", type=int, default=300, help="Execution timebox in seconds")
    run.add_argument("-A", "--audit-log", help="JSONL audit log path")
    run.add_argument("-M", "--module", default="noop", help="Execution module key. Defaults to noop.")
    run.add_argument("-F", "--manifests", help="Execution module manifest JSON file or directory")
    run.add_argument("-D", "--no-default-modules", action="store_true", help="Do not include built-in module manifests")
    run.add_argument("-P", "--opsec-policy", help="OPSEC policy name or JSON file. Defaults to standard.")
    run.add_argument(
        "-N",
        "--accept-non-ready",
        action="store_true",
        help="Allow confirmed planning for paths that still need validation or calibration.",
    )
    run.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Execution output format")
    run.add_argument("-o", "--out", help="Output path. Defaults to stdout.")
    run.add_argument("-a", "--annotate-out", help="Write a RelayX result annotated with controlled execution evidence")

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        profile = load_profile(args.profile)
    except (OSError, ValueError, OperationControlError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    targets = load_targets(args.targets or profile_value(profile, "targets"))
    sources = load_sources(args.sources or profile_value(profile, "sources"))
    scope = load_scope(args.scope or profile_value(profile, "scope"))
    timeout = float(args.timeout if args.timeout is not None else profile_value(profile, "timeout", 3.0))
    workers = int(args.workers if args.workers is not None else profile_value(profile, "workers", 16))
    max_noise = NoiseLevel(str(args.max_noise or profile_value(profile, "max_noise", NoiseLevel.HIGH.value)).lower())
    challenge_flow = profile_bool(profile, "challenge_flow", True)
    if args.no_challenge_flow:
        challenge_flow = False
    mssql_tls = profile_bool(profile, "mssql_tls", True)
    if args.no_mssql_tls:
        mssql_tls = False
    auth_validation = bool(args.auth_validation or profile_bool(profile, "auth_validation", False))
    strict_scope = bool(args.strict_scope or profile_bool(profile, "strict_scope", False))
    operation_control = _operation_control_from_args(args)
    if scope:
        scoped_targets = scope.filter(targets)
        scoped_sources = [source for source in sources if scope.contains(source.host)]
        if strict_scope and (len(scoped_targets) != len(targets) or len(scoped_sources) != len(sources)):
            print("Targets or sources are outside the supplied scope.", file=sys.stderr)
            return 2
        targets = scoped_targets
        sources = scoped_sources
    if not targets:
        print("No targets supplied.", file=sys.stderr)
        return 2
    control_report = operation_control.report(
        operation="scan",
        active_operation=True,
        action_count=len(targets),
        network_action="target_assessment",
    )
    window_ok, window_reason = enforce_operation_window(control_report)
    if not window_ok:
        print(window_reason, file=sys.stderr)
        return 2
    result = ScanResult.new(
        target_count=len(targets),
        active=bool(args.active or auth_validation),
        source_count=len(sources),
    )
    result.metadata.operation_control = control_report
    result.metadata.expected_telemetry = control_report["expected_telemetry"]
    result.metadata.rollback = control_report["rollback"]
    result.sources = sources
    try:
        result.findings = assess_targets(
            targets,
            timeout=timeout,
            workers=workers,
            challenge_flow=challenge_flow,
            mssql_prefer_tls=mssql_tls,
            auth_validation=auth_validation,
            operation_control=operation_control,
        )
    except OperationControlError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    result.paths = build_paths(
        result.findings,
        sources=result.sources,
        max_noise=max_noise,
        scope=scope,
    )
    result.finish()
    write_result(result, args.out)
    print(f"Wrote {args.out}")
    print(render_summary(result))
    return 0


def cmd_help(args: argparse.Namespace) -> int:
    payload = _render_help_topic(args.topic)
    output = json.dumps(payload, indent=2, sort_keys=True) if args.format == "json" else _format_help_payload(payload, color=_color_enabled(args.no_color))
    _write_or_print(output, args.out)
    return 2 if "error" in payload else 0


def cmd_discover(args: argparse.Namespace) -> int:
    payload = _discover_payload(args.query, group=args.group)
    output = json.dumps(payload, indent=2, sort_keys=True) if args.format == "json" else render_discovery(payload, color=_color_enabled(args.no_color))
    _write_or_print(output, args.out)
    return 0


def cmd_next(args: argparse.Namespace) -> int:
    try:
        payload = _next_payload(args.result, path_id=args.path_id)
    except (OSError, ValueError) as exc:
        print(f"Could not load RelayX result: {exc}", file=sys.stderr)
        return 2
    output = json.dumps(payload, indent=2, sort_keys=True) if args.format == "json" else render_next_steps(payload, color=_color_enabled(args.no_color))
    _write_or_print(output, args.out)
    return 0


def cmd_completion(args: argparse.Namespace) -> int:
    try:
        output = render_completion(args.shell)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _write_or_print(output, args.out)
    return 0


def cmd_console(args: argparse.Namespace) -> int:
    context = ConsoleContext(
        result=args.result,
        path_id=args.path_id,
        opsec_policy=args.opsec_policy,
        scope=args.scope,
        no_color=bool(args.no_color),
        history_file=args.history_file,
        history_enabled=not args.no_history,
        completion_enabled=not args.no_completion,
    )
    return run_console(context, script=args.script)


def cmd_summary(args: argparse.Namespace) -> int:
    print(render_summary(read_result(args.result)))
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    print(render_matrix(read_result(args.result)))
    return 0


def cmd_sources(args: argparse.Namespace) -> int:
    print(render_sources(read_result(args.result)))
    return 0


def cmd_routes(args: argparse.Namespace) -> int:
    if args.result:
        result = read_result(args.result)
        sources = result.sources
        targets = sorted({finding.host for finding in result.findings})
    else:
        sources = load_sources(args.sources)
        targets = load_targets(args.targets)
    if not sources:
        print("No sources supplied.", file=sys.stderr)
        return 2
    if not targets:
        print("No targets supplied.", file=sys.stderr)
        return 2
    operation_control = _operation_control_from_args(args)
    control_report = operation_control.report(
        operation="routes",
        active_operation=bool(args.connect_check),
        action_count=len(sources) * len(targets) if args.connect_check else 0,
        network_action="tcp_connect_check" if args.connect_check else "none",
    )
    window_ok, window_reason = enforce_operation_window(control_report)
    if args.connect_check and not window_ok:
        print(window_reason, file=sys.stderr)
        return 2
    try:
        report = assess_route_matrix(
            sources,
            targets,
            target_protocol=args.target_protocol,
            target_port=args.target_port,
            scope=load_scope(args.scope),
            connect_check=bool(args.connect_check),
            timeout=args.timeout,
            operation_control=operation_control,
        )
    except OperationControlError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report["operation_control"] = control_report
    report["guardrails"] = operation_control_guardrails(control_report)
    output = route_report_to_json(report) if args.format == "json" else render_route_report(report)
    _write_or_print(output, args.out)
    return 0


def cmd_source_check(args: argparse.Namespace) -> int:
    sources = load_sources(args.sources)
    request = SourceCheckRequest(
        max_noise=NoiseLevel(args.max_noise),
        scope=load_scope(args.scope),
        connect_check=bool(args.connect_check),
        timeout=args.timeout,
        opsec_policy=load_opsec_policy(args.opsec_policy),
    )
    report = check_sources(sources, request)
    output = source_checks_to_json(report) if args.format == "json" else render_source_checks(report)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_source_plan(args: argparse.Namespace) -> int:
    sources = load_sources(args.sources)
    request = SourceCheckRequest(
        max_noise=NoiseLevel(args.max_noise),
        scope=load_scope(args.scope),
        opsec_policy=load_opsec_policy(args.opsec_policy),
        listener_host=args.listener_host,
        callback_host=args.callback_host,
    )
    plan = build_source_plan(sources, args.source, args.capability, request)
    output = source_plan_to_json(plan) if args.format == "json" else render_source_plan(plan)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_paths(args: argparse.Namespace) -> int:
    print(render_paths(read_result(args.result), include_blocked=args.include_blocked))
    return 0


def cmd_calculus(args: argparse.Namespace) -> int:
    print(render_calculus(read_result(args.result)))
    return 0


def cmd_controls(args: argparse.Namespace) -> int:
    print(render_controls(read_result(args.result)))
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    rows = list_profiles()
    output = profiles_to_json(rows) if args.format == "json" else render_profiles(rows)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_calibrate(args: argparse.Namespace) -> int:
    result = read_result(args.result)
    profiles = load_profiles(args.profiles)
    calibration = calibrate_result(result, profiles)
    if args.annotate_out:
        write_result(apply_calibration_to_result(result, calibration), args.annotate_out)
    output = (
        json.dumps(calibration, indent=2, sort_keys=True)
        if args.format == "json"
        else render_calibration(calibration)
    )
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_compare_baseline(args: argparse.Namespace) -> int:
    baseline = read_result(args.baseline)
    candidate = read_result(args.candidate)
    profiles = load_profiles(args.profiles)
    comparison = compare_baseline(baseline, candidate, profiles)
    output = (
        json.dumps(comparison, indent=2, sort_keys=True)
        if args.format == "json"
        else render_baseline_comparison(comparison)
    )
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_lab_corpus(args: argparse.Namespace) -> int:
    corpus = build_signature_corpus(
        read_result(args.result),
        label=args.label,
        environment=args.environment,
        policy_state=args.policy_state,
        expected_classification=args.expected_classification,
        expected_state=args.expected_state,
        expected_confidence=args.expected_confidence,
        promotion=args.promotion,
        promotion_reason=args.reason,
        remaining_uncertainty=list(args.uncertainty or []),
        notes=list(args.note or []),
    )
    output = json.dumps(corpus, indent=2, sort_keys=True) if args.format == "json" else render_signature_corpus(corpus)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_lab_matrix(args: argparse.Namespace) -> int:
    matrix = standard_lab_matrix(target_family=args.target_family)
    output = json.dumps(matrix, indent=2, sort_keys=True) if args.format == "json" else render_lab_matrix(matrix)
    _write_or_print(output, args.out)
    return 0


def cmd_lab_index(args: argparse.Namespace) -> int:
    try:
        corpuses = load_corpuses(list(args.corpus or []))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    index = summarize_corpuses(corpuses, target_family=args.target_family)
    output = json.dumps(index, indent=2, sort_keys=True) if args.format == "json" else render_corpus_index(index)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_lab_verify(args: argparse.Namespace) -> int:
    try:
        corpuses = load_corpuses(list(args.corpus or []))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report = verify_lab_corpus(
        corpuses,
        target_family=args.target_family,
        min_captures=args.min_captures,
    )
    output = json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else render_lab_verification(report)
    _write_or_print(output, args.out)
    return 2 if report.get("status") == "fail" else 0


def cmd_lab_provenance(args: argparse.Namespace) -> int:
    try:
        corpuses = load_corpuses(list(args.corpus or []))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report = assess_lab_provenance(corpuses, target_family=args.target_family)
    output = json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else render_lab_provenance(report)
    _write_or_print(output, args.out)
    return 2 if report.get("status") == "fail" else 0


def cmd_lab_stability(args: argparse.Namespace) -> int:
    try:
        corpuses = load_corpuses(list(args.corpus or []))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report = assess_lab_stability(
        corpuses,
        target_family=args.target_family,
        min_captures=args.min_captures,
        stable_threshold=args.stable_threshold,
    )
    output = json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else render_lab_stability(report)
    _write_or_print(output, args.out)
    return 2 if report.get("status") == "fail" else 0


def cmd_lab_diff(args: argparse.Namespace) -> int:
    try:
        corpuses = load_corpuses(list(args.corpus or []))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report = assess_lab_differentials(
        corpuses,
        target_family=args.target_family,
        min_captures=args.min_captures,
        stable_threshold=args.stable_threshold,
        pairs=list(args.pair or []),
    )
    output = json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else render_lab_differentials(report)
    _write_or_print(output, args.out)
    return 2 if report.get("status") == "fail" else 0


def cmd_lab_profile(args: argparse.Namespace) -> int:
    try:
        corpuses = load_corpuses(list(args.corpus or []))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    profile = corpus_to_profile(
        corpuses,
        profile_id=args.profile_id,
        target_family=args.target_family,
        service=args.service,
        description=args.description,
        min_captures=args.min_captures,
    )
    output = json.dumps(profile, indent=2, sort_keys=True) if args.format == "json" else render_generated_profile(profile)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    result = read_result(args.result)
    request = ValidationRequest(
        path_id=args.path_id,
        mode=args.mode,
        confirm=bool(args.confirm),
        operator=args.operator,
        reason=args.reason,
        max_noise=NoiseLevel(args.max_noise),
        timebox_seconds=args.timebox,
        scope=load_scope(args.scope),
        audit_log=args.audit_log or "",
        reprobe=bool(args.reprobe),
        auth_validation=bool(args.auth_validation),
        timeout=args.timeout,
        opsec_policy=load_opsec_policy(args.opsec_policy),
        operation_control=_operation_control_from_args(args),
    )
    try:
        run = validate_path(result, request)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    output = validation_to_json(run) if args.format == "json" else render_validation(run)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_rank(args: argparse.Namespace) -> int:
    result = read_result(args.result)
    ranked = sorted(result.paths, key=lambda p: p.score, reverse=True)[: args.top]
    result.paths = ranked
    print(render_paths(result, include_blocked=True))
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    print(render_explain(read_result(args.result), args.query))
    return 0


def cmd_fixes(args: argparse.Namespace) -> int:
    print(render_fixes(read_result(args.result), top=args.top))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    result = read_result(args.result)
    output = (
        render_plan_json(result, args.path_id)
        if args.format == "json"
        else render_plan(result, args.path_id)
    )
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_evidence_report(args: argparse.Namespace) -> int:
    report = build_evidence_report(read_result(args.result))
    output = evidence_report_to_json(report) if args.format == "json" else render_evidence_report(report)
    _write_or_print(output, args.out)
    return 2 if report.get("status") == "fail" else 0


def cmd_report(args: argparse.Namespace) -> int:
    output = render_report(read_result(args.result), args.format)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    try:
        output = export_result(read_result(args.result), args.format)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    try:
        manifest = write_enterprise_bundle(
            read_result(args.result),
            args.out_dir,
            formats=_split_csv_arg(args.formats),
            include_routes=not args.no_routes,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    output = bundle_manifest_to_json(manifest) if args.format == "json" else render_bundle_manifest(manifest)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0 if manifest.get("validation", {}).get("valid", False) else 2


def cmd_diff(args: argparse.Namespace) -> int:
    diff = diff_results(read_result(args.old), read_result(args.new))
    output = diff_to_json(diff) if args.format == "json" else render_diff(diff)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_simulate_fixes(args: argparse.Namespace) -> int:
    fixes = list(args.fix or [])
    fixes.extend(f"control:{control}" for control in args.control or [])
    simulation = simulate_fixes(read_result(args.result), fixes=fixes, top=args.top)
    output = simulation_to_json(simulation) if args.format == "json" else render_simulation(simulation)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_quality_gate(args: argparse.Namespace) -> int:
    report = run_quality_gate(args.project_root)
    output = quality_gate_to_json(report) if args.format == "json" else render_quality_gate(report)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0 if report.get("status") == "pass" else 2


def cmd_opsec(args: argparse.Namespace) -> int:
    if args.opsec_action == "list":
        policies = list_opsec_policies()
        output = opsec_policies_to_json(policies) if args.format == "json" else render_opsec_policies(policies)
        _write_or_print(output, args.out)
        return 0
    policy = load_opsec_policy(args.policy)
    output = opsec_policy_to_json(policy) if args.format == "json" else render_opsec_policy(policy)
    _write_or_print(output, args.out)
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    if args.schema_action == "list":
        output = schema_contracts_to_json() if args.format == "json" else render_schema_contracts()
        _write_or_print(output, args.out)
        return 0
    report = validate_schema_path(args.path, kind=args.kind)
    output = schema_validation_to_json(report) if args.format == "json" else render_schema_validation(report)
    _write_or_print(output, args.out)
    return 0 if report.valid else 2


def cmd_modules(args: argparse.Namespace) -> int:
    try:
        registry = load_module_registry(args.manifests, include_defaults=not args.no_defaults)
        inventory = module_inventory(registry, module_key=args.module)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    output = module_inventory_to_json(inventory) if args.format == "json" else render_module_inventory(inventory)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_module_plan(args: argparse.Namespace) -> int:
    try:
        registry = load_module_registry(args.manifests, include_defaults=not args.no_defaults)
        plan = build_module_plan(
            read_result(args.result),
            args.path_id,
            registry,
            module_key=args.module,
            mode=args.mode,
            accept_non_ready=bool(args.accept_non_ready),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    output = module_plan_to_json(plan) if args.format == "json" else render_module_plan(plan)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if not args.result or not args.path_id:
        print("relayx run requires --result and --path-id.", file=sys.stderr)
        return 2
    try:
        registry = load_module_registry(args.manifests, include_defaults=not args.no_default_modules)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    result = read_result(args.result)
    request = ExecutionRequest(
        path_id=args.path_id,
        mode=args.mode,
        confirm=bool(args.confirm),
        operator=args.operator,
        reason=args.reason,
        max_noise=NoiseLevel(args.max_noise),
        timebox_seconds=args.timebox,
        scope=load_scope(args.scope),
        audit_log=args.audit_log or "",
        module=args.module,
        accept_non_ready=bool(args.accept_non_ready),
        module_registry=registry,
        opsec_policy=load_opsec_policy(args.opsec_policy),
        listener_host=args.listener_host,
        callback_host=args.callback_host,
    )
    try:
        run = execute_path(result, request)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.annotate_out:
        write_result(apply_execution_to_result(result, run), args.annotate_out)
    output = execution_to_json(run) if args.format == "json" else render_execution(run)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parse_argv, no_banner_requested, no_color_requested = _strip_human_output_flags(raw_argv)
    if _argv_requests_argparse_help(parse_argv) and not no_banner_requested:
        print(_format_banner())
    parser = build_parser()
    args = parser.parse_args(parse_argv)
    args.no_banner = no_banner_requested or getattr(args, "no_banner", False)
    args.no_color = no_color_requested or getattr(args, "no_color", False)
    handlers = {
        "help": cmd_help,
        "discover": cmd_discover,
        "next": cmd_next,
        "completion": cmd_completion,
        "console": cmd_console,
        "scan": cmd_scan,
        "assess": cmd_scan,
        "summary": cmd_summary,
        "matrix": cmd_matrix,
        "sources": cmd_sources,
        "routes": cmd_routes,
        "source-check": cmd_source_check,
        "source-plan": cmd_source_plan,
        "paths": cmd_paths,
        "calculus": cmd_calculus,
        "controls": cmd_controls,
        "profiles": cmd_profiles,
        "calibrate": cmd_calibrate,
        "compare-baseline": cmd_compare_baseline,
        "lab-matrix": cmd_lab_matrix,
        "lab-corpus": cmd_lab_corpus,
        "lab-verify": cmd_lab_verify,
        "lab-provenance": cmd_lab_provenance,
        "lab-stability": cmd_lab_stability,
        "lab-diff": cmd_lab_diff,
        "lab-index": cmd_lab_index,
        "lab-profile": cmd_lab_profile,
        "validate": cmd_validate,
        "rank": cmd_rank,
        "explain": cmd_explain,
        "fixes": cmd_fixes,
        "plan": cmd_plan,
        "evidence-report": cmd_evidence_report,
        "report": cmd_report,
        "export": cmd_export,
        "bundle": cmd_bundle,
        "diff": cmd_diff,
        "simulate-fixes": cmd_simulate_fixes,
        "quality-gate": cmd_quality_gate,
        "opsec": cmd_opsec,
        "schema": cmd_schema,
        "modules": cmd_modules,
        "module-plan": cmd_module_plan,
        "run": cmd_run,
    }
    if _should_emit_banner(args):
        print(_format_banner())
    try:
        return handlers[args.command](args)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
