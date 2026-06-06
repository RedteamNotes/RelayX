# RelayX CLI Help

RelayX keeps standard `-h` output for every command and adds registry-backed
curated help topics for workflows, examples, exports, OPSEC boundaries,
completion, and troubleshooting. The CommandSpec registry is the single source
for grouped command help, short-option documentation, shell completion, and
quality-gate drift checks.

For a complete end-to-end offline walkthrough, use
[`docs/TUTORIAL.md`](TUTORIAL.md) or
[`docs/TUTORIAL.zh-CN.md`](TUTORIAL.zh-CN.md) with the fixtures in
[`examples/tutorial`](../examples/tutorial).
Authorized AD/IIS/AD CS/MSSQL integration-test expectations are documented in
[`docs/INTEGRATION_TESTS.md`](INTEGRATION_TESTS.md).

## Quick Help

```bash
relayx help
relayx help getting-started
relayx help commands
relayx help workflows
relayx help exports
relayx help short-options
relayx help safety
relayx help calibration
relayx help execution
relayx help enterprise
relayx help troubleshooting
relayx help completion
relayx help scan
relayx help run
relayx help schema
relayx help bundle
relayx help quality-gate
relayx -q help
```

Use `--format json` when you want machine-readable help content:

```bash
relayx help export -f json
```

`-q` is an alias for `--no-banner`, and `-V` is an alias for `--version`.

Command-specific curated help uses a consistent operator format:

```text
What it does
When to use
Required inputs
Safety notes
Examples
Short options
Output formats and contracts
Common mistakes
Next steps
```

## Command Groups

- Assessment: `scan`, `assess`, `summary`, `matrix`, `sources`, `paths`,
  `rank`, `explain`
- Evidence: `calculus`, `controls`, `fixes`, `plan`, `evidence-report`
- Calibration: `calibrate`, `compare-baseline`, `lab-matrix`, `lab-corpus`,
  `lab-verify`, `lab-provenance`, `lab-stability`, `lab-diff`, `lab-index`,
  `lab-profile`
- Route/Pivot: `routes`, `source-check`, `source-plan`
- Validation: `validate`
- Controlled Execution: `modules`, `module-plan`, `run`
- Enterprise: `profiles`, `report`, `export`, `bundle`, `diff`,
  `simulate-fixes`
- Admin: `help`, `discover`, `next`, `completion`, `console`, `opsec`,
  `schema`, `quality-gate`

## Command Discovery And Next Steps

`relayx discover` searches the CommandSpec registry, examples, output
contracts, help topics, and safety notes. Use it when you know the task but do
not remember the command.

```bash
relayx discover epa
relayx discover jsonl
relayx discover route --group Route/Pivot
relayx discover execution --format json
```

`relayx next` suggests concrete follow-up commands. With no result, it prints a
first-run path. With a result, it summarizes top paths and suggests review,
evidence, route, validation, execution-planning, and enterprise handoff
commands. With `--path-id`, it focuses the guidance on that path.

```bash
relayx next
relayx next --result examples/tutorial/sample-result.json
relayx next --result examples/tutorial/sample-result.json --path-id PX-0001
relayx next -r examples/tutorial/sample-result.json -p PX-0001 -f json
```

`next` is read-only. It does not perform validation, execution, probing, export,
or file modification.

## Operator Console

`relayx console` provides a local, single-process operator shell for repeated
work on the same result, path, OPSEC policy, and scope. It keeps the current
operator context visible in the prompt and reuses the same RelayX CLI handlers
and guardrails as scripted workflows.

```bash
relayx console
relayx console --result examples/tutorial/sample-result.json --path-id PX-0001 --opsec-policy strict
relayx console --script console.txt
relayx console --history-file ~/.relayx/history
relayx console --no-history --no-completion
relayx --no-color console --result examples/tutorial/sample-result.json
```

Interactive sessions use the terminal readline backend when available. That
enables Up/Down command history navigation, incremental line editing, Tab completion
for console commands, help topics, `show` targets, OPSEC policies, and
result-file paths, plus Ctrl-L clear-screen behavior on terminals that support
it. RelayX also provides explicit `clear` and `cls` commands.

History is persisted to `RELAYX_HISTORY_FILE`, or `~/.relayx/history` by
default. Use `--history-file` to choose a different file, `--no-history` or
`RELAYX_NO_HISTORY=1` to disable history, and prefix a command with a leading
space to keep that command out of persistent history. Commands containing
obvious secret-bearing flags such as `--password` or `--token` are not saved.
Script mode keeps deterministic text behavior and does not use readline.

The prompt reflects context:

```text
relayx>
relayx[result:sample-result.json policy:standard]>
relayx[result:sample-result.json path:PX-0001 policy:strict scope:set]>
```

Supported console commands:

```text
use result <file>          Select a RelayX result and clear the current path
use path <id>              Select a path such as PX-0001
set opsec-policy <policy>  Set the policy used by validate/run shortcuts
set scope <scope>          Set scope text or a scope file for validate/run
context                    Show current result, path, policy, and scope
show summary               Run summary with the selected result
show paths                 Run paths with the selected result
show matrix                Run matrix with the selected result
show sources               Run sources with the selected result
explain [query]            Explain a query or the selected path
menu                       Show grouped console commands and tips
next                       Suggest next commands from selected result/path
discover <keyword>         Search commands and topics from the console
validate [args...]         Run validate with context-filled result/path/policy
run [args...]              Run controlled execution with context-filled inputs
export [args...]           Run export with context-filled result
bundle [args...]           Run bundle with context-filled result
help [topic]               Render curated RelayX help
?                          Alias for help
clear / cls                Clear the interactive terminal
history [limit]            Show recent commands from the current session
history clear              Clear in-memory and persisted console history
back                       Clear path first, then result
exit / quit                Leave the console
```

Console shortcuts call the same CLI handlers and preserve the same guardrails.
Confirmed validation and execution still require explicit confirmation,
operator, reason, audit log, and any required scope. Script mode returns exit
code `2` on the first failed console command, which makes it suitable for
runbook smoke tests.

## Shell Completion

`relayx completion bash|zsh|fish` prints shell completion generated from the
CommandSpec registry. Completion covers commands, curated help topics, common
flags, output formats, schema kinds, export formats, and built-in OPSEC policy
names.

```bash
relayx completion bash > relayx.bash
relayx completion zsh > relayx.zsh
relayx completion fish > relayx.fish
```

Completion only suggests syntax. It does not weaken authorization, OPSEC,
scope, audit, or adapter checks.

ANSI color is enabled by default for human-readable curated help and console
output. Use `--no-color` or the `NO_COLOR` environment variable for plain text.
Machine-readable output and generated completion scripts are never colorized.

## Short Options

RelayX exposes short aliases for high-use options. Long options remain the
clearest choice for shared runbooks and scripts; short options are intended for
interactive work and compact local commands.

Common aliases:

```text
-f, --format        Output format where supported
-o, --out           Output path
-r, --result        RelayX result JSON
-s, --sources       Source profile input
-t, --targets       Target input
-S, --scope         Scope input
-q, --no-banner     Suppress human-readable banner output
-V, --version       Print RelayX version
-Q, --rate-limit    Maximum active starts per minute where supported
-D, --delay         Minimum delay between active starts
-J, --jitter        Random delay added to active start spacing
-U, --start-after   ISO-8601 operation window start
-Z, --stop-before   ISO-8601 operation window end
```

Safety and execution aliases:

```text
-m, --mode          dry-run, armed, or confirmed
-p, --path-id       Path ID such as PX-0001
-y, --confirm       Required for confirmed mode
-O, --operator      Operator identity for audit records
-R, --reason        Authorization or operational reason
-A, --audit-log     JSONL audit log path
-P, --opsec-policy  Built-in policy name or external policy JSON
-L, --listener-host Planned listener host for scope checks
-K, --callback-host Planned callback host for scope checks
```

Use `relayx help short-options` for the complete alias map. Short aliases do not
change guardrails: confirmed validation and execution still require explicit
confirmation, operator, reason, scope where required, and audit logging.

## Route And Pivot Awareness

```bash
relayx routes --sources examples/sources.json --targets examples/targets.txt
relayx routes -r result.json -f json -o relayx-routes.json
relayx routes -s examples/sources.json -t examples/targets.txt -P ldap --connect-check --rate-limit 60 -f json -o relayx-routes.json
```

Route awareness is model-driven by default. With `--connect-check`, RelayX runs
authorized direct TCP checks from the operator runtime only; it does not open,
prove, or operate pivot sessions. Source profiles can provide
`session`, `segment`, `subnets`, free-form `routes`, and structured
`route_hops`. Structured routes produce stronger reachability evidence than
unconstrained labels.

## Operation Controls

`scan`, `assess`, `routes --connect-check`, and `validate` accept operation
controls for controlled assessment windows:

```bash
relayx scan -t examples/targets.txt -o result.json --rate-limit 120 --stop-before 2030-01-01T18:00:00+08:00
relayx validate -r result.json -p PX-0001 -m confirmed -y -O redpen -R "authorized target reprobe" -A audit.jsonl -e --start-after 2030-01-01T14:00:00+08:00 --stop-before 2030-01-01T18:00:00+08:00
```

`--rate-limit` controls operation starts per minute. `--delay` sets a minimum
spacing between starts, and `--jitter` adds randomized delay. `--start-after`
and `--stop-before` use ISO-8601 timestamps; naive timestamps are interpreted
in the local timezone. Confirmed validation reprobes fail closed outside the
window, while dry-run validation records the same window as a warning.

## Evidence Report

```bash
relayx evidence-report -r result.json
relayx evidence-report -r examples/tutorial/sample-result.json -f json -o evidence-report.json
relayx schema validate -k evidence-report evidence-report.json
```

`evidence-report` audits an existing result offline. It reports whether
candidate or relayable records have evidence, whether protocol judgement
records expose response classification, policy inference, and remaining
uncertainty, whether any evidence still has unknown confidence, and how each
evidence item maps into the source taxonomy. The taxonomy separates wire
observation, policy inference, lab calibration, source model, route model,
control mapping, operator context, error, and unsupported-boundary evidence.
It is meant for lab promotion review, enterprise handoff, and fixture quality
checks; it does not scan, validate, relay, or mutate the result file.

## Schema Contracts

```bash
relayx schema list
relayx schema list -f json
relayx schema validate result.json
relayx schema validate -k lab-profile fixtures/lab_profiles
relayx schema validate -k jsonl relayx-events.jsonl
```

Supported schema kinds are `result`, `evidence`, `lab-profile`, `lab-corpus`,
`lab-provenance`, `lab-stability`, `lab-differential`, `evidence-report`,
`execution-record`, `module-manifest`, `opsec-policy`, `route-report`,
`bundle-manifest`, `quality-gate`, `opengraph`, `jsonl`, and `csv`.
Invalid artifacts return exit code `2`.

Pin `-k/--kind` when validating a directory. Auto inference is useful for a
single artifact, but a directory may contain files with the same suffix and
different contracts.

## Enterprise Bundle And Quality Gate

```bash
relayx bundle --result result.json --out-dir relayx-bundle
relayx bundle -r result.json -d relayx-bundle -F opengraph,jsonl,csv
relayx quality-gate --project-root .
relayx quality-gate -C . -f json -o relayx-quality-gate.json
```

`relayx bundle` writes a validated handoff directory with a manifest, artifact
hashes, schema status, and optional route report. `relayx quality-gate` is the
local CI/release gate for package metadata, fixtures, schema contracts,
enterprise documentation, GitHub workflow coverage, version consistency, and
short-option coverage.

In `relayx bundle`, `-f/--format` controls the manifest summary printed by the
command, while `-F/--formats` controls which artifacts are written into the
bundle.

`relayx export -f opengraph` includes node/edge mappings, deterministic edge
IDs, and RelayX control nodes. `relayx export -f jsonl` and `relayx export -f
csv` use stable field contracts for SIEM and spreadsheet ingestion. HTML
reports include offline filters for status, severity, protocol, source
capability, target family, defensive control, and free text.

`relayx diff` reports exposure trend, score delta, control trends, remediation
regressions, and remediation improvements. `relayx simulate-fixes` reports
control dependencies and estimated residual exposure in addition to affected
paths and score reduction.

## Validation And Execution Modes

`dry-run` explains guardrails and expected telemetry without performing an
active validation or adapter execution. `armed` records intent and readiness.
`confirmed` requires explicit `-y/--confirm`, `-O/--operator`, `-R/--reason`,
and `-A/--audit-log`; OPSEC policy and scope checks may require additional
context.

`-u/--auth-validation` is separate from Type1/Type2 challenge-flow evidence and
can create failed-logon telemetry. Use it only in explicitly authorized lab or
assessment windows.

`source-plan` and `run` accept `--listener-host` and `--callback-host` as
planning inputs for stricter scope contracts. Supplying these values does not
start listeners or callbacks; it records and checks the intended boundaries.

## Lab Matrix And Corpus Verification

```bash
relayx lab-matrix
relayx lab-matrix -t mssql_epa -f json -o lab-matrix.json
relayx lab-verify -c fixtures/lab_corpus
relayx lab-verify -c fixtures/lab_corpus -t ldaps_cbt -m 2 -f json
relayx lab-provenance -c fixtures/lab_corpus -f json -o lab-provenance.json
relayx lab-stability -c fixtures/lab_corpus -m 2
relayx lab-stability -c fixtures/lab_corpus -t mssql_epa -m 3 -T 0.9 -f json
relayx lab-diff -c fixtures/lab_corpus -t http_iis_epa -p epa_off:epa_required -f json
```

`lab-matrix` prints the standard policy-state coverage plan for HTTP/IIS EPA,
AD CS Web Enrollment EPA, LDAP signing, LDAPS CBT, and MSSQL encryption/EPA.
`lab-verify` checks whether lab corpuses cover that matrix and whether each
required state has the expected stable signature keys. The commands are
offline; they do not scan or promote findings by themselves.

`lab-provenance` is the corpus evidence-admission layer. It audits whether
each corpus declares synthetic versus non-synthetic origin, capture source,
endpoint build metadata, drift baseline, and capture-level operator review.
Synthetic fixtures may pass the structure contract but are explicitly marked as
not real lab promotion evidence. Non-synthetic `promote` or `block` hints are
reported as not promotion-ready until the corpus and capture review approve the
decision.

`lab-stability` is the repeat-capture quality layer. It groups captures by
target family and lab policy state, computes `consistency_score` as the dominant
stable-signature ratio, reports drift keys, and explains why promotion hints
remain promotable or are downgraded to `retain`. The command defaults to
`--min-captures 2` and `--stable-threshold 0.85`; increase both when building a
profile intended for high-assurance lab promotion.

`lab-diff` compares stable policy-state signatures from the corpus and reports
which changed fields are response discriminators versus context-only
differences. It is useful for reviewing HTTP/IIS EPA, AD CS EPA, LDAP signing,
LDAPS CBT, and MSSQL encryption/EPA response deltas before editing calibration
profiles. It does not compare two result files; use `compare-baseline` for that
workflow. Unmatched `-p/--pair` filters are reported as warnings so a typo does
not silently produce an empty pass report.

## Execution Adapter SDK

`relayx modules` and `relayx module-plan` expose both module manifests and the
registered Adapter SDK contract. Confirmed execution is blocked unless the
adapter is registered, credential policy is allowed, listener policy is allowed,
the module support declaration is consistent with the adapter boundary, and
explicit scope is supplied. Lab-only module fixtures may describe future live
adapter contracts, but they are not registered live execution modules.

## Help Content

- Top-level help is compact and workflow-oriented.
- Command-specific help includes purpose, examples, notes, and related commands.
- Safety boundaries are available as first-class help topics.
- JSON help output uses the same source as text help to avoid documentation
  drift.
- Human-readable output may show a RelayX banner and version. `--no-banner`
  suppresses it, and machine-readable formats stay banner-free.
