# RelayX Enterprise Outputs

RelayX turns a result file into artifacts that can be consumed by operators,
defenders, reporting workflows, SIEM pipelines, and graph tooling.

The complete offline tutorial in [`docs/TUTORIAL.md`](TUTORIAL.md) exercises
the enterprise output workflow with the fixtures in
[`examples/tutorial`](../examples/tutorial).

## Commands

```bash
relayx export --result result.json --format opengraph --out relayx-opengraph.json
relayx export --result result.json --format jsonl --out relayx-events.jsonl
relayx export --result result.json --format csv --out relayx.csv
relayx bundle -r result.json -d relayx-bundle
relayx diff old-result.json new-result.json --format json --out relayx-diff.json
relayx simulate-fixes result.json --control smb_signing --format json
relayx routes --result result.json --format json --out relayx-routes.json
relayx evidence-report --result result.json --format json --out relayx-evidence-report.json
relayx quality-gate -C . -f json -o relayx-quality-gate.json
relayx schema validate --kind opengraph relayx-opengraph.json
relayx schema validate --kind jsonl relayx-events.jsonl
relayx schema validate --kind csv relayx.csv
relayx schema validate --kind route-report relayx-routes.json
relayx schema validate -k bundle-manifest relayx-bundle/manifest.json
relayx schema validate -k quality-gate relayx-quality-gate.json
```

## OpenGraph

`--format opengraph` emits a custom BloodHound/OpenGraph-style JSON document
with `graph.nodes` and `graph.edges`. RelayX uses custom kinds such as
`RelayXScan`, `RelayXSource`, `RelayXTargetService`, and `RelayXPath` so that
relay readiness context does not collide with AD or Azure entity kinds.

The export includes `metadata.field_contract_version` and a `mapping` object.
`mapping.node_kinds` and `mapping.edge_kinds` document the RelayX node and edge
contract inside the artifact itself. Edges carry deterministic IDs so graph
imports, repeat exports, and scan diffs can reason about stable relationships.

Current custom node kinds include:

- `RelayXScan`
- `RelayXSource`
- `RelayXTarget`
- `RelayXTargetService`
- `RelayXFinding`
- `RelayXPath`
- `RelayXControl`

Current custom edge kinds include path ownership, source/target relationships,
candidate relay relationships, and `RelayXPathMitigatedBy` edges from paths to
defensive controls.

## JSONL

`--format jsonl` emits one event per line:

- `relayx.scan`
- `relayx.source`
- `relayx.finding`
- `relayx.path`
- `relayx.control`

This is the preferred format for SIEM and blue-team pipelines.

Every event includes `event_type`, `event_id`, `schema_version`, and
`field_contract_version`. Path events keep stable judgement and routing fields
such as `rule_id`, `decision`, `target_family`, `source_capability`,
`control_keys`, `route_state`, `route_risk_level`, and
`remaining_uncertainty`.

## CSV

`--format csv` emits one table with `finding` and `path` rows. The header is the
field contract. It includes stable SIEM/spreadsheet fields for host, protocol,
status, score, impact, source, target service, calculus decision, target
family, source capability, defensive controls, route risk, blockers, fixes,
remaining uncertainty, and `field_contract_version`.

## HTML Reports

HTML reports are designed to work as offline bundle artifacts. The path table
includes filters for:

- free text
- status
- severity
- protocol
- source capability
- target family
- defensive control

The filters operate on row `data-*` attributes, so the visible table and the
underlying path metadata remain aligned when the report is archived.

## Enterprise Bundle

`relayx bundle` writes a complete handoff directory from one result file. The
default bundle contains the canonical RelayX result, OpenGraph, JSONL, CSV,
HTML, Markdown, Mermaid, and a route report when source metadata is available.

The bundle also writes `manifest.json`. The manifest records each artifact's
relative path, format, schema kind, schema validation status, byte size, and
SHA256 hash. It is intended to be archived with the engagement evidence set and
validated with:

```bash
relayx schema validate -k bundle-manifest relayx-bundle/manifest.json
```

## Route Reports

`relayx routes` emits a route and pivot awareness report. It records modeled
source-to-target reachability, route state, pivot types, hop count, route risk,
and remaining uncertainty. Route reports are offline model artifacts by
default. With `--connect-check`, they can include authorized direct TCP
reachability observations from the operator runtime; this still does not open,
prove, or operate pivot sessions.

## Schema Validation

Enterprise artifacts can be validated before handoff:

```bash
relayx schema validate --kind opengraph relayx-opengraph.json
relayx schema validate --kind jsonl relayx-events.jsonl
relayx schema validate --kind csv relayx.csv
```

Validation reports include path-level errors and warnings. Use `--format json`
for CI and ingestion pipeline checks.

## Quality Gate

`relayx quality-gate` is the local CI and release gate. It validates package
metadata, schema catalog coverage, JSON fixtures, schema fixture directories,
enterprise output matrix coverage, lab matrix coverage, lab provenance checks,
lab stability checks, lab differential checks, evidence-report checks, evidence
source taxonomy coverage, including the evidence source taxonomy used by result
reviews, documentation coverage, and GitHub Actions workflow presence. Failed
gates return exit code `2`.

```bash
relayx quality-gate -C . -f json -o relayx-quality-gate.json
relayx schema validate -k quality-gate relayx-quality-gate.json
```

The GitHub CI workflow runs unit tests, the quality gate, wheel build smoke
tests, and wheel install smoke tests. The release workflow repeats those gates
and verifies that a `v*` tag matches the package version before building source
and wheel distributions.

## Diff

`relayx diff` compares stable path fingerprints:

```text
source | transport | target | target_service
```

It reports added, removed, and changed paths, plus finding additions/removals and
score movement. Path changes include protocol oracle subclassification and
route risk changes when those fields are present.

Diff output also reports `exposure_trend`, `score_delta`, `control_trends`,
`remediation_regressions`, and `remediation_improvements`. This makes repeated
scans usable as a remediation trend record rather than only a path inventory
comparison.

## Remediation Simulation

`relayx simulate-fixes` calculates the path and score reduction if matching
fixes or RelayX controls are treated as implemented. It does not mutate the
input result file.

Simulation output is an estimate. It records affected paths, score reduction,
control dependencies, remaining controls, remaining target families, and
estimated residual exposure. Dependency records are intentionally conservative:
they show which related controls still appear on remaining paths, not proof that
those controls have been implemented or bypassed.
