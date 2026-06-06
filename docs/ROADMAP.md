# RelayX Roadmap

RelayX is an OPSEC-aware NTLM relay exposure assessment, lab-calibrated
validation, and controlled execution orchestration tool for authorized red
teaming.

This roadmap separates implemented product capability from data-dependent
calibration work, deliberately disabled live capability, and future engineering
tracks. The guiding standard is evidence-backed relay exposure analysis:
RelayX should explain what it observed, what it inferred, what remains
uncertain, and what an operator is allowed to do next.

## Implemented In v0.1.14

The v0.1.14 release completes the current engineering baseline for RelayX.
These capabilities are implemented, schema-covered, documented, and guarded by
the quality gate.

- Native readiness assessment for SMB, HTTP/HTTPS NTLM, LDAP/LDAPS, and MSSQL.
- NTLM Type1/Type2 challenge-flow evidence for HTTP, LDAP/LDAPS, and MSSQL.
- MSSQL TDS-wrapped TLS negotiation and `tls-server-end-point` CBT evidence
  collection when server TLS completes.
- Optional synthetic Type3 authentication validation for explicitly authorized
  HTTP, LDAP/LDAPS, and MSSQL lab or assessment use.
- Conservative response classification for EPA, LDAP signing, LDAPS CBT, MSSQL
  encryption/EPA, and generic synthetic authentication rejection states.
- Source capability modeling for WebClient/WebDAV, RPC coercion surfaces, MSSQL
  outbound authentication, ADIDNS, ghost SPN, and name-resolution inducement.
- Source-to-target path construction with scope, route/pivot awareness, OPSEC
  noise, blocker, remediation, and expected telemetry metadata.
- Route/Pivot Awareness for source sessions, segments, subnets, structured
  route hops, pivot type normalization, reachability state, and route risk.
- Authorized direct TCP reachability checks from the operator runtime for route
  reports without opening or operating pivot sessions.
- Relay calculus annotations for rule ID, target family, preconditions,
  hardening gates, decision state, and defensive controls.
- Lab calibration profiles and baseline comparison for controlled IIS/AD CS,
  LDAP, LDAPS, and MSSQL policy states.
- Offline lab corpus extraction and calibration profile draft generation.
- Standard lab matrix generation and corpus coverage verification for
  HTTP/IIS EPA, AD CS Web Enrollment EPA, LDAP signing, LDAPS CBT, and MSSQL
  encryption/EPA policy states.
- Lab corpus provenance review for synthetic fixture boundaries, authorized
  lab capture metadata, endpoint build metadata, drift baselines, and
  operator-reviewed promotion decisions.
- Repeat-capture lab stability analysis for consistency scoring, drift keys,
  missing signature keys, and promotion auto-downgrade reasons.
- Lab response differential analysis for comparing stable policy-state
  signatures and separating response discriminators from context-only fields.
- Evidence completeness reporting for existing results, including finding/path
  evidence counts, confidence distribution, protocol judgement fields, missing
  contract keys, and remaining uncertainty.
- Evidence source taxonomy for separating wire observations, policy
  inferences, lab-calibration evidence, source and route models, control
  mappings, operator context, errors, and unsupported boundaries.
- OPSEC policies for validation, execution, source planning, listener planning,
  callback planning, connect checks, armed mode, and confirmed mode.
- Operation controls for assessment, route-check, and validation commands,
  including rate-limit, delay, jitter, start-after, and stop-before.
- Guarded validation and controlled execution state machines with dry-run,
  armed, and confirmed modes.
- Execution module inventory, module planning, and Adapter SDK dispatch,
  including a supported offline audit-record adapter, credential/listener
  policy guardrails, lifecycle audit, lab-only fixture boundaries, and explicit
  unsupported boundaries for live relay adapters.
- Versioned schema and evidence contract validation for results, lab profiles,
  corpuses, lab provenance reports, lab stability reports, execution records,
  module manifests, OPSEC policies, route reports, bundle manifests, quality
  gates, OpenGraph, JSONL, and CSV.
- Enterprise exports for OpenGraph-style graph analysis, JSONL, CSV, Markdown,
  HTML, Mermaid, multi-scan diffing, and remediation impact simulation.
- Enterprise bundle generation with manifest, artifact hashes, schema
  validation status, and optional route report.
- Quality-gate v2 contract for release automation, including package metadata,
  fixture determinism, schema contracts, documentation coverage, GitHub
  workflow coverage, wheel build expectations, and install smoke tests.
- Short option aliases and curated help topics for common interactive CLI
  workflows, with safety-sensitive guardrails preserved.
- Complete offline tutorial and schema-validated example result fixtures that
  exercise assessment review, calibration, validation planning, offline
  execution audit, enterprise bundle, diff, and remediation simulation
  workflows.
- Authorized AD/IIS/AD CS/MSSQL integration-test expectations documented in
  `docs/INTEGRATION_TESTS.md`.

## Data-Dependent Calibration Work

This work is not blocked by missing framework code. It depends on authorized
lab environments and repeated real captures. The current codebase already has
the corpus, provenance, stability, differential, schema, and quality-gate
contracts needed to ingest this data.

- Populate the real lab profile corpus across Windows Server, IIS, AD CS,
  domain controller, and SQL Server policy matrices.
- Expand the real lab profile corpus with repeated captures per standard
  matrix state, raw signatures, expected classifications, promotion reasons,
  remaining uncertainty, and drift baselines for known unstable endpoints.
- Expand real HTTP/IIS EPA, AD CS Web Enrollment EPA, LDAP signing, LDAPS CBT,
  and MSSQL encryption/EPA response-difference captures beyond the bundled
  synthetic fixture corpus.
- Feed authorized real lab-corpus provenance, endpoint build metadata, drift
  baselines, and operator-reviewed promotion decisions into the existing
  provenance contract as those artifacts become available from labs.
- Keep synthetic authentication rejection states subdivided without treating
  invalid-credential rejection as proof of relayability.

Relevant fixture and contract files:

- `fixtures/protocol_validation_matrix.json`
- `fixtures/relay_calculus_matrix.json`
- `fixtures/active_validation_matrix.json`
- `fixtures/source_validation_matrix.json`
- `fixtures/controlled_execution_matrix.json`
- `fixtures/enterprise_output_matrix.json`
- `fixtures/execution_module_matrix.json`
- `fixtures/route_pivot_matrix.json`
- `fixtures/lab_corpus/*.json`

## Next Development Tracks

These tracks are suitable for continued development now because they improve
trust, reporting, and reviewability without enabling uncontrolled live relay
execution.

### Enterprise Trust

Goal: strengthen enterprise handoff integrity and downstream ingestion.

- Add signed export manifests for organizations that need immutable evidence
  handoff packages.
- Add `relayx bundle verify` or equivalent manifest verification.
- Add export profiles for team-defined CSV/JSONL allowlists while preserving
  the default stable field contract.
- Add quality-gate checks for signed bundle metadata and export profile schema.

### Telemetry Catalog

Goal: make expected telemetry more precise without pretending lab-specific
event behavior is universal.

- Add a telemetry catalog schema and fixtures for Windows security events,
  LDAP bind failures, IIS logs, AD CS Web Enrollment logs, SQL Server audit or
  error events, and network sensor observations.
- Map validation and execution plans to expected telemetry families.
- Add report and bundle sections that show expected telemetry, collection
  surface, rollback notes, and remaining uncertainty.
- Fill exact event IDs, log fields, and product-specific differences from
  authorized lab captures over time.

### Route Adapter SDK

Goal: support richer authorized reachability checks while preserving the
current no-broad-pivot default.

- Add route adapter contracts for pre-existing proxy, tun, or SOCKS contexts.
- Keep proxy/tun checks disabled or lab-only until scope, audit, OPSEC, and
  regression requirements are satisfied.
- Record adapter identity, route scope, expected telemetry, timeout behavior,
  and rollback assumptions.
- Keep direct TCP checks as the default operator-runtime reachability mode.

### Live Capability Review Pack

Goal: prepare for future live modules without registering live relay
capability by default.

- Add protocol design review checklists for future live relay adapters.
- Add credential handling policy checks for capture, forwarding, storage,
  masking, and audit boundaries.
- Add listener lifecycle fixtures for bind, accept, timeout, cleanup, and
  rollback behavior.
- Add mock/lab-only adapters and negative tests that prove unsupported or
  lab-only modules cannot dispatch in confirmed mode.
- Add authorized lab regression harness requirements before any live adapter
  can be registered as supported.

## Deliberately Disabled Pending Review

These capabilities are intentionally not enabled in the default product. They
should remain disabled until they pass protocol design review, credential
handling review, OPSEC review, and authorized lab regression.

- Live relay adapters.
- Source trigger and target relay linked execution.
- Credential capture or forwarding by RelayX execution modules.
- Listener-backed live relay modules.
- Proxy/tun route reachability adapters outside lab-only or explicitly
  authorized adapter contracts.

Current controlled execution support remains limited to safe offline audit
recording through `relayx_audit_record`.

## OPSEC Direction

RelayX should favor controlled, auditable action over broad probing.

Current OPSEC capabilities are implemented in v0.1.14. Future OPSEC work should
focus on:

- Policy-profile presets for common engagement windows and rate envelopes.
- Deeper telemetry mapping by Windows event family, IIS log surface, SQL audit
  source, LDAP diagnostic surface, AD CS web logs, and network sensor type.
- Richer route reachability validation through authorized, scoped adapters
  while preserving no-broad-pivot defaults.
- Stronger rollback recording for active or future-active operations.

## Engineering Quality Direction

The engineering quality baseline is implemented in v0.1.14. Future quality
work should focus on keeping release automation trustworthy as the project adds
real lab data and future adapter contracts.

- Keep the `relayx quality-gate` contract stable for release automation.
- Keep CLI short-option coverage, generated help, README, and CLI docs
  synchronized through the quality gate.
- Keep lab fixtures deterministic and tied to expected classifications.
- Keep integration-test expectations current for authorized AD/IIS/AD CS/MSSQL
  labs.
- Add quality-gate checks for signed bundle verification, telemetry catalog
  fixtures, route adapter contracts, and future live-capability review packs as
  those tracks are implemented.
