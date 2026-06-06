# RelayX Complete Offline Tutorial

This tutorial walks through a complete RelayX workflow using the offline
fixtures in `examples/tutorial`. It is designed for training, documentation,
CI smoke tests, and runbook development. The workflow does not scan the
network, does not relay credentials, and does not trigger source-side
coercion.

Use this tutorial to understand the RelayX result model before adapting the
workflow to an authorized lab or engagement.

## Scenario

The tutorial models a small enterprise assessment:

- `jump01.redteamnotes.com` is an authorized workstation-like source with
  WebClient and Spooler capability metadata and a Ligolo route.
- `sqlagent01.redteamnotes.com` is an authorized SQL-adjacent source with
  MSSQL outbound-auth capability metadata and a Sliver P2P route.
- `filesrv01.redteamnotes.com` exposes an SMB path where signing is not
  required.
- `ca01.redteamnotes.com` exposes an AD CS Web Enrollment HTTP NTLM path that
  needs EPA calibration.
- `dc01.redteamnotes.com` exposes LDAP/LDAPS examples that demonstrate
  conservative signing and CBT interpretation.
- `sql01.redteamnotes.com` exposes an MSSQL SSPI path with TDS-wrapped TLS and
  CBT evidence, while EPA enforcement remains conservative.

The goal is not to prove exploitation. The goal is to show how RelayX records
evidence, uncertainty, OPSEC gates, route metadata, remediation controls,
enterprise output, and controlled execution audit records.

## Files

| File | Purpose |
| --- | --- |
| `examples/tutorial/targets.txt` | Example target list for adapting to a live lab. |
| `examples/tutorial/scope.txt` | Example scope policy covering tutorial hosts and CIDRs. |
| `examples/tutorial/sources.json` | Source capability and route/pivot metadata. |
| `examples/tutorial/baseline-result.json` | Smaller baseline result for diff examples. |
| `examples/tutorial/sample-result.json` | Full offline result used throughout the tutorial. |

The sample result is a first-class RelayX result file. You can use it anywhere
that accepts `--result` or a positional result argument.

## Preflight

From the repository root:

```bash
relayx -V
relayx -q help workflows
relayx -q help getting-started
relayx discover epa
relayx -q quality-gate -C .
```

When you know the task but not the exact command, use discovery:

```bash
relayx discover epa
relayx discover jsonl
relayx discover route --group Route/Pivot
```

Once you have a result file, `next` gives concrete follow-up commands:

```bash
relayx next --result examples/tutorial/sample-result.json
relayx next --result examples/tutorial/sample-result.json --path-id PX-0001
```

Optional shell completion can make longer RelayX commands easier to use during
runbook development:

```bash
relayx completion zsh > /tmp/relayx.zsh
relayx completion bash > /tmp/relayx.bash
relayx completion fish > /tmp/relayx.fish
```

Validate the tutorial fixtures:

```bash
relayx -q schema validate -k result examples/tutorial/sample-result.json
relayx -q schema validate -k result examples/tutorial/baseline-result.json
```

The expected validation result is `valid: true` with zero errors.

You can also use `relayx console`, the local operator console, for repeated
work on the same result. The console remembers selected result, path, OPSEC
policy, and scope, then calls the same guarded CLI handlers used by scripted
workflows.

```bash
relayx -q console --result examples/tutorial/sample-result.json --path-id PX-0001 --opsec-policy strict
relayx --no-color -q console --result examples/tutorial/sample-result.json
relayx -q console --history-file ~/.relayx/history
relayx -q console --no-history --no-completion
```

Example console commands:

```text
context
menu
next
discover jsonl
show summary
show paths
explain
clear
history
validate --mode dry-run
run --mode dry-run
exit
```

In an interactive terminal, RelayX uses readline for line editing, Up/Down
history navigation, Tab completion, and Ctrl-L clear-screen behavior when the
terminal backend supports it. Use `clear` or `cls` when you want an explicit
console command. Use `--no-history`, `RELAYX_NO_HISTORY=1`, or a leading space
before a command when the command should not be persisted.

## 1. Inspect The Result

Start with a compact summary:

```bash
relayx -q summary examples/tutorial/sample-result.json
```

Then review source assets and modeled capabilities:

```bash
relayx -q sources examples/tutorial/sample-result.json
```

Important interpretation:

- Source capability metadata is modeling input, not proof that RelayX executed
  a source trigger.
- Route metadata is modeling input, not proof that RelayX opened or operated a
  pivot session.
- `active=false` in result metadata means the tutorial result is an offline
  artifact.

## 2. Review Readiness And Paths

Show the readiness matrix:

```bash
relayx -q matrix examples/tutorial/sample-result.json
```

List candidate and blocked paths:

```bash
relayx -q paths examples/tutorial/sample-result.json -b
```

The path IDs are stable tutorial anchors:

| Path | Meaning | Initial interpretation |
| --- | --- | --- |
| `PX-0001` | WebClient-capable source to AD CS Web Enrollment over HTTP NTLM | High-impact candidate; EPA state remains unproven. |
| `PX-0002` | Source to SMB service with signing not required | Candidate path with direct hardening control. |
| `PX-0003` | Source to LDAP/389 with NTLM negotiation evidence | Candidate, but LDAP signing policy remains conservative. |
| `PX-0004` | SQL-adjacent source to MSSQL SSPI with TLS CBT evidence | Candidate; MSSQL EPA enforcement remains conservative. |
| `PX-0005` | Source to LDAPS/636 | Blocked by modeled route awareness. |

Explain a single path:

```bash
relayx -q explain examples/tutorial/sample-result.json PX-0001
```

The explanation should include observed evidence, blockers, fixes, and OPSEC
notes. For `PX-0001`, RelayX intentionally keeps EPA state conservative because
a synthetic authentication rejection is not enough to prove whether EPA is off,
accepted, or required.

Audit the result evidence contract:

```bash
relayx -q evidence-report -r examples/tutorial/sample-result.json -f json -o /tmp/relayx-evidence-report.json
relayx -q schema validate -k evidence-report /tmp/relayx-evidence-report.json
```

The evidence report is offline. It highlights records that lack evidence,
protocol judgement fields, remaining uncertainty, confidence assignments, or
clear source taxonomy before the result is used for lab promotion or
enterprise handoff.

## 3. Review Route And Pivot Awareness

Generate a route report:

```bash
relayx -q routes -r examples/tutorial/sample-result.json -f json -o /tmp/relayx-routes.json
relayx -q schema validate -k route-report /tmp/relayx-routes.json
```

Route and pivot awareness is model-driven. RelayX uses source metadata such as
`session`, `segment`, `subnets`, and structured `route_hops` to explain likely
reachability, route constraints, and route risk.

In an authorized lab or assessment window, you can add a direct TCP observation
without opening a pivot session:

```bash
relayx -q routes \
  -r examples/tutorial/sample-result.json \
  -P ldap \
  --connect-check \
  --rate-limit 60 \
  -f json \
  -o /tmp/relayx-routes-checked.json
```

Treat `reachability_check` as operator-runtime direct TCP context. It is useful
for route-profile review, but it is not proof that a session-backed pivot is
currently available.

Interpret route fields carefully:

- `route_reachable=true` means the modeled source metadata supports a route to
  the target.
- `route_reachability_state=routed` means the route came from structured route
  metadata instead of an unconstrained label.
- `route_risk_level=high` or a high route risk score should raise OPSEC review
  priority before validation or execution.
- `route_reachable=false` means the path should remain blocked unless a scoped
  route profile or an authorized route check changes the evidence.

## 4. Understand Calculus And Controls

RelayX annotates paths with rule, control, and remediation metadata:

```bash
relayx -q calculus examples/tutorial/sample-result.json
relayx -q controls examples/tutorial/sample-result.json
relayx -q fixes examples/tutorial/sample-result.json
```

Export an OPSEC-aware plan for the highest-priority path:

```bash
relayx -q plan examples/tutorial/sample-result.json PX-0001 -f json -o /tmp/relayx-px0001-plan.json
```

The plan is a dry-run planning artifact. It should explain preconditions,
hardening gates, expected telemetry, rollback ideas, and why the path should
or should not move toward validation.

Simulate remediation impact:

```bash
relayx -q simulate-fixes examples/tutorial/sample-result.json -c smb_signing -c http_epa -f json -o /tmp/relayx-simulation.json
```

Control simulation is read-only. It estimates how many modeled paths and how
much path score would be reduced if selected controls were implemented. JSON
output includes control dependencies, remaining controls, remaining target
families, and estimated residual exposure. It does not mutate the result file
and does not assert that the environment has actually been hardened.

## 5. Apply Lab Calibration

Run the bundled calibration profiles against the tutorial result:

```bash
relayx -q calibrate examples/tutorial/sample-result.json -p fixtures/lab_profiles -f json -o /tmp/relayx-calibration.json
```

Compare a baseline and a richer sample:

```bash
relayx -q compare-baseline \
  -b examples/tutorial/baseline-result.json \
  -c examples/tutorial/sample-result.json \
  -p fixtures/lab_profiles \
  -f json \
  -o /tmp/relayx-baseline-compare.json
```

Review the bundled lab corpus stability contract:

```bash
relayx -q lab-provenance -c fixtures/lab_corpus -f json -o /tmp/relayx-lab-provenance.json
relayx -q schema validate -k lab-provenance /tmp/relayx-lab-provenance.json
relayx -q lab-stability -c fixtures/lab_corpus -m 2 -f json -o /tmp/relayx-lab-stability.json
relayx -q schema validate -k lab-stability /tmp/relayx-lab-stability.json
relayx -q lab-diff -c fixtures/lab_corpus -m 2 -f json -o /tmp/relayx-lab-diff.json
relayx -q schema validate -k lab-differential /tmp/relayx-lab-diff.json
```

Calibration is how RelayX moves from conservative inference toward stronger
judgement. A finding can be promoted only when provenance, review, stability,
and a profile or baseline difference support that conclusion. If no
discriminator matches, or if a corpus is synthetic or unreviewed, RelayX should
say why the finding cannot be promoted and what uncertainty remains.

Important examples:

- HTTP/AD CS synthetic rejection is useful evidence, but it does not prove EPA
  enforcement by itself.
- LDAPS CBT evidence proves RelayX computed CBT material from TLS, but it does
  not prove that the domain controller enforces channel binding.
- MSSQL TDS-wrapped TLS and Login7 SSPI Type2 evidence prove challenge-flow
  and CBT material, but they do not prove EPA state without calibration.

## 6. Plan Guarded Validation

Dry-run validation is safe for tutorial use:

```bash
relayx -q validate \
  -r examples/tutorial/sample-result.json \
  -p PX-0001 \
  -m dry-run \
  -f json \
  -o /tmp/relayx-validation-dry-run.json
```

Dry-run validation does not perform active target reprobes. It records what
would be required for a guarded validation decision.

Confirmed validation is intentionally stricter:

```bash
relayx validate \
  -r result.json \
  -p PX-0001 \
  -m confirmed \
  -y \
  -O redpen \
  -R "authorized target reprobe" \
  -A audit.jsonl \
  --reprobe \
  --stop-before 2030-01-01T18:00:00+08:00
```

Use confirmed validation only in an authorized lab or assessment window. If you
also enable `--auth-validation`, RelayX may create failed-logon telemetry
because it sends synthetic NTLM Authenticate messages with placeholder
credentials. Confirmed reprobes fail closed outside the configured operation
window; dry-run validation records the same window as a warning.

## 7. Record Controlled Execution Decisions

The built-in supported adapter is an offline audit-record adapter. It records a
controlled execution decision without relaying credentials or triggering a
source-side coercion path:

```bash
relayx -q run \
  -r examples/tutorial/sample-result.json \
  -p PX-0001 \
  -M relayx_audit_record \
  -m confirmed \
  -y \
  -O redpen \
  -R "authorized offline tutorial audit" \
  -A /tmp/relayx-audit.jsonl \
  -S examples/tutorial/scope.txt \
  -f json \
  -o /tmp/relayx-execution-record.json
```

Validate the execution record:

```bash
relayx -q schema validate -k execution-record /tmp/relayx-execution-record.json
```

This is the safest way to test the execution state machine in training or CI.
Confirmed execution requires explicit scope in addition to operator identity,
reason, confirmation, and an audit log. Live relay adapters remain outside the
default enabled boundary unless they pass explicit protocol, credential-handling,
listener, OPSEC, and lab regression reviews. Lab-only module fixtures may be
used for contract review, but they are not registered live execution modules.

## 8. Produce Enterprise Outputs

Export graph, SIEM, and spreadsheet artifacts:

```bash
relayx -q export -r examples/tutorial/sample-result.json -f opengraph -o /tmp/relayx-opengraph.json
relayx -q export -r examples/tutorial/sample-result.json -f jsonl -o /tmp/relayx-events.jsonl
relayx -q export -r examples/tutorial/sample-result.json -f csv -o /tmp/relayx.csv
```

OpenGraph exports include RelayX node/edge mappings, deterministic edge IDs,
path-to-control edges, and control nodes. JSONL and CSV exports include stable
field contract versions so downstream pipelines can depend on a predictable
shape. HTML bundle reports include offline filters for status, severity,
protocol, source capability, target family, defensive control, and free text.

Validate the artifacts:

```bash
relayx -q schema validate -k opengraph /tmp/relayx-opengraph.json
relayx -q schema validate -k jsonl /tmp/relayx-events.jsonl
relayx -q schema validate -k csv /tmp/relayx.csv
```

Build a full handoff bundle:

```bash
relayx -q bundle \
  -r examples/tutorial/sample-result.json \
  -d /tmp/relayx-tutorial-bundle \
  -F opengraph,jsonl,csv,html,markdown,mermaid \
  -f json \
  -o /tmp/relayx-tutorial-bundle-summary.json

relayx -q schema validate -k bundle-manifest /tmp/relayx-tutorial-bundle/manifest.json
```

The bundle manifest records artifact paths, formats, schema kinds, validation
status, byte counts, and SHA256 hashes. It is the recommended handoff package
for teams that want the same evidence set available to operators, defenders,
report writers, and automation.

## 9. Compare Scans

Compare the baseline result against the full sample:

```bash
relayx -q diff \
  examples/tutorial/baseline-result.json \
  examples/tutorial/sample-result.json \
  -f json \
  -o /tmp/relayx-tutorial-diff.json
```

The expected diff should show added paths for AD CS, MSSQL, and LDAPS examples.
JSON diff output also includes exposure trend, score delta, control trends,
remediation regressions, and remediation improvements. Use this workflow for
recurring assessments, lab calibration changes, and remediation regression
reviews.

## 10. Adapt To An Authorized Lab

When you move from the offline tutorial to a real lab:

1. Replace `examples/tutorial/targets.txt` with authorized lab hosts.
2. Replace `examples/tutorial/scope.txt` with explicit host, CIDR, source,
   listener, and callback boundaries.
3. Replace `examples/tutorial/sources.json` with real authorized source
   metadata. Include `route_hops` when pivot context matters.
4. Run a readiness scan and save the result:

   ```bash
   relayx scan \
     -t lab-targets.txt \
     -s lab-sources.json \
     -S lab-scope.txt \
     -o lab-result.json
   ```

5. Review `summary`, `paths`, `routes`, `calculus`, `controls`, `plan`, and
   `validate --mode dry-run` before any confirmed action.
6. Use `--auth-validation` only when failed-logon telemetry is authorized and
   monitored.
7. Keep audit logs, route reports, calibration outputs, and enterprise bundles
   with the engagement evidence set.

## Interpretation Checklist

Before moving any path from analysis to validation, answer these questions:

- What did RelayX observe directly?
- What did RelayX infer from those observations?
- Which evidence keys explain the inference?
- Does `relayx evidence-report` show failures or unresolved warnings?
- Which blockers still apply?
- Which defensive controls would reduce or remove the path?
- Which source capabilities and route assumptions are modeled rather than
  live-tested?
- What telemetry is expected if validation becomes confirmed?
- Which OPSEC policy gates must pass?
- What remains uncertain after calibration?

RelayX is strongest when the answer to each question is visible in the result,
the plan, the validation record, or the enterprise bundle.
