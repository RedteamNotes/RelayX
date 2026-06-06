# RelayX Tutorial Examples

This directory contains a complete offline example pack for the RelayX tutorial.
It is safe to use in documentation, training, and CI because it does not scan
the network, relay credentials, or execute source-side triggers.

## Files

- `targets.txt`: example target inventory.
- `scope.txt`: example scope boundary for hosts, source assets, and CIDRs.
- `sources.json`: source capability and route/pivot metadata.
- `baseline-result.json`: smaller baseline result for diff examples.
- `sample-result.json`: full RelayX result used by the tutorial.

## Quick Workflow

Validate the fixtures:

```bash
relayx -q schema validate -k result examples/tutorial/sample-result.json
relayx -q schema validate -k result examples/tutorial/baseline-result.json
```

Review the modeled exposure:

```bash
relayx -q summary examples/tutorial/sample-result.json
relayx -q paths examples/tutorial/sample-result.json -b
relayx -q explain examples/tutorial/sample-result.json PX-0001
relayx -q evidence-report -r examples/tutorial/sample-result.json -f json -o /tmp/relayx-evidence-report.json
```

Review routes, controls, and plans:

```bash
relayx -q routes -r examples/tutorial/sample-result.json -f json -o /tmp/relayx-routes.json
relayx -q controls examples/tutorial/sample-result.json
relayx -q plan examples/tutorial/sample-result.json PX-0001 -f json -o /tmp/relayx-plan.json
```

Run calibration and baseline comparison:

```bash
relayx -q calibrate examples/tutorial/sample-result.json -p fixtures/lab_profiles -f json -o /tmp/relayx-calibration.json
relayx -q compare-baseline -b examples/tutorial/baseline-result.json -c examples/tutorial/sample-result.json -p fixtures/lab_profiles -f json -o /tmp/relayx-baseline-compare.json
relayx -q lab-provenance -c fixtures/lab_corpus -f json -o /tmp/relayx-lab-provenance.json
relayx -q lab-stability -c fixtures/lab_corpus -m 2 -f json -o /tmp/relayx-lab-stability.json
relayx -q lab-diff -c fixtures/lab_corpus -m 2 -f json -o /tmp/relayx-lab-diff.json
```

Exercise guarded validation and offline execution recording:

```bash
relayx -q validate -r examples/tutorial/sample-result.json -p PX-0001 -m dry-run -f json -o /tmp/relayx-validation.json
relayx -q run -r examples/tutorial/sample-result.json -p PX-0001 -M relayx_audit_record -m confirmed -y -O redpen -R "authorized offline tutorial audit" -A /tmp/relayx-audit.jsonl -f json -o /tmp/relayx-execution-record.json
```

Export enterprise artifacts:

```bash
relayx -q export -r examples/tutorial/sample-result.json -f jsonl -o /tmp/relayx-events.jsonl
relayx -q bundle -r examples/tutorial/sample-result.json -d /tmp/relayx-tutorial-bundle -F opengraph,jsonl,csv,html,markdown,mermaid -f json -o /tmp/relayx-bundle-summary.json
relayx -q diff examples/tutorial/baseline-result.json examples/tutorial/sample-result.json -f json -o /tmp/relayx-diff.json
relayx -q simulate-fixes examples/tutorial/sample-result.json -c smb_signing -c http_epa -f json -o /tmp/relayx-simulation.json
```

See `docs/TUTORIAL.md` for the full explanation and adaptation guidance.
