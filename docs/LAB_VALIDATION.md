# RelayX Lab Validation

This document defines the minimum lab matrix for validating RelayX readiness
and authenticate-validation oracles. The goal is calibration: RelayX
must explain what it observed, what it inferred, and what it refuses to claim
without stronger evidence.

RelayX remains a readiness and validation tool by default. It does not coerce
sources or execute credential relay. `--auth-validation` sends synthetic NTLM
Authenticate messages with random placeholder credentials and can create failed
logon telemetry.

For a safe end-to-end walkthrough before building a real lab matrix, use the
offline tutorial in [`docs/TUTORIAL.md`](TUTORIAL.md) and the fixtures in
[`examples/tutorial`](../examples/tutorial).

## Evidence Contract

Every protocol oracle should produce stable evidence keys that can be used
by reports, ranking, and regression tests.

Use `relayx evidence-report -r result.json` before promoting lab evidence. The
report checks whether finding/path records carry evidence, protocol judgement
fields, source taxonomy, confidence, and remaining uncertainty in a consistent
structure.

| Oracle | Required evidence keys |
| --- | --- |
| SMB | `smb_signing_required`, `smb_security_mode` |
| HTTP/HTTPS | `http_status`, `www_authenticate`, `ntlm_type2_challenge`, `ntlm_authenticate_validation`, `relayx_response_classification`, `epa_status` |
| HTTPS | HTTP keys plus `tls_certificate_sha256` when a certificate is observed |
| LDAP | `ldap_reachable`, `rootdse_supported_sasl_mechanisms`, `ldap_sasl_ntlm_type2_challenge`, `ldap_ntlm_authenticate_validation`, `relayx_response_classification`, `ldap_bind_result_code` when a bind response is observed |
| LDAPS | `ldaps_reachable`, `rootdse_supported_sasl_mechanisms`, `ldap_sasl_ntlm_type2_challenge`, `ldap_ntlm_authenticate_validation`, `relayx_response_classification`, `ldap_bind_result_code` when a bind response is observed, plus `tls_certificate_sha256` when a certificate is observed |
| MSSQL | `tds_prelogin_encryption`, `tds_wrapped_tls`, `mssql_cbt_tls_server_end_point`, `mssql_sspi_ntlm_type2_challenge`, `mssql_ntlm_authenticate_validation`, `relayx_response_classification`, `tds_loginack_observed`, `tds_errors`, `mssql_epa_enforcement` |

The shared `relayx_response_classification` key is intentionally conservative.
Expected response states are:

- `not_performed`: synthetic Type3 validation was not requested.
- `synthetic_auth_rejected`: the server rejected random credentials in a
  normal-looking way. This is expected and is not proof of EPA/CBT enforcement.
- `possible_cbt_enforcement` or `possible_epa_cbt_enforcement`: response text
  contains channel-binding, Extended Protection, or `80090346`-style signals.
- `stronger_auth_or_confidentiality_required`: LDAP returned a stronger-auth
  result, which may be signing/confidentiality policy rather than CBT.
- `unexpected_acceptance`: a synthetic authenticate message appeared to be
  accepted. Treat as a high-priority lab anomaly.
- `inconclusive`: transport or response semantics were not sufficient.

## Lab Matrix

RelayX exposes the lab policy matrix and corpus coverage checks as offline
commands:

```bash
relayx lab-matrix
relayx lab-matrix --target-family mssql_epa --format json --out lab-matrix.json
relayx lab-verify --corpus fixtures/lab_corpus --format json --out lab-verify.json
relayx lab-provenance --corpus fixtures/lab_corpus --format json --out lab-provenance.json
relayx lab-stability --corpus fixtures/lab_corpus --min-captures 2 --format json --out lab-stability.json
relayx lab-diff --corpus fixtures/lab_corpus --target-family http_iis_epa --format json --out lab-diff.json
```

`lab-matrix` is the planning contract. `lab-verify` checks that a lab corpus
covers the required policy states and stable signature keys. Verification does
not promote findings by itself; promotion still requires reviewed calibration
profiles or a stable baseline difference.

`lab-provenance` is the evidence-admission contract. It checks whether each
corpus records synthetic versus non-synthetic origin, capture source, endpoint
build metadata, drift baseline metadata, and capture-level operator review.
Synthetic fixtures may pass structure checks, but RelayX keeps them out of real
promotion readiness. Non-synthetic `promotion=promote` or `promotion=block`
hints require endpoint build metadata, drift baseline metadata, and explicit
operator review before they can support profile promotion.

`lab-stability` is the repeat-capture quality contract. It groups captures by
target family and policy state, computes a dominant-signature
`consistency_score`, reports changed stable-signature fields as `drift_keys`,
and explains why a promotion hint can be preserved or must be downgraded to
`retain`. Its default `--min-captures 2` is intentionally stricter than fixture
coverage checks: one capture can prove that a matrix state exists, but repeated
captures are needed before RelayX should treat a lab signature as stable.

`lab-diff` is the response-difference contract. It compares stable dominant
signatures between policy states, separates response discriminator keys from
context-only fields, and reports whether a policy-state pair can support
calibration promotion. This is the offline corpus-level companion to
`compare-baseline`, which compares two RelayX result files.

| ID | Service | Lab policy state | RelayX command mode | Expected behavior |
| --- | --- | --- | --- | --- |
| SMB-01 | SMB server | Signing disabled or not required | default scan | `smb_signing_required=false`; finding relay-ready/candidate through path engine |
| SMB-02 | SMB server | Signing required | default scan | `smb_signing_required=true`; path blocked with remediation |
| LDAP-01 | Domain controller LDAP/389 | LDAP signing not required | default scan | rootDSE reachable; SASL NTLM Type2 may be observed; no signing proof without validation |
| LDAP-02 | Domain controller LDAP/389 | LDAP signing required | default scan and `--auth-validation` | rootDSE reachable; bind result may show stronger auth requirement; classify conservatively |
| LDAPS-01 | Domain controller LDAPS/636 | Channel binding never | `--auth-validation` | TLS cert hash and CBT hash available; random credentials rejected; do not claim CBT enforcement |
| LDAPS-02 | Domain controller LDAPS/636 | Channel binding when supported | `--auth-validation` | TLS cert hash and CBT hash available; compare result codes and diagnostics against LDAPS-01 |
| LDAPS-03 | Domain controller LDAPS/636 | Channel binding always | `--auth-validation` | classify CBT hints when diagnostics expose binding failure; otherwise retain caveat |
| HTTP-01 | IIS NTLM endpoint | EPA disabled | `--auth-validation` | Type2 observed; synthetic rejection; EPA remains unknown without lab baseline comparison |
| HTTP-02 | IIS NTLM endpoint | EPA accept | `--auth-validation` over HTTPS | TLS cert hash available; response classifier should remain conservative |
| HTTP-03 | IIS NTLM endpoint | EPA required | `--auth-validation` over HTTPS | CBT hash is sent when TLS is observed; classify explicit EPA/CBT wording if present |
| ADCS-01 | AD CS Web Enrollment | EPA disabled | `--auth-validation` | `adcs_web_enrollment` finding; high impact candidate; remediation recommends EPA or disabling endpoint |
| ADCS-02 | AD CS Web Enrollment | EPA required | `--auth-validation` over HTTPS | response classifier records EPA/CBT hints when exposed; path remains candidate unless confirmed by lab baseline |
| MSSQL-01 | SQL Server | `ENCRYPT_OFF`, EPA disabled | default scan | prelogin observed; SSPI Type2 may be observed; no TLS CBT evidence |
| MSSQL-02 | SQL Server | `ENCRYPT_ON`, EPA disabled | default scan | TDS-wrapped TLS should complete; certificate SHA256 and CBT hash evidence recorded |
| MSSQL-03 | SQL Server | `ENCRYPT_REQ`, EPA enabled/required | `--auth-validation` | Login7 Type2 observed; synthetic Type3 response classified; CBT evidence captured over TLS |
| MSSQL-04 | SQL Server | `ENCRYPT_NOT_SUP` | default scan | TLS CBT unavailable; finding explains skipped TLS evidence |

## Calibration Rules

RelayX should prefer under-claiming over false certainty.

1. A Type2 challenge proves that NTLM negotiation was possible for that
   protocol flow. It does not prove relay success.
2. A synthetic Type3 rejection proves that the server processed an
   Authenticate-stage message enough to return semantics. It does not prove
   whether valid relayed credentials would succeed.
3. CBT evidence means RelayX computed `tls-server-end-point` input from the
   observed TLS certificate. It does not prove policy enforcement.
4. EPA/CBT enforcement can be promoted only when lab baselines show a stable
   difference between policy states or when the server returns explicit
   binding-related diagnostics.
5. Path ranking should include candidates with caveats; execution must remain
   separate from readiness.

## Confidence Contract

Calibration decisions and baseline comparisons expose a versioned confidence
contract. The contract records the profile, matched state, signature ID,
present and missing discriminators, promotion gate, evidence sources, and
remaining uncertainty. This is intentionally stricter than a plain confidence
label: a `high` confidence decision must still explain what evidence supports
it and which interpretation boundary remains.

Lab provenance reports expose evidence model
`lab_corpus_provenance_review`. That contract records the boundary between
synthetic fixtures, operator-supplied captures, real lab captures, endpoint
build metadata, drift baselines, and operator-approved promotion decisions.

Lab stability reports expose a separate confidence contract with evidence model
`repeat_capture_stability`. That contract records the consistency rule,
promotion boundary, and auto-downgrade rule used when a corpus or generated
profile attempts to preserve `promotion=promote` or `promotion=block`.

Lab differential reports expose evidence model `lab_response_differential`.
They record stable changed keys, response discriminator keys, context-only
keys, promotion support, and remaining uncertainty for each policy-state pair.

Evidence reports expose evidence model `result_evidence_completeness`. They are
offline audits of an existing result and do not prove protocol correctness; they
make missing judgement fields and unknown-confidence evidence visible before a
lab profile or enterprise handoff relies on the result.

The evidence-report source taxonomy distinguishes observed wire evidence,
policy inference, lab calibration evidence, modeled source or route context,
control mappings, operator context, errors, and unsupported boundaries. Lab
promotion should be based on the appropriate source categories rather than a
single undifferentiated evidence count.

For baseline comparisons, promotion requires both:

1. A candidate signature that matches a promotable calibrated lab state.
2. A baseline/candidate differential signal on the calibrated discriminators.

If either condition is absent, RelayX retains the conservative state and
records why.

## Exit Criteria

- All protocol parsers and classifiers pass unit tests.
- `relayx scan` produces stable JSON with the evidence contract above.
- HTTP, LDAP/LDAPS, and MSSQL `--auth-validation` findings include
  `relayx_response_classification`.
- MSSQL records TDS-wrapped TLS and CBT evidence when SQL Server negotiates
  encryption.
- A real lab run is required before RelayX changes any `unknown` EPA/CBT
  inference into a stronger policy claim.
