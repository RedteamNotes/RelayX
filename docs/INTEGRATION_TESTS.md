# Authorized Integration Test Expectations

RelayX integration tests are intended for systems you own or are explicitly
authorized to assess. They should run in isolated AD/IIS/AD CS/MSSQL lab
environments, preserve OPSEC controls, and produce reviewable lab corpus
artifacts before any conclusion is promoted.

## Scope And Authorization

Every integration run should record:

- authorization reference and operator identity
- target hosts, source hosts, listener and callback scope, and CIDR boundaries
- operation window, rate limit, delay, jitter, and maximum acceptable OPSEC noise
- expected telemetry and rollback steps before the run starts
- whether synthetic authentication validation is enabled

Confirmed validation should use `--confirm`, `--operator`, `--reason`,
`--scope`, `--audit-log`, `--rate-limit`, and `--stop-before`. Source-side
triggers and target-side validation remain separate activities.

## Active Directory

Active Directory domain controller labs should cover LDAP signing and LDAPS CBT
policy states:

- LDAP signing none
- LDAP signing required
- LDAPS CBT never
- LDAPS CBT when-supported with valid CBT
- LDAPS CBT always with malformed or missing CBT

Expected evidence includes RootDSE SASL mechanisms, NTLM Type2 challenge
metadata, bind result codes, diagnostic strings, TLS certificate metadata for
LDAPS, CBT hash availability, `relayx_response_classification`, policy
inference, remaining uncertainty, and an operator-reviewed expected
classification.

Rollback should return domain controller signing and channel binding policy to
the pre-test state and verify that no unintended policy change remains.

## IIS

IIS labs should cover HTTP/IIS EPA states:

- EPA off
- EPA accept with CBT available
- EPA required

Expected evidence includes HTTP status, WWW-Authenticate headers, NTLM Type2
challenge metadata, synthetic authentication rejection state when authorized,
TLS certificate metadata for HTTPS, CBT hash availability, response keywords,
`relayx_response_classification`, policy inference, remaining uncertainty, and
expected classification.

Rollback should restore IIS Extended Protection settings, provider order, TLS
binding configuration, and test site authentication settings.

## AD CS

AD CS Web Enrollment EPA labs should cover:

- AD CS Web Enrollment EPA off
- AD CS Web Enrollment EPA required

Expected evidence includes `/certsrv` endpoint identity, HTTP/IIS EPA evidence,
AD CS Web Enrollment target family, response classification, EPA/CBT wording
when present, and explicit uncertainty separating relay exposure from template
enrollment viability.

Rollback should restore IIS authentication and Extended Protection settings for
the AD CS Web Enrollment application. Template permissions and enrollment
policy changes should be tracked separately from RelayX endpoint validation.

## MSSQL

MSSQL encryption/EPA labs should cover:

- MSSQL ENCRYPT_OFF without authenticate validation
- MSSQL ENCRYPT_ON with TDS-wrapped TLS and CBT evidence
- MSSQL ENCRYPT_REQ with EPA-required diagnostics
- MSSQL ENCRYPT_NOT_SUP where TLS CBT evidence is unavailable

Expected evidence includes TDS prelogin encryption mode, TDS-wrapped TLS state,
server certificate metadata when present, CBT server-end-point hash state,
SSPI NTLM Type2 challenge-flow evidence, Login7 authenticate outcome when
authorized, SQL error tokens, `relayx_response_classification`, policy
inference, remaining uncertainty, and expected classification.

Rollback should restore SQL Server force encryption settings, endpoint
certificate bindings, service account policy, and audit settings.

## Expected Telemetry

Integration tests may create:

- LDAP bind failure telemetry
- IIS failed authentication logs
- AD CS Web Enrollment web logs
- SQL Server login failure or audit events
- RelayX JSONL audit logs
- endpoint TLS handshake records

Telemetry expectations should be recorded before confirmed actions. Unexpected
telemetry should block promotion until reviewed.

## Lab Corpus Requirements

Each integration run should produce or update a lab corpus with:

- endpoint build metadata
- drift baseline metadata
- repeated captures per standard matrix state
- deterministic `observed_signature` fields
- `expected.classification`, `expected.policy_state`, and
  `expected.calibrated_state`
- operator review status and promotion decision
- remaining uncertainty and promotion reason

Run these checks before using the corpus for calibration:

```bash
relayx lab-verify -c fixtures/lab_corpus
relayx lab-provenance -c fixtures/lab_corpus -f json
relayx lab-stability -c fixtures/lab_corpus -m 2 -f json
relayx lab-diff -c fixtures/lab_corpus -m 2 -f json
relayx quality-gate -C . -f json
```

`quality-gate` verifies that bundled lab fixtures remain deterministic and tied
to expected classifications. Real lab promotion still requires authorized
captures and operator review; synthetic fixtures are not promotion evidence.

## OPSEC And Rollback

Integration tests should prefer the lowest useful noise level, explicit scope,
short operation windows, and pre-planned rollback. Any future live adapter work
must separately pass protocol design review, credential handling review, OPSEC
review, and authorized lab regression before registration.
