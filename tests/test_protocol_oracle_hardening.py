import unittest
from unittest.mock import patch

from relayx.classifiers import (
    classify_http_auth_validation,
    classify_ldap_auth_validation,
    classify_mssql_auth_validation,
)
from relayx.ldap_proto import LDAPNTLMChallenge, LDAPRootDSE
from relayx.mssql_tds import MSSQLSSPIChallenge
from relayx.oracles import ldap, mssql


class ProtocolOracleHardeningTests(unittest.TestCase):
    def test_http_rejection_without_cbt_gets_precise_subclassification(self):
        classification = classify_http_auth_validation(
            {"sent": True, "synthetic_credentials": True, "status_code": 401}
        )

        self.assertEqual(classification.state, "synthetic_auth_rejected")
        self.assertEqual(classification.subclassification, "invalid_credentials_no_binding_signal")
        self.assertEqual(classification.policy_inference, "auth_rejected_epa_not_proven")
        self.assertIn("status=401", classification.oracle_signature)

    def test_http_rejection_with_cbt_remains_conservative(self):
        classification = classify_http_auth_validation(
            {
                "sent": True,
                "synthetic_credentials": True,
                "status_code": 401,
                "cbt_mode": "tls-server-end-point",
                "cbt_hash": "aa" * 32,
            }
        )

        self.assertEqual(classification.state, "synthetic_auth_rejected")
        self.assertEqual(classification.subclassification, "invalid_credentials_with_cbt_no_epa_signal")
        self.assertEqual(classification.policy_inference, "auth_rejected_with_cbt_material_epa_not_proven")
        self.assertIn("cbt_hash_available", classification.observations)

    def test_http_epa_wording_gets_binding_signal(self):
        classification = classify_http_auth_validation(
            {
                "sent": True,
                "synthetic_credentials": True,
                "status_code": 401,
                "body_sample_hex": b"Extended Protection channel binding failure".hex(),
            }
        )

        self.assertEqual(classification.state, "possible_epa_cbt_enforcement")
        self.assertEqual(classification.subclassification, "epa_or_cbt_rejection_signal")
        self.assertEqual(classification.policy_inference, "epa_cbt_enforcement_possible")

    def test_ldap_cbt_diagnostic_has_stable_signature(self):
        classification = classify_ldap_auth_validation(
            {
                "sent": True,
                "synthetic_credentials": True,
                "result_code": 49,
                "diagnostic_message": "AcceptSecurityContext error, data 80090346",
            }
        )

        self.assertEqual(classification.state, "possible_cbt_enforcement")
        self.assertEqual(classification.subclassification, "cbt_binding_rejected")
        self.assertIn("80090346", classification.observations)
        self.assertIn("cbt_hint", classification.oracle_signature)

    def test_mssql_login_failure_signature_is_sanitized(self):
        classification = classify_mssql_auth_validation(
            {
                "sent": True,
                "synthetic_credentials": True,
                "cbt_mode": "tls-server-end-point",
                "cbt_hash": "bb" * 32,
                "errors": ["Login failed for user 'redpen'."],
                "infos": [],
                "loginack": False,
            },
            prelogin={"encryption_name": "ENCRYPT_ON", "encryption": 1},
            tls={"certificate_sha256": "cc" * 32},
        )

        self.assertEqual(classification.state, "synthetic_auth_rejected")
        self.assertEqual(classification.subclassification, "invalid_credentials_with_cbt_no_epa_signal")
        self.assertIn("login_failed", classification.oracle_signature)
        self.assertNotIn("redpen", classification.oracle_signature)
        self.assertIn("tds_prelogin_encryption=encrypt_on", classification.observations)

    def test_mssql_encrypt_not_supported_marks_cbt_unavailable(self):
        classification = classify_mssql_auth_validation(
            None,
            prelogin={"encryption_name": "ENCRYPT_NOT_SUP", "encryption": 2},
        )

        self.assertEqual(classification.state, "not_performed")
        self.assertEqual(classification.subclassification, "tls_or_cbt_unavailable")
        self.assertEqual(classification.policy_inference, "tls_channel_binding_unavailable")

    def test_ldap_oracle_emits_hardened_evidence_contract(self):
        root_dse = LDAPRootDSE(
            {
                "supportedSASLMechanisms": ["GSS-SPNEGO", "GSSAPI", "NTLM"],
                "dnsHostName": ["dc01.lab.local"],
            }
        )
        challenge = LDAPNTLMChallenge(
            result_code=14,
            diagnostic_message="",
            type2={"target_name": "LDAPLAB"},
            auth_validation={
                "sent": True,
                "synthetic_credentials": True,
                "result_code": 49,
                "diagnostic_message": "invalid credentials",
            },
        )
        with patch.object(ldap, "query_root_dse", return_value=(root_dse, None)), patch.object(
            ldap, "request_ntlm_challenge", return_value=(challenge, None)
        ):
            finding = ldap.assess("dc01.lab.local", port=389, auth_validation=True)

        evidence = {item.key: item for item in finding.evidence}
        self.assertEqual(evidence["relayx_response_classification"].value, "synthetic_auth_rejected")
        self.assertEqual(evidence["relayx_response_subclassification"].value, "invalid_credentials_no_binding_signal")
        self.assertEqual(evidence["relayx_policy_inference"].value, "auth_rejected_cbt_not_proven")
        self.assertTrue(evidence["relayx_oracle_signature"].value.startswith("ldap:"))
        self.assertIn("invalid_credentials", evidence["relayx_oracle_observations"].value)

    def test_mssql_oracle_emits_hardened_evidence_contract(self):
        challenge = MSSQLSSPIChallenge(
            prelogin={"encryption_name": "ENCRYPT_ON", "encryption": 1},
            tls={"certificate_sha256": "cc" * 32, "cbt_hash": "dd" * 32},
            type2={"target_name": "SQLLAB"},
            auth_validation={
                "sent": True,
                "synthetic_credentials": True,
                "cbt_mode": "tls-server-end-point",
                "cbt_hash": "dd" * 32,
                "errors": ["Login failed for user 'redpen'."],
                "infos": [],
                "loginack": False,
            },
        )
        with patch.object(mssql, "ntlm_sspi_challenge", return_value=challenge):
            finding = mssql.assess("sql01.lab.local", auth_validation=True)

        evidence = {item.key: item for item in finding.evidence}
        self.assertEqual(evidence["relayx_response_classification"].value, "synthetic_auth_rejected")
        self.assertEqual(evidence["relayx_response_subclassification"].value, "invalid_credentials_with_cbt_no_epa_signal")
        self.assertEqual(evidence["relayx_policy_inference"].value, "auth_rejected_with_cbt_material_epa_not_proven")
        self.assertNotIn("redpen", evidence["relayx_oracle_signature"].value)


if __name__ == "__main__":
    unittest.main()
