import unittest

from relayx.classifiers import (
    classify_http_auth_validation,
    classify_ldap_auth_validation,
    classify_mssql_auth_validation,
)


class ResponseClassifierTests(unittest.TestCase):
    def test_http_401_is_synthetic_rejection(self):
        classification = classify_http_auth_validation(
            {"sent": True, "synthetic_credentials": True, "status_code": 401}
        )
        self.assertEqual(classification.state, "synthetic_auth_rejected")
        self.assertEqual(classification.confidence, "medium")

    def test_http_success_is_unexpected_acceptance(self):
        classification = classify_http_auth_validation(
            {"sent": True, "synthetic_credentials": True, "status_code": 200}
        )
        self.assertEqual(classification.state, "unexpected_acceptance")
        self.assertEqual(classification.confidence, "high")

    def test_ldap_invalid_credentials_is_synthetic_rejection(self):
        classification = classify_ldap_auth_validation(
            {"sent": True, "synthetic_credentials": True, "result_code": 49}
        )
        self.assertEqual(classification.state, "synthetic_auth_rejected")

    def test_ldap_cbt_diagnostic_is_possible_enforcement(self):
        classification = classify_ldap_auth_validation(
            {
                "sent": True,
                "synthetic_credentials": True,
                "result_code": 49,
                "diagnostic_message": "AcceptSecurityContext error, data 80090346",
            }
        )
        self.assertEqual(classification.state, "possible_cbt_enforcement")
        self.assertEqual(classification.epa_cbt, "possible_enforcement_signal")

    def test_mssql_login_failure_is_synthetic_rejection(self):
        classification = classify_mssql_auth_validation(
            {
                "sent": True,
                "synthetic_credentials": True,
                "errors": ["Login failed for user 'redpen'."],
                "infos": [],
                "loginack": False,
            }
        )
        self.assertEqual(classification.state, "synthetic_auth_rejected")

    def test_mssql_loginack_is_unexpected_acceptance(self):
        classification = classify_mssql_auth_validation(
            {
                "sent": True,
                "synthetic_credentials": True,
                "errors": [],
                "infos": [],
                "loginack": True,
            }
        )
        self.assertEqual(classification.state, "unexpected_acceptance")

    def test_missing_validation_is_not_performed(self):
        classification = classify_mssql_auth_validation(None)
        self.assertEqual(classification.state, "not_performed")
        self.assertEqual(classification.epa_cbt, "not_evaluated")

    def test_cbt_hint_does_not_match_unrelated_substrings(self):
        classification = classify_http_auth_validation(
            {
                "sent": True,
                "synthetic_credentials": True,
                "status_code": 401,
                "body_sample_hex": "Please use a separate account".encode("utf-8").hex(),
            }
        )
        self.assertEqual(classification.state, "synthetic_auth_rejected")


if __name__ == "__main__":
    unittest.main()
