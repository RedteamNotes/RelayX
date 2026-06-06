import unittest
from unittest.mock import patch

from relayx.ldap_proto import LDAPNTLMChallenge, LDAPRootDSE
from relayx.mssql_tds import MSSQLSSPIChallenge
from relayx.oracles import ldap, mssql


class OracleClassificationTests(unittest.TestCase):
    def test_ldap_oracle_attaches_response_classification(self):
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
        self.assertEqual(
            evidence["relayx_response_classification"].value,
            "synthetic_auth_rejected",
        )

    def test_mssql_oracle_attaches_response_classification(self):
        challenge = MSSQLSSPIChallenge(
            prelogin={"encryption_name": "ENCRYPT_ON", "encryption": 1},
            type2={"target_name": "SQLLAB"},
            auth_validation={
                "sent": True,
                "synthetic_credentials": True,
                "errors": ["Login failed for user 'redpen'."],
                "infos": [],
                "loginack": False,
            },
        )
        with patch.object(mssql, "ntlm_sspi_challenge", return_value=challenge):
            finding = mssql.assess("sql01.lab.local", auth_validation=True)

        evidence = {item.key: item for item in finding.evidence}
        self.assertEqual(
            evidence["relayx_response_classification"].value,
            "synthetic_auth_rejected",
        )


if __name__ == "__main__":
    unittest.main()
