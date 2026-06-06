import unittest

from relayx.engine.path import build_paths, remediation_counts
from relayx.models import Confidence, Evidence, EvidenceType, Finding, Impact, Status


class RelayXPathTests(unittest.TestCase):
    def test_smb_unsigned_builds_candidate_path(self):
        finding = Finding(
            host="filesrv01",
            port=445,
            protocol="smb",
            name="smb_signing",
            status=Status.RELAYABLE,
            confidence=Confidence.HIGH,
            impact=Impact.MEDIUM,
            summary="SMB signing is not required.",
            evidence=[
                Evidence(EvidenceType.OBSERVED, "smb_signing_required", False, Confidence.HIGH)
            ],
            fixes=["Require SMB signing on this server."],
        )
        paths = build_paths([finding])
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].target, "filesrv01")
        self.assertEqual(paths[0].status, Status.CANDIDATE)
        self.assertGreater(paths[0].score, 0)

    def test_remediation_counts(self):
        finding = Finding(
            host="ca01",
            port=80,
            protocol="http",
            name="adcs_web_enrollment",
            status=Status.CANDIDATE,
            confidence=Confidence.MEDIUM,
            impact=Impact.HIGH,
            summary="HTTP endpoint advertises NTLM.",
            fixes=["Enable Extended Protection for Authentication on AD CS Web Enrollment."],
        )
        paths = build_paths([finding])
        fixes = remediation_counts(paths)
        self.assertEqual(fixes[0][0], "Enable Extended Protection for Authentication on AD CS Web Enrollment.")

    def test_ldap_candidate_status_is_preserved(self):
        finding = Finding(
            host="dc01",
            port=636,
            protocol="ldaps",
            name="ldaps_channel_binding",
            status=Status.CANDIDATE,
            confidence=Confidence.MEDIUM,
            impact=Impact.MEDIUM,
            summary="LDAPS SASL NTLM Type2 challenge was observed.",
        )
        paths = build_paths([finding])
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].status, Status.CANDIDATE)
        self.assertGreater(paths[0].score, 0)

    def test_mssql_candidate_status_is_preserved(self):
        finding = Finding(
            host="sql01",
            port=1433,
            protocol="mssql",
            name="mssql_ntlm_epa",
            status=Status.CANDIDATE,
            confidence=Confidence.HIGH,
            impact=Impact.MEDIUM,
            summary="MSSQL SSPI Type2 challenge was observed.",
        )
        paths = build_paths([finding])
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].status, Status.CANDIDATE)
        self.assertNotIn("relayx_future_oracle", {item.key for item in paths[0].evidence})


if __name__ == "__main__":
    unittest.main()
