import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from relayx.cli import main
from relayx.engine.path import build_paths
from relayx.engine.scope import load_scope
from relayx.engine.source import source_capabilities
from relayx.io import load_sources, read_result
from relayx.models import (
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Impact,
    NoiseLevel,
    ScanResult,
    SourceAsset,
    Status,
    scan_result_from_plain,
    to_plain,
)


class SourceModelTests(unittest.TestCase):
    def test_load_sources_csv_with_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sources.csv"
            path.write_text(
                "host,webdav,spooler,routes,tags,noise_limit,notes\n"
                "ws01,true,false,ligolo:ws,workstation,medium,asset inventory\n",
                encoding="utf-8",
            )
            sources = load_sources(str(path))

        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0].host, "ws01")
        self.assertTrue(sources[0].capabilities["webclient"])
        self.assertEqual(sources[0].noise_limit, NoiseLevel.MEDIUM)
        self.assertEqual(sources[0].routes, ["ligolo:ws"])

    def test_load_sources_json_enables_name_resolution_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sources.json"
            path.write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "host": "dc01",
                                "adidns": True,
                                "ghost_spn": True,
                                "tags": ["dc"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            sources = load_sources(str(path))

        caps = [cap.key for cap in source_capabilities(sources[0])]
        self.assertEqual(caps, ["name_resolution"])

    def test_scope_policy_supports_exact_hosts_and_cidr(self):
        scope = load_scope("ws01,10.10.0.0/16")
        self.assertIsNotNone(scope)
        self.assertTrue(scope.contains("ws01"))
        self.assertTrue(scope.contains("10.10.2.5"))
        self.assertFalse(scope.contains("10.11.2.5"))

    def test_build_paths_expands_concrete_source_to_target(self):
        finding = _http_candidate()
        source = SourceAsset(
            host="ws01",
            capabilities={"webclient": True},
            routes=["ligolo:ws"],
            noise_limit=NoiseLevel.MEDIUM,
        )

        paths = build_paths([finding], sources=[source], max_noise=NoiseLevel.MEDIUM)

        self.assertEqual(len(paths), 1)
        path = paths[0]
        evidence = {item.key: item for item in path.evidence}
        self.assertEqual(path.source, "ws01")
        self.assertEqual(evidence["source_capability"].value, "webclient")
        self.assertEqual(evidence["source_noise_level"].value, "medium")
        self.assertIn("HTTP/WebDAV", path.transport)
        self.assertGreater(path.score, 0)

    def test_max_noise_filters_high_noise_capabilities(self):
        finding = _ldap_candidate()
        source = SourceAsset(
            host="srv01",
            capabilities={"webclient": True, "spooler": True},
            noise_limit=NoiseLevel.HIGH,
        )

        paths = build_paths([finding], sources=[source], max_noise=NoiseLevel.MEDIUM)

        self.assertEqual(len(paths), 1)
        evidence = {item.key: item for item in paths[0].evidence}
        self.assertEqual(evidence["source_capability"].value, "webclient")

    def test_scope_filters_source_to_target_paths(self):
        finding = _ldap_candidate(host="10.20.0.10")
        source = SourceAsset(host="outside", capabilities={"webclient": True})
        scope = load_scope("10.20.0.0/24")

        paths = build_paths([finding], sources=[source], scope=scope)

        self.assertEqual(paths, [])

    def test_scan_result_round_trips_sources(self):
        result = ScanResult.new(target_count=1, source_count=1)
        result.sources = [SourceAsset(host="ws01", capabilities={"webclient": True})]
        plain = to_plain(result)
        restored = scan_result_from_plain(plain)

        self.assertEqual(restored.metadata.source_count, 1)
        self.assertEqual(restored.sources[0].host, "ws01")
        self.assertTrue(restored.sources[0].capabilities["webclient"])

    def test_cli_scan_wires_sources_into_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = root / "targets.txt"
            sources = root / "sources.csv"
            output = root / "result.json"
            targets.write_text("ca01\n", encoding="utf-8")
            sources.write_text(
                "host,webclient,noise_limit,routes\nws01,true,medium,ligolo:ws\n",
                encoding="utf-8",
            )
            with patch("relayx.cli.assess_targets", return_value=[_http_candidate(host="ca01")]):
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = main(
                        [
                            "scan",
                            "--targets",
                            str(targets),
                            "--sources",
                            str(sources),
                            "--max-noise",
                            "medium",
                            "--out",
                            str(output),
                        ]
                    )

            result = read_result(str(output))

        self.assertEqual(rc, 0)
        self.assertEqual(result.metadata.source_count, 1)
        self.assertEqual(result.paths[0].source, "ws01")
        self.assertEqual(result.paths[0].target, "ca01")

    def test_cli_strict_scope_blocks_out_of_scope_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = root / "targets.txt"
            sources = root / "sources.csv"
            scope = root / "scope.txt"
            output = root / "result.json"
            targets.write_text("ca01\n", encoding="utf-8")
            sources.write_text("host,webclient\nws01,true\n", encoding="utf-8")
            scope.write_text("ca01\n", encoding="utf-8")
            with patch("relayx.cli.assess_targets", return_value=[_http_candidate(host="ca01")]):
                with contextlib.redirect_stderr(io.StringIO()):
                    rc = main(
                        [
                            "scan",
                            "--targets",
                            str(targets),
                            "--sources",
                            str(sources),
                            "--scope",
                            str(scope),
                            "--strict-scope",
                            "--out",
                            str(output),
                        ]
                    )

        self.assertEqual(rc, 2)


def _http_candidate(host: str = "ca01") -> Finding:
    return Finding(
        host=host,
        port=80,
        protocol="http",
        name="adcs_web_enrollment",
        status=Status.CANDIDATE,
        confidence=Confidence.HIGH,
        impact=Impact.HIGH,
        summary="HTTP endpoint advertises NTLM.",
        evidence=[Evidence(EvidenceType.OBSERVED, "ntlm_type2_challenge", True, Confidence.HIGH)],
        fixes=["Enable EPA on AD CS Web Enrollment."],
    )


def _ldap_candidate(host: str = "dc01") -> Finding:
    return Finding(
        host=host,
        port=389,
        protocol="ldap",
        name="ldap_signing",
        status=Status.CANDIDATE,
        confidence=Confidence.MEDIUM,
        impact=Impact.MEDIUM,
        summary="LDAP SASL NTLM Type2 challenge was observed.",
        evidence=[Evidence(EvidenceType.OBSERVED, "ldap_sasl_ntlm_type2_challenge", True, Confidence.HIGH)],
        fixes=["Require LDAP signing."],
    )


if __name__ == "__main__":
    unittest.main()
