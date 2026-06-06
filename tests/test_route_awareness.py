import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx.cli import main
from relayx.engine.path import build_paths
from relayx.engine.routes import assess_route, assess_route_matrix, normalize_route_hops
from relayx.engine.schema import validate_schema_object
from relayx.io import load_sources
from relayx.models import (
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Impact,
    NoiseLevel,
    SourceAsset,
    Status,
)


class RouteAwarenessTests(unittest.TestCase):
    def test_load_sources_json_accepts_structured_route_hops(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sources.json"
            path.write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "host": "ws01",
                                "session": "ligolo-ws01",
                                "segment": "workstations",
                                "subnets": ["10.10.0.0/16"],
                                "webclient": True,
                                "route_hops": [
                                    {
                                        "kind": "ligolo",
                                        "name": "agent-ws01",
                                        "networks": ["10.20.0.0/16"],
                                        "risk": "low",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            sources = load_sources(str(path))

        self.assertEqual(sources[0].session, "ligolo-ws01")
        self.assertEqual(sources[0].segment, "workstations")
        self.assertEqual(sources[0].subnets, ["10.10.0.0/16"])
        self.assertEqual(sources[0].route_hops[0]["kind"], "ligolo")

    def test_normalize_legacy_route_strings(self):
        source = SourceAsset(
            host="ws01",
            routes=["ligolo:agent@10.20.0.0/16", "kind=socks,name=listener"],
        )

        hops = normalize_route_hops(source)

        self.assertEqual(hops[0].kind, "ligolo")
        self.assertEqual(hops[0].name, "agent")
        self.assertEqual(hops[0].networks, ["10.20.0.0/16"])
        self.assertEqual(hops[1].kind, "socks")

    def test_cidr_route_match_is_high_confidence(self):
        source = SourceAsset(
            host="ws01",
            subnets=["10.10.0.0/16"],
            route_hops=[
                {
                    "kind": "ligolo",
                    "name": "agent-ws01",
                    "networks": ["10.20.0.0/16"],
                    "risk": "low",
                }
            ],
        )

        assessment = assess_route(source, "10.20.5.10", target_protocol="ldap")

        self.assertTrue(assessment.reachable)
        self.assertEqual(assessment.state, "routed")
        self.assertEqual(assessment.confidence, Confidence.HIGH)
        self.assertEqual(assessment.pivot_types, ["direct", "ligolo"])
        self.assertEqual(assessment.noise, NoiseLevel.LOW)

    def test_metadata_only_route_stays_reachable_but_low_confidence(self):
        source = SourceAsset(host="ws01", routes=["ligolo:ws01"])

        assessment = assess_route(source, "ca01.redteamnotes.com")

        self.assertTrue(assessment.reachable)
        self.assertEqual(assessment.state, "metadata_only")
        self.assertEqual(assessment.confidence, Confidence.LOW)
        self.assertIn("unconstrained", assessment.limitations[0])

    def test_structured_route_miss_blocks_source_path(self):
        finding = _ldap_candidate(host="10.30.1.10")
        source = SourceAsset(
            host="ws01",
            capabilities={"webclient": True},
            route_hops=[{"kind": "ligolo", "networks": ["10.20.0.0/16"]}],
        )

        paths = build_paths([finding], sources=[source])

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].status, Status.BLOCKED)
        evidence = {item.key: item for item in paths[0].evidence}
        self.assertFalse(evidence["route_reachable"].value)
        self.assertEqual(evidence["route_reachability_state"].value, "unreachable")

    def test_route_risk_penalty_changes_ranking(self):
        finding = _http_candidate(host="10.20.1.50")
        low_risk = SourceAsset(
            host="direct-ws",
            capabilities={"webclient": True},
            subnets=["10.20.0.0/16"],
            noise_limit=NoiseLevel.MEDIUM,
        )
        high_risk = SourceAsset(
            host="deep-pivot",
            capabilities={"webclient": True},
            route_hops=[
                {"kind": "ligolo", "networks": ["10.10.0.0/16"]},
                {"kind": "socks", "networks": ["10.20.0.0/16"], "requires_listener": True, "risk": "high"},
            ],
            noise_limit=NoiseLevel.MEDIUM,
        )

        paths = build_paths([finding], sources=[high_risk, low_risk], max_noise=NoiseLevel.MEDIUM)

        self.assertEqual(paths[0].source, "direct-ws")
        self.assertGreater(paths[0].score, paths[1].score)

    def test_assess_route_matrix_shape(self):
        source = SourceAsset(host="ws01", subnets=["10.20.0.0/16"])

        report = assess_route_matrix([source], ["10.20.1.10"], target_protocol="http")

        self.assertEqual(report["name"], "RelayX route awareness")
        self.assertEqual(report["routes"][0]["state"], "direct")
        self.assertTrue(report["routes"][0]["reachable"])
        self.assertTrue(validate_schema_object(report, "route-report").valid)

    def test_cli_routes_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = root / "sources.json"
            targets = root / "targets.txt"
            output = root / "routes.json"
            sources.write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "host": "ws01",
                                "webclient": True,
                                "route_hops": [{"kind": "ligolo", "networks": ["10.20.0.0/16"]}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            targets.write_text("10.20.2.5\n", encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "routes",
                        "--sources",
                        str(sources),
                        "--targets",
                        str(targets),
                        "--target-protocol",
                        "ldap",
                        "--format",
                        "json",
                        "--out",
                        str(output),
                    ]
                )
            data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(data["routes"][0]["state"], "routed")
        self.assertEqual(data["routes"][0]["target_protocol"], "ldap")


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
