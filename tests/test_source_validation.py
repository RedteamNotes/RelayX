import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from relayx.cli import main
from relayx.engine.scope import load_scope
from relayx.engine.source_validation import (
    SourceCheckRequest,
    build_source_plan,
    check_sources,
    render_source_checks,
    render_source_plan,
)
from relayx.models import NoiseLevel, SourceAsset
from relayx.net import ConnectResult


class SourceValidationTests(unittest.TestCase):
    def test_source_check_models_capability_without_active_check(self):
        sources = [
            SourceAsset(
                host="ws01",
                capabilities={"webclient": True},
                noise_limit=NoiseLevel.MEDIUM,
                routes=["ligolo:ws01"],
            )
        ]
        report = check_sources(sources, SourceCheckRequest(max_noise=NoiseLevel.MEDIUM))

        check = report["checks"][0]
        self.assertEqual(check["capability"], "webclient")
        self.assertEqual(check["state"], "modeled")
        self.assertFalse(check["active_performed"])
        self.assertIn("does not execute", check["limitations"][0])

    def test_scope_marks_source_out_of_scope(self):
        sources = [SourceAsset(host="ws01", capabilities={"webclient": True})]
        report = check_sources(sources, SourceCheckRequest(scope=load_scope("other-host")))

        self.assertEqual(report["checks"][0]["state"], "out_of_scope")

    def test_noise_budget_filters_high_noise_capability(self):
        sources = [SourceAsset(host="srv01", capabilities={"spooler": True}, noise_limit=NoiseLevel.HIGH)]
        report = check_sources(sources, SourceCheckRequest(max_noise=NoiseLevel.MEDIUM))

        self.assertEqual(report["checks"][0]["state"], "no_capability")

    def test_connect_check_observes_rpc_tcp_surface_without_rpc_call(self):
        sources = [SourceAsset(host="srv01", capabilities={"spooler": True}, noise_limit=NoiseLevel.HIGH)]

        def fake_connect(_host, port, timeout=3.0):
            return ConnectResult(open=port == 445, error="" if port == 445 else "closed")

        with patch("relayx.engine.source_validation.tcp_connect", side_effect=fake_connect):
            report = check_sources(
                sources,
                SourceCheckRequest(connect_check=True, timeout=0.1),
            )

        check = report["checks"][0]
        self.assertEqual(check["state"], "network_surface_observed")
        self.assertTrue(check["active_performed"])
        self.assertTrue(any(row["port"] == 445 and row["open"] for row in check["evidence"][2]["value"]))
        self.assertIn("No RPC method call was made", check["reason"])

    def test_webclient_connect_check_remains_plan_only(self):
        sources = [SourceAsset(host="ws01", capabilities={"webclient": True}, noise_limit=NoiseLevel.MEDIUM)]
        report = check_sources(sources, SourceCheckRequest(connect_check=True))

        self.assertEqual(report["checks"][0]["state"], "plan_only")
        self.assertFalse(report["checks"][0]["active_performed"])

    def test_source_plan_for_name_resolution_contains_rollback_and_forbidden_actions(self):
        sources = [
            SourceAsset(
                host="dc01",
                capabilities={"name_resolution": True},
                noise_limit=NoiseLevel.MEDIUM,
                routes=["ligolo:dc"],
            )
        ]
        plan = build_source_plan(
            sources,
            "dc01",
            "name_resolution",
            SourceCheckRequest(max_noise=NoiseLevel.MEDIUM),
        )

        self.assertEqual(plan["state"], "planned")
        self.assertFalse(plan["execution"]["supported"])
        self.assertEqual(plan["route_context"]["pivot_types"], ["ligolo"])
        self.assertTrue(any("Remove any created DNS" in item for item in plan["rollback"]))
        self.assertTrue(any("Creating or modifying" in item for item in plan["forbidden_actions"]))

    def test_source_plan_errors_for_disabled_capability(self):
        sources = [SourceAsset(host="ws01", capabilities={"webclient": True})]
        plan = build_source_plan(sources, "ws01", "spooler")

        self.assertEqual(plan["state"], "error")
        self.assertEqual(plan["error"], "capability_not_enabled")

    def test_renderers_include_boundaries(self):
        sources = [
            SourceAsset(
                host="ws01",
                capabilities={"webclient": True},
                noise_limit=NoiseLevel.MEDIUM,
                routes=["ligolo:ws01"],
            )
        ]
        report = check_sources(sources, SourceCheckRequest(max_noise=NoiseLevel.MEDIUM))
        plan = build_source_plan(sources, "ws01", "webclient", SourceCheckRequest(max_noise=NoiseLevel.MEDIUM))

        self.assertIn("RelayX Source Checks", render_source_checks(report))
        rendered_plan = render_source_plan(plan)
        self.assertIn("Forbidden Actions", rendered_plan)
        self.assertIn("Route Context", rendered_plan)

    def test_cli_source_check_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = root / "sources.csv"
            out = root / "source-check.json"
            sources.write_text("host,webclient,noise_limit\nws01,true,medium\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "source-check",
                        "--sources",
                        str(sources),
                        "--max-noise",
                        "medium",
                        "--format",
                        "json",
                        "--out",
                        str(out),
                    ]
                )
            data = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(data["checks"][0]["capability"], "webclient")

    def test_cli_source_plan_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = root / "sources.csv"
            out = root / "source-plan.json"
            sources.write_text("host,webclient,noise_limit\nws01,true,medium\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "source-plan",
                        "--sources",
                        str(sources),
                        "--source",
                        "ws01",
                        "--capability",
                        "webclient",
                        "--max-noise",
                        "medium",
                        "--format",
                        "json",
                        "--out",
                        str(out),
                    ]
                )
            data = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(data["capability"], "webclient")
        self.assertFalse(data["execution"]["supported"])


if __name__ == "__main__":
    unittest.main()
