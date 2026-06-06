import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx.cli import main
from relayx.engine.schema import validate_schema_path


ROOT = Path(__file__).resolve().parents[1]
TUTORIAL = ROOT / "examples" / "tutorial"
SAMPLE_RESULT = TUTORIAL / "sample-result.json"
BASELINE_RESULT = TUTORIAL / "baseline-result.json"
SOURCES = TUTORIAL / "sources.json"


class TutorialExampleTests(unittest.TestCase):
    def test_tutorial_results_satisfy_result_schema(self):
        for path in (SAMPLE_RESULT, BASELINE_RESULT):
            with self.subTest(path=path.name):
                report = validate_schema_path(str(path), kind="result")
                self.assertTrue(report.valid, json.dumps(report.as_dict(), indent=2))

    def test_tutorial_sources_include_capabilities_and_routes(self):
        data = json.loads(SOURCES.read_text(encoding="utf-8"))
        rows = data["sources"]

        self.assertGreaterEqual(len(rows), 2)
        self.assertTrue(any(row.get("route_hops") for row in rows))
        self.assertTrue(
            any(
                isinstance(row.get("capabilities"), dict)
                and any(row["capabilities"].values())
                for row in rows
            )
        )

    def test_cli_tutorial_workflow_smoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes = root / "routes.json"
            validation = root / "validation.json"
            execution = root / "execution-record.json"
            audit_log = root / "audit.jsonl"
            opengraph = root / "opengraph.json"
            jsonl = root / "events.jsonl"
            csv = root / "relayx.csv"
            bundle = root / "bundle"
            bundle_summary = root / "bundle-summary.json"
            diff = root / "diff.json"
            simulation = root / "simulation.json"

            commands = [
                ["-q", "summary", str(SAMPLE_RESULT)],
                ["-q", "paths", str(SAMPLE_RESULT), "-b"],
                ["-q", "explain", str(SAMPLE_RESULT), "PX-0001"],
                ["-q", "routes", "-r", str(SAMPLE_RESULT), "-f", "json", "-o", str(routes)],
                [
                    "-q",
                    "validate",
                    "-r",
                    str(SAMPLE_RESULT),
                    "-p",
                    "PX-0001",
                    "-m",
                    "dry-run",
                    "-f",
                    "json",
                    "-o",
                    str(validation),
                ],
                [
                    "-q",
                    "run",
                    "-r",
                    str(SAMPLE_RESULT),
                    "-p",
                    "PX-0001",
                    "-M",
                    "relayx_audit_record",
                    "-m",
                    "confirmed",
                    "-y",
                    "-O",
                    "redpen",
                    "-R",
                    "authorized offline tutorial audit",
                    "-A",
                    str(audit_log),
                    "-S",
                    str(TUTORIAL / "scope.txt"),
                    "-f",
                    "json",
                    "-o",
                    str(execution),
                ],
                ["-q", "export", "-r", str(SAMPLE_RESULT), "-f", "opengraph", "-o", str(opengraph)],
                ["-q", "export", "-r", str(SAMPLE_RESULT), "-f", "jsonl", "-o", str(jsonl)],
                ["-q", "export", "-r", str(SAMPLE_RESULT), "-f", "csv", "-o", str(csv)],
                [
                    "-q",
                    "bundle",
                    "-r",
                    str(SAMPLE_RESULT),
                    "-d",
                    str(bundle),
                    "-F",
                    "opengraph,jsonl,csv,html,markdown,mermaid",
                    "-f",
                    "json",
                    "-o",
                    str(bundle_summary),
                ],
                [
                    "-q",
                    "diff",
                    str(BASELINE_RESULT),
                    str(SAMPLE_RESULT),
                    "-f",
                    "json",
                    "-o",
                    str(diff),
                ],
                [
                    "-q",
                    "simulate-fixes",
                    str(SAMPLE_RESULT),
                    "-c",
                    "smb_signing",
                    "-c",
                    "http_epa",
                    "-f",
                    "json",
                    "-o",
                    str(simulation),
                ],
            ]

            for command in commands:
                with self.subTest(command=" ".join(command)):
                    with contextlib.redirect_stdout(io.StringIO()):
                        rc = main(command)
                    self.assertEqual(rc, 0)

            self.assertTrue(validate_schema_path(str(routes), kind="route-report").valid)
            self.assertTrue(validate_schema_path(str(execution), kind="execution-record").valid)
            self.assertTrue(validate_schema_path(str(opengraph), kind="opengraph").valid)
            self.assertTrue(validate_schema_path(str(jsonl), kind="jsonl").valid)
            self.assertTrue(validate_schema_path(str(csv), kind="csv").valid)
            self.assertTrue(validate_schema_path(str(bundle / "manifest.json"), kind="bundle-manifest").valid)

            diff_data = json.loads(diff.read_text(encoding="utf-8"))
            validation_data = json.loads(validation.read_text(encoding="utf-8"))
            simulation_data = json.loads(simulation.read_text(encoding="utf-8"))

            self.assertGreaterEqual(diff_data["summary"]["added_paths"], 3)
            self.assertEqual(validation_data["result"]["state"], "dry_run")
            self.assertGreaterEqual(simulation_data["simulations"][0]["paths_reduced"], 1)


if __name__ == "__main__":
    unittest.main()
