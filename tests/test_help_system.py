import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import relayx.cli as cli_module
from relayx.cli import (
    ConsoleContext,
    _console_completion_candidates,
    _console_history_recordable,
    _console_prompt,
    _format_console_history,
    _get_command_specs,
    _handle_console_line,
    _record_console_history,
    build_parser,
    main,
    render_completion,
)
from relayx import __version__


class HelpSystemTests(unittest.TestCase):
    def test_top_level_help_mentions_curated_help(self):
        help_text = build_parser().format_help()

        self.assertIn("Operator workflows", help_text)
        self.assertIn("relayx help getting-started", help_text)
        self.assertIn("relayx discover epa", help_text)
        self.assertIn("relayx next --result result.json", help_text)
        self.assertIn("relayx help short-options", help_text)
        self.assertIn("relayx console --result result.json", help_text)
        self.assertIn("Common starts", help_text)
        self.assertIn("-V, --version", help_text)
        self.assertIn("--no-color", help_text)

    def test_help_overview_text(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["help"])

        self.assertEqual(rc, 0)
        self.assertIn(f"RelayX {__version__}", stdout.getvalue())
        self.assertIn("RelayX Help", stdout.getvalue())
        self.assertIn("Common workflows", stdout.getvalue())
        self.assertIn("relayx discover epa", stdout.getvalue())
        self.assertIn("relayx next --result result.json", stdout.getvalue())

    def test_no_banner_suppresses_human_banner(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["help", "--no-banner"])

        self.assertEqual(rc, 0)
        self.assertNotIn(f"RelayX {__version__}", stdout.getvalue())
        self.assertIn("RelayX Help", stdout.getvalue())

    def test_help_command_text(self):
        stdout = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=False), contextlib.redirect_stdout(stdout):
            os.environ.pop("NO_COLOR", None)
            rc = main(["help", "scan"])

        self.assertEqual(rc, 0)
        self.assertIn("\x1b[", stdout.getvalue())
        self.assertIn("relayx scan", stdout.getvalue())
        self.assertIn("What it does", stdout.getvalue())
        self.assertIn("When to use", stdout.getvalue())
        self.assertIn("Required inputs", stdout.getvalue())
        self.assertIn("Common mistakes", stdout.getvalue())
        self.assertIn("Examples", stdout.getvalue())
        self.assertIn("auth-validation", stdout.getvalue())

    def test_no_color_suppresses_ansi_help(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-color", "help", "scan"])

        self.assertEqual(rc, 0)
        self.assertNotIn("\x1b[", stdout.getvalue())
        self.assertIn("relayx scan", stdout.getvalue())

    def test_registry_provides_help_for_grouped_command(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["help", "summary"])

        self.assertEqual(rc, 0)
        self.assertIn("relayx summary", stdout.getvalue())
        self.assertIn("What it does", stdout.getvalue())
        self.assertIn("Required inputs", stdout.getvalue())

    def test_help_commands_json(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["help", "commands", "--format", "json"])
        data = json.loads(stdout.getvalue())

        self.assertEqual(rc, 0)
        self.assertEqual(data["topic"], "commands")
        self.assertNotIn("\x1b[", stdout.getvalue())
        self.assertTrue(any(group["group"] == "Enterprise" for group in data["groups"]))
        self.assertTrue(any(group["group"] == "Evidence" for group in data["groups"]))
        self.assertTrue(any(group["group"] == "Controlled Execution" for group in data["groups"]))

    def test_discover_command_searches_registry(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "--no-color", "discover", "jsonl"])

        self.assertEqual(rc, 0)
        text = stdout.getvalue()
        self.assertIn("RelayX Command Discovery - jsonl", text)
        self.assertIn("export (command, Enterprise)", text)
        self.assertIn("relayx export -r result.json -f jsonl -o relayx-events.jsonl", text)

    def test_discover_json_is_machine_clean(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "discover", "epa", "--format", "json"])
        data = json.loads(stdout.getvalue())

        self.assertEqual(rc, 0)
        self.assertEqual(data["query"], "epa")
        self.assertNotIn("\x1b[", stdout.getvalue())
        self.assertTrue(any(row["name"] == "lab-matrix" for row in data["matches"]))

    def test_next_command_guides_without_result(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "--no-color", "next"])

        self.assertEqual(rc, 0)
        self.assertIn("No result selected yet.", stdout.getvalue())
        self.assertIn("relayx scan --targets examples/targets.txt --out result.json", stdout.getvalue())

    def test_next_command_guides_from_result_and_path(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(
                [
                    "--no-banner",
                    "--no-color",
                    "next",
                    "--result",
                    "examples/tutorial/sample-result.json",
                    "--path-id",
                    "PX-0001",
                ]
            )

        self.assertEqual(rc, 0)
        self.assertIn("PX-0001", stdout.getvalue())
        self.assertIn("relayx validate --result examples/tutorial/sample-result.json --path-id PX-0001 --mode dry-run", stdout.getvalue())

    def test_next_json_for_missing_path_lists_available_paths(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(
                [
                    "--no-banner",
                    "next",
                    "--result",
                    "examples/tutorial/sample-result.json",
                    "--path-id",
                    "PX-9999",
                    "--format",
                    "json",
                ]
            )
        data = json.loads(stdout.getvalue())

        self.assertEqual(rc, 0)
        self.assertEqual(data["state"], "path_not_found")
        self.assertTrue(any(path["id"] == "PX-0001" for path in data["top_paths"]))

    def test_unknown_top_level_command_suggests_close_match(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            build_parser().parse_args(["path"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("Did you mean: paths?", stderr.getvalue())

    def test_short_options_help_topic(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "help", "short-options"])

        self.assertEqual(rc, 0)
        self.assertIn("RelayX Short Options", stdout.getvalue())
        self.assertIn("-f, --format", stdout.getvalue())
        self.assertIn("-y, --confirm", stdout.getvalue())
        self.assertIn("Command Alias Map", stdout.getvalue())
        self.assertIn("quality-gate", stdout.getvalue())

    def test_short_options_help_json_contains_command_map(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "help", "short-options", "--format", "json"])
        data = json.loads(stdout.getvalue())

        self.assertEqual(rc, 0)
        commands = {row["command"]: row["aliases"] for row in data["commands"]}
        self.assertIn("scan", commands)
        self.assertIn("-t/--targets", commands["scan"])
        self.assertIn("quality-gate", commands)
        self.assertIn("-C/--project-root", commands["quality-gate"])
        self.assertIn("console", commands)
        self.assertIn("-s/--script", commands["console"])

    def test_command_help_lists_short_options(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "help", "bundle"])

        self.assertEqual(rc, 0)
        self.assertIn("Short options", stdout.getvalue())
        self.assertIn("-F/--formats", stdout.getvalue())

    def test_lab_stability_help_explains_thresholds(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "help", "lab-stability"])

        self.assertEqual(rc, 0)
        self.assertIn("repeat-capture", stdout.getvalue())
        self.assertIn("-T/--stable-threshold", stdout.getvalue())

    def test_lab_diff_help_explains_response_differentials(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "help", "lab-diff"])

        self.assertEqual(rc, 0)
        self.assertIn("policy-state response differences", stdout.getvalue())
        self.assertIn("-p/--pair", stdout.getvalue())

    def test_lab_provenance_help_explains_review_boundary(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "help", "lab-provenance"])

        self.assertEqual(rc, 0)
        self.assertIn("provenance", stdout.getvalue())
        self.assertIn("operator review", stdout.getvalue())
        self.assertIn("-c/--corpus", stdout.getvalue())

    def test_evidence_report_help_explains_offline_audit(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["--no-banner", "help", "evidence-report"])

        self.assertEqual(rc, 0)
        self.assertIn("evidence completeness", stdout.getvalue())
        self.assertIn("source taxonomy", stdout.getvalue())
        self.assertIn("-r/--result", stdout.getvalue())
        self.assertIn("offline", stdout.getvalue())

    def test_unknown_help_topic_returns_error(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["help", "does-not-exist"])

        self.assertEqual(rc, 2)
        self.assertIn("Unknown Help Topic", stdout.getvalue())

    def test_python_module_entrypoint_propagates_exit_code(self):
        completed = subprocess.run(
            [sys.executable, "-m", "relayx", "help", "does-not-exist", "--no-banner"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("Unknown Help Topic", completed.stdout)

    def test_command_registry_covers_parser_commands(self):
        parser_commands = set()
        for action in build_parser()._actions:
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                parser_commands = set(choices)
                break

        specs = _get_command_specs()

        self.assertEqual(parser_commands, set(specs))
        for command, spec in specs.items():
            self.assertTrue(spec.group, command)
            self.assertTrue(spec.purpose, command)
            self.assertTrue(spec.when_to_use, command)
            self.assertTrue(spec.required_inputs, command)
            self.assertTrue(spec.examples, command)
            self.assertTrue(spec.output_contracts, command)

    def test_completion_scripts_cover_registry_terms(self):
        bash = render_completion("bash")
        zsh = render_completion("zsh")
        fish = render_completion("fish")

        for script in (bash, zsh, fish):
            self.assertIn("CommandSpec registry", script)
            self.assertIn("console", script)
            self.assertIn("completion", script)
            self.assertIn("opengraph", script)
            self.assertIn("opsec", script)

    def test_console_context_and_script_mode(self):
        self.assertIn(
            "path:PX-0001",
            _console_prompt(ConsoleContext(result="result.json", path_id="PX-0001", opsec_policy="strict")),
        )
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "console.txt"
            script.write_text("context\nhelp console\nexit\n", encoding="utf-8")
            stdout = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=False), contextlib.redirect_stdout(stdout):
                os.environ.pop("NO_COLOR", None)
                rc = main(["--no-banner", "console", "--script", str(script)])

        self.assertEqual(rc, 0)
        self.assertIn("\x1b[", stdout.getvalue())
        self.assertIn("RelayX Console Context", stdout.getvalue())
        self.assertIn("relayx console", stdout.getvalue())

    def test_console_internal_commands_support_clear_history_and_help_alias(self):
        context = ConsoleContext(no_color=True, history_entries=["show summary", "help console"])
        self.assertIn("2  help console", _format_console_history(context, limit=1))

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc_history, exit_history = _handle_console_line("history 1", context)
            rc_clear_screen, exit_clear_screen = _handle_console_line("clear", context, interactive=False)
            rc_help, exit_help = _handle_console_line("?", context)
            rc_clear_history, exit_clear_history = _handle_console_line("history clear", context)

        self.assertEqual(rc_history, 0)
        self.assertEqual(rc_clear_screen, 0)
        self.assertEqual(rc_help, 0)
        self.assertEqual(rc_clear_history, 0)
        self.assertFalse(exit_history)
        self.assertFalse(exit_clear_screen)
        self.assertFalse(exit_help)
        self.assertFalse(exit_clear_history)
        self.assertIn("2  help console", stdout.getvalue())
        self.assertIn("RelayX Help", stdout.getvalue())
        self.assertEqual(context.history_entries, [])

    def test_console_history_policy_skips_sensitive_or_hidden_lines(self):
        self.assertTrue(_console_history_recordable("show summary"))
        self.assertFalse(_console_history_recordable(" show summary"))
        self.assertFalse(_console_history_recordable("run --password RedteamN0t3s."))
        self.assertFalse(_console_history_recordable("validate --token=secret"))
        self.assertFalse(_console_history_recordable("# comment"))

    def test_console_history_policy_discards_auto_recorded_sensitive_line(self):
        class FakeReadline:
            def __init__(self):
                self.items = ["run --password RedteamN0t3s."]

            def get_current_history_length(self):
                return len(self.items)

            def get_history_item(self, index):
                if 1 <= index <= len(self.items):
                    return self.items[index - 1]
                return None

            def remove_history_item(self, index):
                self.items.pop(index)

            def add_history(self, line):
                self.items.append(line)

        fake = FakeReadline()
        context = ConsoleContext(readline_enabled=True)
        with mock.patch.object(cli_module, "_READLINE", fake):
            _record_console_history("run --password RedteamN0t3s.", context)

        self.assertEqual(fake.items, [])
        self.assertEqual(context.history_entries, [])

    def test_console_completion_candidates_are_contextual(self):
        self.assertIn("show ", _console_completion_candidates("sh", "sh"))
        self.assertIn("summary ", _console_completion_candidates("show s", "s"))
        self.assertIn("console ", _console_completion_candidates("help con", "con"))
        self.assertIn("opsec-policy ", _console_completion_candidates("set o", "o"))
        self.assertIn("strict ", _console_completion_candidates("set opsec-policy s", "s"))

    def test_console_script_mode_accepts_operator_shell_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "console.txt"
            script.write_text("menu\nnext\ndiscover jsonl\nclear\nhistory\nhistory clear\n?\nexit\n", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = main(
                    [
                        "--no-banner",
                        "--no-color",
                        "console",
                        "--script",
                        str(script),
                        "--result",
                        "examples/tutorial/sample-result.json",
                        "--path-id",
                        "PX-0001",
                        "--no-history",
                        "--no-completion",
                    ]
                )

        self.assertEqual(rc, 0)
        self.assertIn("RelayX Console Menu", stdout.getvalue())
        self.assertIn("RelayX Next Steps", stdout.getvalue())
        self.assertIn("RelayX Command Discovery - jsonl", stdout.getvalue())
        self.assertIn("No console history recorded in this session.", stdout.getvalue())
        self.assertIn("Console history cleared.", stdout.getvalue())
        self.assertIn("RelayX Help", stdout.getvalue())

    def test_console_unknown_command_suggests_close_match(self):
        context = ConsoleContext(no_color=True)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc, should_exit = _handle_console_line("nxt", context)

        self.assertEqual(rc, 2)
        self.assertFalse(should_exit)
        self.assertIn("Did you mean: next", stderr.getvalue())

    def test_no_color_suppresses_console_ansi(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "console.txt"
            script.write_text("context\nhelp console\nexit\n", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = main(["--no-banner", "--no-color", "console", "--script", str(script)])

        self.assertEqual(rc, 0)
        self.assertNotIn("\x1b[", stdout.getvalue())
        self.assertIn("RelayX Console Context", stdout.getvalue())

    def test_console_unknown_command_fails_script_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "console.txt"
            script.write_text("does-not-exist\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = main(["--no-banner", "console", "--script", str(script)])

        self.assertEqual(rc, 2)
        self.assertIn("Unknown console command", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
