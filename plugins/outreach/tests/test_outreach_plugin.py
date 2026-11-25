"""Tests for the outreach plugin: its setup check and its manifest.

Run: python3 -m unittest discover -s plugins/outreach/tests
The fake outreach programs are POSIX shell scripts, so the setup tests are skipped on Windows.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
PLUGIN = Path(__file__).resolve().parent.parent
CHECK = PLUGIN / "check_outreach.py"

USAGE = """usage:
  outreach broadcast create -p PROJECT --subject S
  outreach mcp [--token-file FILE]
      an MCP server on stdin/stdout for agents
"""


def run_check(fake_outreach=None):
    """Runs the setup check with PATH holding only a fake outreach (or nothing)."""
    with tempfile.TemporaryDirectory() as folder:
        if fake_outreach is not None:
            program = Path(folder) / "outreach"
            program.write_text("#!/bin/sh\n" + fake_outreach)
            program.chmod(0o755)
        env = {key: value for key, value in os.environ.items() if key != "PATH"}
        env["PATH"] = folder
        return subprocess.run(
            [sys.executable, str(CHECK)],
            cwd=PLUGIN,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )


@unittest.skipIf(os.name == "nt", "the fake programs are shell scripts")
class SetupCheck(unittest.TestCase):
    def assert_fails_with_fix(self, result, reason):
        self.assertEqual(result.returncode, 1, result)
        last = result.stderr.strip().splitlines()[-1]
        self.assertIn(reason, last)
        # The app shows only the last line, so the fix has to be on it.
        self.assertIn("go build -o outreach ./cmd/outreach", last)
        self.assertIn("Set up again", last)

    def test_missing_program_explains_the_fix(self):
        self.assert_fails_with_fix(run_check(None), "not on PATH")

    def test_version_found(self):
        result = run_check('[ "$1" = "--version" ] && echo "outreach 0.4.0" && exit 0\nexit 9\n')
        self.assertEqual(result.returncode, 0, result)
        self.assertIn("outreach 0.4.0", result.stdout)

    def test_build_without_version_flag_passes_on_its_usage(self):
        # printf, not cat: PATH holds only the fake, so only shell builtins work.
        result = run_check(f"printf '%s' '{USAGE}' >&2\nexit 1\n")
        self.assertEqual(result.returncode, 0, result)
        self.assertIn("no --version", result.stdout)

    def test_build_without_mcp_command_fails(self):
        result = run_check("printf 'usage:\\n  outreach broadcast status ID\\n' >&2\nexit 1\n")
        self.assert_fails_with_fix(result, "without the mcp command")

    def test_other_failure_fails(self):
        self.assert_fails_with_fix(run_check("echo boom >&2\nexit 3\n"), "failed (exit 3)")

    def test_only_version_is_asked(self):
        # Any other argument makes the fake fail, so a pass shows the check ran just --version.
        result = run_check('[ "$#" = 1 ] && [ "$1" = "--version" ] && echo v1 && exit 0\nexit 9\n')
        self.assertEqual(result.returncode, 0, result)


class Manifest(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((PLUGIN / "agentd-plugin.json").read_text())

    def test_one_outreach_server_running_outreach_mcp(self):
        servers = self.manifest["contributes"]["mcpServers"]
        self.assertEqual(list(servers), ["outreach"])
        self.assertEqual(servers["outreach"]["command"], "outreach")
        self.assertEqual(servers["outreach"]["args"], ["mcp"])
        self.assertNotIn("env", servers["outreach"])

    def test_url_is_a_plain_setting_and_the_token_a_secret_file(self):
        settings = {setting["name"]: setting for setting in self.manifest["settings"]}
        self.assertFalse(settings["outreach_url"]["secret"])
        self.assertTrue(settings["outreach_token"]["secret"])
        self.assertNotIn("default", settings["outreach_token"])
        given = self.manifest["contributes"]["mcpServers"]["outreach"]["settings"]
        self.assertEqual(given["OUTREACH_URL"], "outreach_url")
        self.assertEqual(
            given["OUTREACH_API_KEY_FILE"], {"setting": "outreach_token", "file": True}
        )
        self.assertNotIn("OUTREACH_API_KEY", given)

    def test_setup_runs_only_the_check(self):
        self.assertEqual(self.manifest["setup"]["command"], ["python3", "check_outreach.py"])


if __name__ == "__main__":
    unittest.main()
