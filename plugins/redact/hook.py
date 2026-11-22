"""before-send hook: runs redact.py in the plugin's own venv, or blocks until setup has made one."""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import redact  # noqa: E402


def _in_venv(venv):
    try:
        return Path(sys.prefix).resolve() == venv.resolve()
    except OSError:
        return False


def run():
    data = redact.data_dir()
    python = redact.venv_python(data)
    if _in_venv(data / "venv"):
        redact.main()
        return 0
    if not python.is_file() or os.environ.get("AGENTD_REDACT_CHILD") == "1":
        sys.stdin.buffer.read()
        reason = (
            "Local redaction is not ready: its Python environment with torch and transformers is "
            f"not set up. To fix it, {redact.setup_hint()}."
        )
        sys.stdout.write(json.dumps({"decision": "block", "reason": reason}) + "\n")
        return 0
    # The child inherits stdin and stdout, so the message never passes through this process.
    env = {**os.environ, "AGENTD_REDACT_CHILD": "1", "TRANSFORMERS_VERBOSITY": "error"}
    return subprocess.run([str(python), str(Path(__file__).resolve())], env=env, check=False).returncode


if __name__ == "__main__":
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.exit(run())
