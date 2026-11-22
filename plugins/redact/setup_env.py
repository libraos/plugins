"""Sets up local redaction: a venv with pinned CPU torch and transformers, and the veil-detect weights.

Run it with Python 3.10 or newer on the computer that runs AgentD Next:  python3 setup_env.py
It writes only to the plugin's data folder (printed below) and can be run again to repair it.
"""

import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import redact  # noqa: E402

TORCH = "torch==2.14.1"
TORCH_INDEX = "https://download.pytorch.org/whl/cpu"
TRANSFORMERS = "transformers==5.12.1"


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def make_venv(data):
    python = redact.venv_python(data)
    if python.is_file():
        return python
    print(f"Creating a Python environment in {data / 'venv'}")
    result = subprocess.run([sys.executable, "-m", "venv", str(data / "venv")], check=False)
    if result.returncode != 0 or not python.is_file():
        shutil.rmtree(data / "venv", ignore_errors=True)
        fail("could not create a venv. On Debian or Ubuntu install python3-venv, then run this again.")
    return python


def install_packages(python):
    print(f"Installing {TORCH} (CPU) and {TRANSFORMERS}")
    pip = [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-input"]
    for args in ([TORCH, "--index-url", TORCH_INDEX], [TRANSFORMERS]):
        if subprocess.run(pip + args, check=False).returncode != 0:
            fail("installing packages failed; check the network connection and run this again.")


def download_weights(folder):
    folder.mkdir(parents=True, exist_ok=True)
    for name, expected in redact.MODEL_FILES.items():
        target = folder / name
        if target.is_file() and redact.sha256_file(target) == expected:
            continue
        url = f"https://huggingface.co/{redact.MODEL_REPO}/resolve/{redact.MODEL_REVISION}/{name}"
        print(f"Downloading {name}")
        part = folder / f"{name}.part"
        try:
            with urllib.request.urlopen(url, timeout=60) as response, open(part, "wb") as out:
                shutil.copyfileobj(response, out, 4 * 1024 * 1024)
        except OSError as error:
            part.unlink(missing_ok=True)
            fail(f"downloading {name} failed ({error}); run this again.")
        if redact.sha256_file(part) != expected:
            part.unlink(missing_ok=True)
            fail(f"{name} does not match veil-detect {redact.MODEL_REVISION}; nothing was kept.")
        part.replace(target)


def main():
    if sys.version_info < (3, 10):
        fail("Python 3.10 or newer is needed.")
    data = redact.data_dir()
    print(f"Local redaction data folder: {data}")
    python = make_venv(data)
    install_packages(python)
    download_weights(redact.model_dir(data))
    redact.verify_weights(redact.model_dir(data))
    check = subprocess.run([str(python), "-c", "import torch, transformers"], check=False)
    if check.returncode != 0:
        fail("torch or transformers does not import in the new environment; run this again.")
    print("Local redaction is ready. Turn it on from the AgentD page.")


if __name__ == "__main__":
    main()
