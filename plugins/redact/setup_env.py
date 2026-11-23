"""Sets up local redaction: a venv with pinned CPU torch, transformers and pypdf, and the veil-detect weights.

AgentD Next runs it from Settings, Plugins, in the plugin's folder; by hand, with Python 3.10 or
newer on the computer that runs AgentD Next:  python3 setup_env.py
It writes only to the plugin's data folder (printed below) and can be run again to repair it.
Each progress line is one short line on stdout, flushed, so the app can show the latest one.
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
# Reads text from PDFs. Pure-Python wheels, installed only when they match these sha256 hashes;
# typing_extensions is pypdf's one dependency (before Python 3.11).
EXTRACTION = [
    "pypdf==7.1.1 --hash=sha256:04c5680d4b4cfa04ab505b09393fc949860c34a4dad6565284d11a2f5c3ce8b1",
    "typing_extensions==4.16.0 --hash=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8",
]


STEPS = 4


def fail(message):
    print(f"error: {message}", file=sys.stderr, flush=True)
    sys.exit(1)


def step(number, message):
    print(f"Step {number} of {STEPS}: {message}", flush=True)


def make_venv(data):
    python = redact.venv_python(data)
    if python.is_file():
        return python
    step(1, f"creating a Python environment in {data / 'venv'}")
    result = subprocess.run(
        [sys.executable, "-m", "venv", str(data / "venv")], check=False, stdout=sys.stderr
    )
    if result.returncode != 0 or not python.is_file():
        shutil.rmtree(data / "venv", ignore_errors=True)
        fail("could not create a venv. On Debian or Ubuntu install python3-venv, then run this again.")
    return python


def install_packages(python, data):
    pip = [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "-q"]
    requirements = data / "extraction-requirements.txt"
    requirements.write_text("\n".join(EXTRACTION) + "\n", encoding="utf-8")
    hashed = ["--require-hashes", "--only-binary", ":all:", "--no-deps", "-r", str(requirements)]
    for label, args in (
        (f"installing {TORCH} (CPU), the largest download", [TORCH, "--index-url", TORCH_INDEX]),
        (f"installing {TRANSFORMERS}", [TRANSFORMERS]),
        ("installing the PDF reader", hashed),
    ):
        step(2, label)
        # pip's own lines go to stderr, so stdout stays one progress line per step.
        if subprocess.run(pip + args, check=False, stdout=sys.stderr).returncode != 0:
            fail("installing packages failed; check the network connection and run this again.")


def copy_with_progress(name, response, out):
    total = int(response.headers.get("Content-Length") or 0)
    done, shown = 0, -1
    while chunk := response.read(4 * 1024 * 1024):
        out.write(chunk)
        done += len(chunk)
        if total > 0 and (percent := done * 100 // total) // 10 != shown // 10:
            shown = percent
            step(3, f"downloading {name}, {percent}% of {total // (1024 * 1024)} MB")


def download_weights(folder):
    folder.mkdir(parents=True, exist_ok=True)
    for name, expected in redact.MODEL_FILES.items():
        target = folder / name
        if target.is_file() and redact.sha256_file(target) == expected:
            continue
        url = f"https://huggingface.co/{redact.MODEL_REPO}/resolve/{redact.MODEL_REVISION}/{name}"
        step(3, f"downloading {name}")
        part = folder / f"{name}.part"
        try:
            with urllib.request.urlopen(url, timeout=60) as response, open(part, "wb") as out:
                copy_with_progress(name, response, out)
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
    print(f"Local redaction data folder: {data}", flush=True)
    python = make_venv(data)
    install_packages(python, data)
    download_weights(redact.model_dir(data))
    step(4, "checking the model and the environment")
    redact.verify_weights(redact.model_dir(data))
    check = subprocess.run([str(python), "-c", "import torch, transformers, pypdf"], check=False)
    if check.returncode != 0:
        fail("torch, transformers or pypdf does not import in the new environment; run this again.")
    print("Local redaction is ready. Turn it on in Settings, Plugins.", flush=True)


if __name__ == "__main__":
    main()
