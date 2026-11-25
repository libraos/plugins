"""Setup for the outreach plugin: checks that the outreach program is on PATH.

It runs `outreach --version` and nothing else. It downloads nothing and writes nothing.
Exit 0 when the program answers; 1 with the fix as the last line on stderr when it does not.
"""

import shutil
import subprocess
import sys

INSTALL = (
    "Install outreach (see the plugin's README: build it from github.com/libraos/outreach with "
    "'go build -o outreach ./cmd/outreach' in its shim folder), put it in a folder on the PATH "
    "of the program that runs LibraOS Next, restart LibraOS Next and choose Set up again."
)


def fail(reason):
    print(f"{reason} {INSTALL}", file=sys.stderr)
    return 1


def main():
    program = shutil.which("outreach")
    if program is None:
        return fail("The outreach program is not on PATH.")
    try:
        result = subprocess.run(
            [program, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        return fail(f"{program} --version did not answer within 20 seconds.")
    except OSError as error:
        return fail(f"{program} could not be started ({error.strerror}).")
    said = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        version = said.splitlines()[0] if said else "a version it did not print"
        print(f"Found {program}: {version}")
        return 0
    # Builds before --version print their usage and exit 1: the program is there and runs.
    if result.returncode == 1 and said.startswith("usage:"):
        if "outreach mcp" not in said:
            return fail(f"{program} is a build without the mcp command.")
        print(f"Found {program} (this build has no --version).")
        return 0
    return fail(f"{program} --version failed (exit {result.returncode}).")


if __name__ == "__main__":
    sys.exit(main())
