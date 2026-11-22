"""The hook with veil-detect replaced by a fake that tags known names; for tests only.

Usage: python3 fake_hook.py [raise]  < hook input on stdin
"""

import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import redact  # noqa: E402

FAKE_PEOPLE = re.compile(r"Maren Holloway|Holloway")


def fake_load(_folder):
    def detect(text, _deadline):
        if len(sys.argv) > 1 and sys.argv[1] == "raise":
            raise RuntimeError(f"tokenizer choked on {text!r}")
        return [{"start": m.start(), "end": m.end(), "label": "person"} for m in FAKE_PEOPLE.finditer(text)]

    return detect


if __name__ == "__main__":
    redact.verify_weights = lambda _folder: None
    redact.main(load=fake_load)
