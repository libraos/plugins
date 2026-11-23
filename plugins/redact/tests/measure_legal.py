"""Count misses and wrong replacements on legal_samples.json with the real model.

Run with the plugin's venv python: <data>/venv/bin/python tests/measure_legal.py [--baseline] [--show]
--baseline keeps only the rules from before the legal ones, to compare; --show prints the output.
A miss is a "must" value left in the output; a wrong replacement is a replaced span that
overlaps no "must" or "may" value.
"""

import json
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import redact  # noqa: E402


def occurrences(text, values):
    return [(i, i + len(v)) for v in values for i in _find_all(text, v)]


def _find_all(text, value):
    start = text.find(value)
    while start >= 0:
        yield start
        start = text.find(value, start + 1)


BASELINE_LABELS = {"email", "credential", "id", "phone"}


def main():
    if "--baseline" in sys.argv:
        redact.RULES[:] = [rule for rule in redact.RULES if rule[0] in BASELINE_LABELS]
    samples = json.loads((HERE / "legal_samples.json").read_text(encoding="utf-8"))["samples"]
    detect = redact.load_detector(redact.model_dir(redact.data_dir()))
    total_must = total_missed = total_spans = total_wrong = total_chars = 0
    for sample in samples:
        text = sample["text"]
        total_chars += len(text)
        started = time.monotonic()
        out = redact.redact_text(text, detect, float("inf"), redact.Placeholders())
        spans = redact.find_spans(text, detect, float("inf"))
        elapsed = time.monotonic() - started
        missed = [v for v in sample["must"] if v in out]
        known = occurrences(text, sample["must"] + sample["may"])
        wrong = [
            (s["label"], text[s["start"] : s["end"]])
            for s in spans
            if not any(a < s["end"] and s["start"] < b for a, b in known)
        ]
        total_must += len(sample["must"])
        total_missed += len(missed)
        total_spans += len(spans)
        total_wrong += len(wrong)
        print(f"{sample['name']}: {len(text)} chars, {elapsed:.1f}s, missed {len(missed)}/{len(sample['must'])}, wrong {len(wrong)}/{len(spans)}")
        for value in missed:
            print(f"  missed: {value}")
        for label, value in wrong:
            print(f"  wrong: {label} {value}")
        print("  labels:", sorted({s["label"] for s in spans}))
        if "--show" in sys.argv:
            print("  ", out.replace("\n", " | "))
    print(
        f"total: {len(samples)} texts, {total_chars} chars, missed {total_missed}/{total_must}, "
        f"wrong {total_wrong}/{total_spans}"
    )


if __name__ == "__main__":
    main()
