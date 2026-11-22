"""Local redaction for the before-send hook: veil-detect plus rules, spans replaced by placeholders.

Nothing here writes the message, its spans or the placeholder map to a file, a log or stderr.
Standard library only at import time; torch and transformers load inside load_detector().
"""

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

MODEL_REPO = "libraos/veil-detect"
MODEL_REVISION = "v1.0.0"
# sha256 of each file at MODEL_REVISION; setup checks downloads against these and the hook
# checks them again before every load, since the tag on the Hub could move.
MODEL_FILES = {
    "config.json": "b84de1ba3d8b0a2ce763d33add118d844316e405f7841eb96e8216d930502bdf",
    "model.safetensors": "3b37153552480624212909e3323ff352fafcfe11ef7b1fcfd21df2eedd821a1f",
    "tokenizer.json": "acbd420e2269cdc1ef45332d3d5c418be4aef6b8cb5a0b7ccae0893485307153",
    "tokenizer_config.json": "45d44c25e701d4de0591503b45ee8cdba2460ce683839360323b954c45f1fe4b",
}

# The host stops the hook at 60 s. Loading the model takes seconds; detection stops here so the
# answer is a block that says why, not a timeout.
DETECT_DEADLINE_SECONDS = 50.0
# About 25,000 tokens: well inside the deadline on a laptop CPU.
MAX_TOTAL_CHARS = 100_000

PLUGIN_DIR = Path(__file__).resolve().parent


def data_dir():
    """The plugin's own data folder, kept across versions and outside the installed files."""
    override = os.environ.get("AGENTD_REDACT_DATA_DIR")
    if override:
        return Path(override)
    # Installed at <stateDir>/plugins/cache/<source>/<id>/<version>/.
    parts = PLUGIN_DIR.parents
    if len(parts) >= 4 and parts[2].name == "cache" and parts[3].name == "plugins":
        return parts[3] / "data" / PLUGIN_DIR.parent.name
    return PLUGIN_DIR / ".data"


def model_dir(data):
    return data / "model" / MODEL_REVISION


def venv_python(data):
    venv = data / "venv"
    return venv / "Scripts" / "python.exe" if os.name == "nt" else venv / "bin" / "python"


def setup_hint():
    script = PLUGIN_DIR / "setup_env.py"
    return f'run "python3 {script}" on the computer that runs AgentD Next, then send again'


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Blocked(Exception):
    """Stops the send; the message is the reason the person reads."""


def verify_weights(folder):
    missing = [name for name in MODEL_FILES if not (folder / name).is_file()]
    if missing:
        raise Blocked(
            f"Local redaction is not ready: the veil-detect {MODEL_REVISION} model is not "
            f"downloaded. To fix it, {setup_hint()}."
        )
    for name, expected in MODEL_FILES.items():
        if sha256_file(folder / name) != expected:
            raise Blocked(
                f"Local redaction is not ready: the downloaded model file {name} does not match "
                f"veil-detect {MODEL_REVISION}. To fix it, {setup_hint()}; it downloads the model again."
            )


# --- detection -------------------------------------------------------------------------------


def load_detector(folder):
    """detect(text, deadline) -> [{start, end, label}] using the verified local weights."""
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    try:
        import torch
        from transformers import AutoModelForTokenClassification, AutoTokenizer
    except ImportError:
        raise Blocked(
            f"Local redaction is not ready: torch or transformers is missing. To fix it, {setup_hint()}."
        ) from None
    tok = AutoTokenizer.from_pretrained(str(folder), local_files_only=True)
    model = AutoModelForTokenClassification.from_pretrained(str(folder), local_files_only=True).eval()

    # detect() from the veil-detect model card, with a deadline check per window.
    def detect(text, deadline, window=384, stride=64):
        enc = tok(text, add_special_tokens=False, return_offsets_mapping=True, verbose=False)
        ids, offs = enc["input_ids"], enc["offset_mapping"]
        body = window - 2
        tag_at = {}
        for w0 in range(0, max(1, len(ids) - stride), body - stride):
            if time.monotonic() > deadline:
                raise TimeoutError
            x = torch.tensor([[tok.cls_token_id] + ids[w0 : w0 + body] + [tok.sep_token_id]])
            with torch.no_grad():
                pred = model(input_ids=x).logits[0, 1:-1].argmax(-1).tolist()
            for (a, b), p in zip(offs[w0 : w0 + body], pred):
                if a < b:
                    tag_at[(a, b)] = model.config.id2label[p]
        spans = []
        for (a, b), tag in sorted(tag_at.items()):
            if tag == "O":
                continue
            label = tag.split("-", 1)[1]
            prev = spans[-1] if spans else None
            if prev and prev["label"] == label and _joinable(text[prev["end"] : a]):
                prev["end"] = b
            else:
                spans.append({"start": a, "end": b, "label": label})
        return spans

    return detect


# --- rules for exact formats the model may miss ----------------------------------------------

_B = r"(?<![0-9A-Za-z])"
_E = r"(?![0-9A-Za-z])"
_USCC_CHAR = "[0-9A-HJ-NPQRTUWXY]"
# Each rule masks its named group "v" when it has one, else the whole match.
RULES = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")),
    ("credential", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("credential", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("credential", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("credential", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("credential", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("credential", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("credential", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("credential", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("credential", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("credential", re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/-]{16,}=*)")),
    (
        "credential",
        re.compile(
            r"(?i)(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|"
            r"password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?(?P<v>[^\s\"',;]{6,})"
        ),
    ),
    # 18-digit resident ID: area code, birth date, sequence, check character.
    (
        "id",
        re.compile(_B + r"[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]" + _E),
    ),
    # Unified social credit code: 18 characters, the region code in positions 3-8.
    ("id", re.compile(_B + _USCC_CHAR + "{2}" + r"\d{6}" + _USCC_CHAR + "{9}[0-9A-HJ-NPQRTUWXY]" + _E)),
    ("phone", re.compile(r"(?<![\d+])(?:\+?86[\s-]?)?1[3-9]\d(?:[\s-]?\d{4}){2}(?!\d)")),
    ("phone", re.compile(r"(?<![\w+])\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]?\d{2,4}){1,4}(?!\d)")),
    ("phone", re.compile(r"(?<![\w(])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)")),
]


def rule_spans(text):
    spans = []
    for label, pattern in RULES:
        for match in pattern.finditer(text):
            group = "v" if "v" in pattern.groupindex else 0
            start, end = match.span(group)
            if start < end:
                spans.append({"start": start, "end": end, "label": label})
    return spans


def merge_spans(spans):
    """Overlapping spans become one; the longer one names it."""
    merged = []
    for span in sorted(spans, key=lambda s: (s["start"], -(s["end"] - s["start"]))):
        prev = merged[-1] if merged else None
        if prev and span["start"] < prev["end"]:
            if span["end"] - span["start"] > prev["end"] - prev["start"]:
                prev["label"] = span["label"]
            prev["end"] = max(prev["end"], span["end"])
        else:
            merged.append(dict(span))
    return merged


# --- spans into placeholders ----------------------------------------------------------------

# A word character for widening and for word boundaries. CJK script is left out: it has no spaces
# between words, so widening there would swallow the whole line.
_WORD_CLASS = r"[^\W\u2e80-\u9fff\uac00-\ud7af\uf900-\ufaff]"
_WORD = re.compile(_WORD_CLASS)
_SPACE_GAP = re.compile(r"[^\S\r\n]*")
_NAME_PART = re.compile(_WORD_CLASS + "+")


def _is_word(char):
    return bool(_WORD.fullmatch(char))


def _joinable(gap):
    """Same-label spans join across spaces or an untagged subword; a line break ends a span."""
    return bool(_SPACE_GAP.fullmatch(gap) or _NAME_PART.fullmatch(gap))


def refine_spans(text, spans):
    """Widen model spans to whole words, then join same-label spans the model split apart."""
    widened = []
    for span in sorted(spans, key=lambda s: s["start"]):
        start, end = span["start"], span["end"]
        while start > 0 and _is_word(text[start - 1]) and _is_word(text[start]):
            start -= 1
        while end < len(text) and _is_word(text[end]) and _is_word(text[end - 1]):
            end += 1
        widened.append({"start": start, "end": end, "label": span["label"]})
    joined = []
    for span in merge_spans(widened):
        prev = joined[-1] if joined else None
        if prev and prev["label"] == span["label"] and _joinable(text[prev["end"] : span["start"]]):
            prev["end"] = span["end"]
        else:
            joined.append(span)
    return joined


class Placeholders:
    """One placeholder per distinct value and label across the whole message; held in memory only."""

    def __init__(self):
        self._by_value = {}
        self._counts = {}

    def for_value(self, label, value):
        key = (label, value)
        if key not in self._by_value:
            self._counts[label] = self._counts.get(label, 0) + 1
            self._by_value[key] = f"[{label.upper()}_{self._counts[label]}]"
        return self._by_value[key]


def _trimmed(text, span):
    start, end = span["start"], span["end"]
    # Keep surrounding whitespace out of the placeholder.
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return {"start": start, "end": end, "label": span["label"]} if start < end else None


def find_spans(text, detect, deadline):
    spans = merge_spans(refine_spans(text, detect(text, deadline)) + rule_spans(text))
    return [span for span in (_trimmed(text, s) for s in spans) if span]


def _value_pattern(values):
    """Matches any of values, longest first, only where it is not part of a longer word."""
    alternatives = []
    for value in sorted(values, key=lambda v: (-len(v), v)):
        head = f"(?<!{_WORD_CLASS})" if _is_word(value[0]) else ""
        tail = f"(?!{_WORD_CLASS})" if _is_word(value[-1]) else ""
        alternatives.append(head + re.escape(value) + tail)
    return re.compile("|".join(alternatives))


def redact_all(texts, detect, deadline, placeholders):
    """Redact every text, replacing each value found in any of them everywhere it occurs.

    A person's name parts of three or more letters are replaced on their own too.
    """
    found = [find_spans(text, detect, deadline) for text in texts]
    label_of = {}
    for text, spans in zip(texts, found):
        for span in spans:
            label_of.setdefault(text[span["start"] : span["end"]], span["label"])
    for value, label in list(label_of.items()):
        if label == "person":
            for part in _NAME_PART.findall(value):
                if len(part) >= 3 and part != value and any(c.isalpha() for c in part):
                    label_of.setdefault(part, label)
    if not label_of:
        return list(texts)
    pattern = _value_pattern(label_of)
    out = []
    for text, spans in zip(texts, found):
        matches = [{"start": m.start(), "end": m.end(), "label": label_of[m[0]]} for m in pattern.finditer(text)]
        pieces = []
        cursor = 0
        for span in merge_spans(spans + matches):
            start, end = span["start"], span["end"]
            value = text[start:end]
            pieces.append(text[cursor:start])
            pieces.append(placeholders.for_value(label_of.get(value, span["label"]), value))
            cursor = end
        pieces.append(text[cursor:])
        out.append("".join(pieces))
    return out


def redact_text(text, detect, deadline, placeholders):
    return redact_all([text], detect, deadline, placeholders)[0]


# --- the hook --------------------------------------------------------------------------------


def _block(reason):
    return {"decision": "block", "reason": reason}


def _read_message(raw):
    request = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    message = request["message"]
    text = message["text"]
    attachments = message.get("attachments", [])
    if not isinstance(text, str) or not isinstance(attachments, list):
        raise ValueError
    for attachment in attachments:
        if not isinstance(attachment.get("id"), str) or not isinstance(attachment.get("text"), str):
            raise ValueError
    unshown = request.get("unshownAttachments", [])
    if not isinstance(unshown, list):
        raise ValueError
    return text, attachments, unshown


def decide(raw, folder, load=load_detector, clock=time.monotonic):
    """The hook's answer for one stdin payload: pass, rewrite or block. Never raises."""
    started = clock()
    try:
        text, attachments, unshown = _read_message(raw)
    except Exception:
        return _block("Local redaction could not read this message, so it was not sent. Update AgentD Next and the plugin, then send again.")
    if unshown:
        names = ", ".join(str(item.get("name", "attachment")) for item in unshown[:3] if isinstance(item, dict))
        return _block(
            f"Local redaction only checks text and UTF-8 text files up to 1 MB, so {names or 'an attachment'} "
            "cannot be checked and the message was not sent. Remove it, or paste its text, then send again."
        )
    total = len(text) + sum(len(attachment["text"]) for attachment in attachments)
    if total > MAX_TOTAL_CHARS:
        return _block(
            f"Local redaction can check up to {MAX_TOTAL_CHARS:,} characters in one message within "
            "its time limit, and this one is longer. Split it into smaller messages or attachments."
        )
    try:
        verify_weights(folder)
        detect = load(folder)
        deadline = started + DETECT_DEADLINE_SECONDS
        placeholders = Placeholders()
        new_text, *redacted = redact_all(
            [text] + [attachment["text"] for attachment in attachments], detect, deadline, placeholders
        )
        changed = [
            {"id": attachment["id"], "text": out}
            for attachment, out in zip(attachments, redacted)
            if out != attachment["text"]
        ]
    except Blocked as blocked:
        return _block(str(blocked))
    except TimeoutError:
        return _block(
            "Local redaction could not finish checking this message in time, so it was not sent. "
            "Split it into smaller messages or attachments."
        )
    except Exception as error:
        # The type only: an exception's message can quote the text it failed on.
        return _block(
            f"Local redaction failed ({type(error).__name__}), so the message was not sent. Send it "
            f"again; if it keeps failing, {setup_hint()}, or turn the plugin off on the AgentD page."
        )
    if new_text == text and not changed:
        return {"decision": "pass"}
    message = {"text": new_text}
    if changed:
        message["attachments"] = changed
    return {"decision": "rewrite", "message": message}


def main(load=load_detector):
    answer = decide(sys.stdin.buffer.read(), model_dir(data_dir()), load=load)
    sys.stdout.write(json.dumps(answer, ensure_ascii=True) + "\n")
    sys.stdout.flush()
