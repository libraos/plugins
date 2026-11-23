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
import unicodedata
from pathlib import Path

import extract

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
    return (
        'choose "Set up again" for Local redaction in Settings, Plugins '
        f'(or run "python3 {script}" on the computer that runs AgentD Next), then send again'
    )


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
_PROVINCE = "[京津沪渝冀晋辽吉黑苏浙皖闽赣鲁豫鄂湘粤琼川贵云陕甘青蒙桂藏宁新]"
_PLATE_CHAR = "[A-HJ-NP-Z0-9]"
_NUM = r"(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?"
_CAPITAL = "[零壹贰叁肆伍陆柒捌玖拾佰仟万萬亿億]"
_CUR_WORD = "(?:元|圆|美元|港元|港币|欧元|英镑|日元)"


def _digits(value):
    return re.sub(r"[\s-]", "", value)


def _luhn(value):
    digits = _digits(value)
    total = 0
    for i, char in enumerate(reversed(digits)):
        n = int(char) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def _iban(value):
    code = _digits(value).upper()
    if not 15 <= len(code) <= 34:
        return False
    moved = code[4:] + code[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


def _plate(value):
    # A serial of letters only is a word, not a plate; real ones carry at least three digits.
    return sum(c.isdigit() for c in value[2:]) >= 3


# Each rule masks its named group "v" when it has one, else the whole match; a third element is a
# check the matched value must pass.
RULES = [
    ("email", re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")),
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
    # Court case number: (year), court code, case type, serial, such as （2024）京0105民初12345号.
    (
        "case_number",
        re.compile(
            r"[（(〔\[]\s*(?:19|20)\d{2}\s*[）)〕\]]\s*(?:最高法|" + _PROVINCE + r"\d{0,4})"
            r"[\u4e00-\u9fa5]{1,6}?\d{1,7}(?:-\d+)?号(?:之[一二三四五六七八九十])?"
        ),
    ),
    # A number after an account keyword, whatever its format; on its own, a card number passing Luhn.
    (
        "bank_account",
        re.compile(
            r"(?i)(?:账号|帐号|账户|帐户|卡号|account\s*(?:no\.?|number)|a/c\s*no\.?)[^\d\n。；;，,]{0,12}?"
            r"(?<!\d)(?P<v>\d{4}(?:[ -]\d{4}){2,6}(?:[ -]\d{1,4})?|\d{8,30})" + _E
        ),
    ),
    ("bank_account", re.compile(r"(?<![0-9A-Za-z-])(?<![A-Z]{2}\d{2} )(?:[2-6]\d{15,18}|[2-6]\d{3}(?:[ -]\d{4}){3}(?:[ -]?\d{1,3})?)" + _E), _luhn),
    ("iban", re.compile(_B + r"[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?" + _E), _iban),
    # Amounts with a currency, in figures or Chinese capital numerals.
    (
        "amount",
        re.compile(
            r"(?:(?<![A-Za-z])(?:人民币|RMB|CNY|USD|HKD|EUR|GBP|JPY|美元|港币|港元|欧元|英镑|日元)\s*|[¥￥€£]\s?"
            # $ alone before one digit is a shell or regex reference, not money.
            r"|(?<![\w$])(?:US|HK)?\$(?=\d{1,3},\d{3}|\d+\.\d|\d{2}))"
            + _NUM + r"(?:\s*(?:千万|百万|万|亿))?(?:\s*" + _CUR_WORD + r")?(?:整)?"
            r"|(?<![\d.,])" + _NUM + r"\s*(?:千万|百万|万|亿)?\s*" + _CUR_WORD + r"(?:整)?"
            r"|(?:人民币\s*)?(?<!" + _CAPITAL + r")[零壹贰叁肆伍陆柒捌玖拾]" + _CAPITAL + r"{0,24}[元圆](?:[零壹贰叁肆伍陆柒捌玖]角)?"
            r"(?:[零壹贰叁肆伍陆柒捌玖]分)?整?"
        ),
    ),
    # Mainland plate: province, issuing letter, five-character serial or six for new energy.
    (
        "plate",
        re.compile(
            r"(?<![0-9A-Za-z])" + _PROVINCE + r"[A-HJ-NP-Z][·•]?"
            r"(?:[DF]" + _PLATE_CHAR + r"\d{4}|\d{5}[DF]|" + _PLATE_CHAR + r"{4}[A-HJ-NP-Z0-9挂学警])" + _E
        ),
        _plate,
    ),
    # Lawyer licence: category, region code, year first licensed, type, sex, serial; 17 digits.
    ("lawyer_licence", re.compile(r"(?<!\d)[1-9][1-6]\d{3}(?:19[89]\d|20[0-4]\d)\d{8}(?!\d)")),
    # Real estate title certificates, such as 京（2020）朝阳区不动产权第0012345号 or 京房权证朝字第123456号.
    (
        "property_certificate",
        re.compile(
            _PROVINCE + r"\s*[（(]\s*(?:19|20)\d{2}\s*[）)][\u4e00-\u9fa5]{0,12}?不动产(?:权|证明)第\s*\d{4,10}\s*号"
            r"|" + _PROVINCE + r"房(?:地产?|产?权证|产证)[\u4e00-\u9fa5]{0,6}?字?\s*"
            r"(?:[（(]\s*(?:19|20)\d{2}\s*[）)])?\s*第\s*\d{4,10}\s*号"
        ),
    ),
]


def rule_spans(text):
    spans = []
    for label, pattern, *check in RULES:
        for match in pattern.finditer(text):
            group = "v" if "v" in pattern.groupindex else 0
            start, end = match.span(group)
            if start < end and all(passes(text[start:end]) for passes in check):
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


_PLACEHOLDER = re.compile(r"\[([A-Z][A-Z0-9_]*)_([1-9][0-9]*)\]")


class Placeholders:
    """One placeholder per distinct value across the conversation; held in memory only.

    `known` is the thread's map from the host, placeholder to value: its values keep their
    placeholders and new ones are numbered after the highest of each label.
    """

    def __init__(self, known=None):
        self._by_value = {}
        self._counts = {}
        self._map = {}
        for placeholder, value in (known or {}).items():
            self._map[placeholder] = value
            self._by_value.setdefault(value, placeholder)
            match = _PLACEHOLDER.fullmatch(placeholder)
            if match:
                label = match[1].lower()
                self._counts[label] = max(self._counts.get(label, 0), int(match[2]))

    def known_values(self):
        """Each known value with its label, as a detector would tag it."""
        values = {}
        for placeholder, value in self._map.items():
            match = _PLACEHOLDER.fullmatch(placeholder)
            values.setdefault(value, match[1].lower() if match else "known")
        return values

    def for_value(self, label, value):
        if value not in self._by_value:
            count = self._counts.get(label, 0) + 1
            placeholder = f"[{label.upper()}_{count}]"
            while placeholder in self._map:
                count += 1
                placeholder = f"[{label.upper()}_{count}]"
            self._counts[label] = count
            self._by_value[value] = placeholder
            self._map[placeholder] = value
        return self._by_value[value]

    def mapping(self):
        return dict(self._map)


_CLOSERS = dict(zip(")）]】}」』》〉”’", "(（[【{「『《〈“‘"))
_OPENERS = {opener: closer for closer, opener in _CLOSERS.items()}


def _strippable(char, value):
    """Whitespace or punctuation at a span's edge, but not a bracket the span also closes or opens."""
    if char.isspace():
        return True
    if not unicodedata.category(char).startswith("P"):
        return False
    pair = _CLOSERS.get(char) or _OPENERS.get(char)
    return pair is None or pair not in value


def _trimmed(text, span):
    # veil-detect tags a full-width bracket or comma after a number as part of it; keep it in the text.
    start, end = span["start"], span["end"]
    while start < end and _strippable(text[start], text[start:end]):
        start += 1
    while end > start and _strippable(text[end - 1], text[start:end]):
        end -= 1
    return {"start": start, "end": end, "label": span["label"]} if start < end else None


def find_spans(text, detect, deadline):
    # Rules first: where a rule and the model find the same span, the rule's more exact label names it.
    found = rule_spans(text) + refine_spans(text, detect(text, deadline))
    spans = merge_spans([span for span in (_trimmed(text, s) for s in found) if span])
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

    A person's name parts of three or more letters are replaced on their own too. Values already
    in the conversation's map are replaced wherever they occur, found again or not, and text that
    is already a placeholder stays as it is.
    """
    found = [_outside_placeholders(text, find_spans(text, detect, deadline)) for text in texts]
    label_of = dict(placeholders.known_values())
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
        matches = _outside_placeholders(
            text, [{"start": m.start(), "end": m.end(), "label": label_of[m[0]]} for m in pattern.finditer(text)]
        )
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


def _outside_placeholders(text, spans):
    taken = [m.span() for m in _PLACEHOLDER.finditer(text)]
    return [s for s in spans if not any(s["start"] < end and start < s["end"] for start, end in taken)]


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
    # The thread's placeholder map; a host without one sends none.
    known = request.get("placeholders") or {}
    if not isinstance(known, dict) or not all(
        isinstance(key, str) and isinstance(value, str) and value for key, value in known.items()
    ):
        raise ValueError
    return text, attachments, unshown, known


def _unsupported_block(unshown):
    names = ", ".join(str(item.get("name", "attachment")) for item in unshown[:3] if isinstance(item, dict))
    return _block(
        "Local redaction checks text, UTF-8 text files up to 1 MB, Word documents (.docx) and PDFs "
        f"with a text layer, so {names or 'an attachment'} cannot be checked and the message was "
        "not sent. Remove it, or paste its text, then send again."
    )


def _files_to_read(unshown):
    """(item, kind) for each unshown attachment the host gave a path for and that has text."""
    files = []
    for item in unshown:
        if not isinstance(item, dict):
            return None
        name, path = item.get("name"), item.get("path")
        kind = extract.kind_of(name, item.get("mimeType", "")) if isinstance(name, str) else None
        if kind is None or not isinstance(path, str) or not isinstance(item.get("id"), str):
            return None
        files.append((item, kind))
    return files


def decide(raw, folder, load=load_detector, clock=time.monotonic):
    """The hook's answer for one stdin payload: pass, rewrite or block. Never raises."""
    started = clock()
    deadline = started + DETECT_DEADLINE_SECONDS
    try:
        text, attachments, unshown, known = _read_message(raw)
    except Exception:
        return _block("Local redaction could not read this message, so it was not sent. Update AgentD Next and the plugin, then send again.")
    files = _files_to_read(unshown)
    if files is None:
        return _unsupported_block(unshown)
    try:
        # Each Word document or PDF goes on as the text read from it; the file itself never does.
        extracted = [
            (item, extract.extract(item["path"], kind, item["name"], deadline)) for item, kind in files
        ]
    except extract.Unreadable as unreadable:
        return _block(
            f"Local redaction cannot check this message: {unreadable}. It was not sent. Remove the "
            "file, or paste its text, then send again."
        )
    except TimeoutError:
        return _block(
            "Local redaction could not finish reading the attached files in time, so the message "
            "was not sent. Send fewer or smaller files."
        )
    except Exception as error:
        return _block(
            f"Local redaction could not read an attached file ({type(error).__name__}), so the "
            "message was not sent. Remove it, or paste its text, then send again."
        )
    total = len(text) + sum(len(a["text"]) for a in attachments) + sum(len(t) for _, t in extracted)
    if total > MAX_TOTAL_CHARS:
        return _block(
            f"Local redaction can check up to {MAX_TOTAL_CHARS:,} characters in one message within "
            "its time limit, and this one is longer. Split it into smaller messages or attachments."
        )
    try:
        verify_weights(folder)
        detect = load(folder)
        placeholders = Placeholders(known)
        sources = [text] + [a["text"] for a in attachments] + [t for _, t in extracted]
        new_text, *redacted = redact_all(sources, detect, deadline, placeholders)
        changed = [
            {"id": attachment["id"], "text": out}
            for attachment, out in zip(attachments, redacted)
            if out != attachment["text"]
        ]
        replaced = [
            {"id": item["id"], "name": f"{item['name']}.txt", "text": out}
            for (item, _), out in zip(extracted, redacted[len(attachments) :])
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
    if new_text == text and not changed and not replaced:
        return {"decision": "pass"}
    message = {"text": new_text}
    if changed or replaced:
        message["attachments"] = changed + replaced
    return {"decision": "rewrite", "message": message, "placeholders": placeholders.mapping()}


def main(load=load_detector):
    answer = decide(sys.stdin.buffer.read(), model_dir(data_dir()), load=load)
    sys.stdout.write(json.dumps(answer, ensure_ascii=True) + "\n")
    sys.stdout.flush()
