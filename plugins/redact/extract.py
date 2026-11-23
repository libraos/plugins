"""Text out of a Word document or a PDF with a text layer, for redaction; nothing else survives.

.docx is read with the standard library. PDFs need pypdf, which setup_env.py installs into the
plugin's venv; it loads inside extract_pdf(). Nothing read here is written anywhere.
"""

import re
import time
import warnings
import zipfile
from pathlib import Path
from xml.etree import ElementTree

# Bigger files are stopped: reading them would not finish inside the hook's limit.
MAX_FILE_BYTES = 20 * 1024 * 1024
# Uncompressed size of the document parts read from a .docx, against zip bombs.
MAX_DOCX_PART_BYTES = 50 * 1024 * 1024
MAX_PDF_PAGES = 2000


class Unreadable(Exception):
    """The file cannot be turned into text; the message is the reason the person reads."""


def kind_of(name, mime_type=""):
    """docx, pdf or None, by the file's name and then its type."""
    lower = name.lower()
    mime = (mime_type or "").lower()
    if lower.endswith(".docx") or mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        return "docx"
    if lower.endswith(".pdf") or mime == "application/pdf":
        return "pdf"
    return None


def extract(path, kind, name, deadline):
    """The file's text; raises Unreadable with a reason naming the file."""
    file = Path(path)
    try:
        size = file.stat().st_size
    except OSError:
        raise Unreadable(f"{name} could not be read on the computer that runs AgentD Next") from None
    if size > MAX_FILE_BYTES:
        raise Unreadable(f"{name} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    text = extract_docx(file, name) if kind == "docx" else extract_pdf(file, name, deadline)
    text = _tidy(text)
    if not text:
        raise Unreadable(
            f"{name} has no text layer (it is scanned or made of images), and local redaction "
            "cannot read text in images"
            if kind == "pdf"
            else f"{name} has no text in it"
        )
    return text


def _tidy(text):
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


# --- Word ------------------------------------------------------------------------------------

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
# The document, then its headers, footers, footnotes and endnotes. Comments are left out.
_DOCX_PARTS = re.compile(r"word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml")


def _part_order(name):
    stem = name[len("word/") : -len(".xml")]
    rank = 0 if stem == "document" else 1 if stem.startswith("header") else 3 if stem.startswith("footer") else 2
    return (rank, name)


def extract_docx(file, name):
    try:
        with zipfile.ZipFile(file) as archive:
            parts = sorted((info for info in archive.infolist() if _DOCX_PARTS.fullmatch(info.filename)), key=lambda i: _part_order(i.filename))
            if not any(info.filename == "word/document.xml" for info in parts):
                raise Unreadable(f"{name} is not a Word document")
            if sum(info.file_size for info in parts) > MAX_DOCX_PART_BYTES:
                raise Unreadable(f"{name} holds more text than local redaction can read")
            return "\n\n".join(_docx_part_text(archive.read(info), name) for info in parts)
    except Unreadable:
        raise
    except (zipfile.BadZipFile, OSError, KeyError, RuntimeError, ValueError):
        # RuntimeError: an encrypted archive. The type only, never the error's text.
        raise Unreadable(f"{name} could not be opened as a Word document") from None


def _docx_part_text(xml, name):
    # Word never writes a DTD; one here could expand entities without bound.
    if b"<!DOCTYPE" in xml[:4096].upper() or b"<!ENTITY" in xml.upper():
        raise Unreadable(f"{name} could not be opened as a Word document")
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        raise Unreadable(f"{name} could not be opened as a Word document") from None
    paragraphs = []
    for paragraph in root.iter(f"{_W}p"):
        pieces = []
        for node in paragraph.iter():
            # w:t is the text as it reads now; deleted tracked text is w:delText and stays out.
            if node.tag == f"{_W}t" and node.text:
                pieces.append(node.text)
            elif node.tag == f"{_W}tab":
                pieces.append("\t")
            elif node.tag in (f"{_W}br", f"{_W}cr"):
                pieces.append("\n")
        paragraphs.append("".join(pieces))
    return "\n".join(paragraphs)


# --- PDF -------------------------------------------------------------------------------------


def extract_pdf(file, name, deadline, clock=time.monotonic):
    try:
        import logging

        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
    except ImportError:
        raise Unreadable(f"{name} is a PDF, and the PDF reader is not installed") from None
    # pypdf warns through logging and warnings with bits of the file; nothing may reach stderr.
    logging.getLogger("pypdf").setLevel(logging.CRITICAL + 1)
    warnings.simplefilter("ignore")
    try:
        reader = PdfReader(str(file))
        if reader.is_encrypted and not reader.decrypt(""):
            raise Unreadable(f"{name} is protected by a password")
        if len(reader.pages) > MAX_PDF_PAGES:
            raise Unreadable(f"{name} has more than {MAX_PDF_PAGES} pages")
        pages = []
        for page in reader.pages:
            if clock() > deadline:
                raise TimeoutError
            pages.append(page.extract_text() or "")
        return "\n\n".join(pages)
    except (Unreadable, TimeoutError):
        raise
    except PdfReadError:
        raise Unreadable(f"{name} could not be opened as a PDF") from None
    except Exception as error:
        if type(error).__name__ in ("DependencyError", "FileNotDecryptedError"):
            raise Unreadable(f"{name} is protected by a password") from None
        raise Unreadable(f"{name} could not be opened as a PDF ({type(error).__name__})") from None
