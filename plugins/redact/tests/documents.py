"""Small .docx and PDF files built in memory, for tests only."""

import io
import zipfile
from xml.sax.saxutils import escape

_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def docx(paragraphs, comment=None, deleted=None, header=None, doctype=""):
    """A Word document with these paragraphs; a comment and deleted tracked text it must not show."""
    text = (lambda p: p) if doctype else escape
    body = "".join(f'<w:p><w:r><w:t xml:space="preserve">{text(p)}</w:t></w:r></w:p>' for p in paragraphs)
    if deleted:
        body += f'<w:p><w:del w:id="1" w:author="x"><w:r><w:delText>{escape(deleted)}</w:delText></w:r></w:del></w:p>'
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        archive.writestr("word/document.xml", f'<?xml version="1.0"?>{doctype}<w:document xmlns:w="{_W}"><w:body>{body}</w:body></w:document>')
        if header:
            archive.writestr("word/header1.xml", f'<w:hdr xmlns:w="{_W}"><w:p><w:r><w:t>{escape(header)}</w:t></w:r></w:p></w:hdr>')
        if comment:
            archive.writestr("word/comments.xml", f'<w:comments xmlns:w="{_W}"><w:comment><w:p><w:r><w:t>{escape(comment)}</w:t></w:r></w:p></w:comment></w:comments>')
    return out.getvalue()


def pdf(lines):
    """A one-page PDF; with lines it has a text layer, without them the page is blank like a scan."""
    stream = ""
    if lines:
        shown = " T* ".join(f"({line.replace(chr(92), chr(92) * 2).replace('(', chr(92) + '(').replace(')', chr(92) + ')')}) Tj" for line in lines)
        stream = f"BT /F1 12 Tf 14 TL 72 720 Td {shown} ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out
