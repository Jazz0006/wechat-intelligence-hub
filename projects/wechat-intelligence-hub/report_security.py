"""Security boundary for untrusted report fragments, not the application UI."""

from __future__ import annotations

import base64
import hashlib
from html import escape
import re
from urllib.parse import unquote, urlsplit


def require_sanitizer():
    try:
        import nh3
    except ImportError as exc:
        raise RuntimeError(
            "HTML generation requires nh3. Run scripts/setup_html.sh in the Hub "
            "project, then use its .venv/bin/python (or set PYTHON_BIN). "
            "Markdown remains available; unsafe HTML fallback is disabled."
        ) from exc
    return nh3


def safe_href(value: str, *, allow_parent: bool = False) -> str | None:
    value = value.strip()
    decoded = unquote(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in decoded) or "\\" in decoded:
        return None
    if decoded.startswith(("//", "/")):
        return None
    try:
        parsed = urlsplit(value)
        decoded_scheme = urlsplit(decoded).scheme.lower()
    except ValueError:
        return None
    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        return value
    if decoded_scheme or (not allow_parent and (decoded.startswith("..") or "/../" in decoded)):
        return None
    return value


def sanitize_fragment(fragment: str, *, id_prefix: str = "", allow_parent: bool = False) -> str:
    nh3 = require_sanitizer()

    def attribute_filter(tag: str, name: str, value: str) -> str | None:
        if name == "href":
            return safe_href(value, allow_parent=allow_parent)
        if name == "id":
            if not id_prefix or not value.startswith(id_prefix):
                return None
        return value

    # No images, CSS, embedded documents, forms or application data attributes.
    # Original links remain user-initiated; opening a report makes no requests.
    return nh3.clean(
        fragment,
        tags={"a", "p", "br", "hr", "strong", "b", "em", "i", "s", "del",
              "ul", "ol", "li", "blockquote", "pre", "code", "span", "div",
              "h1", "h2", "h3", "h4", "h5", "h6", "table", "thead", "tbody",
              "tfoot", "tr", "th", "td", "sup", "sub", "details", "summary"},
        clean_content_tags={"script", "style", "iframe", "object", "svg", "math", "template"},
        attributes={"a": {"href", "title"}, "*": {"id"},
                    "ol": {"start"}, "li": {"value"}, "th": {"colspan", "rowspan"},
                    "td": {"colspan", "rowspan"}, "details": {"open"}},
        attribute_filter=attribute_filter,
        url_schemes={"http", "https"},
        link_rel="noopener noreferrer",
        strip_comments=True,
    )


def protect_document(document: str, *, static: bool = False) -> str:
    """Hash only the renderer's one application script after fragments are clean."""
    scripts = re.findall(r"<script>([\s\S]*?)</script>", document)
    expected = 0 if static else 1
    if len(scripts) != expected or len(re.findall(r"<script\b", document, re.I)) != expected:
        raise RuntimeError("Unexpected report script structure; refusing HTML output.")
    if document.count('<meta charset="utf-8">') != 1:
        raise RuntimeError("Missing report security insertion point; refusing HTML output.")
    script_policy = "'none'"
    if not static:
        digest = base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode()
        script_policy = f"'sha256-{digest}'"
    policy = (
        "default-src 'none'; base-uri 'none'; object-src 'none'; frame-src 'none'; "
        "connect-src 'none'; img-src 'none'; media-src 'none'; form-action 'none'; "
        f"script-src {script_policy}; style-src 'unsafe-inline'"
    )
    meta = '<meta http-equiv="Content-Security-Policy" content="' + escape(policy, quote=True) + '">'
    meta += '\n<meta name="referrer" content="no-referrer">'
    return document.replace('<meta charset="utf-8">', '<meta charset="utf-8">\n' + meta, 1)
