#!/usr/bin/env python3
"""Generate inert, offline input-boundary probes for authorized lab validation.

This utility does not send requests, execute commands, or accept arbitrary
payload text. The catalog intentionally excludes exploit and WAF-bypass strings.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import quote

ALL_CATEGORIES = ("xss", "sqli", "command")
ENCODINGS = ("none", "url", "base64", "hex", "unicode")
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{4,32}\Z")

# Delimiter/canary probes only. No executable JavaScript, SQL logic, or shell
# commands are included. The custom HTML element has no active attributes.
_PROBES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "xss": (
        (
            "html-custom-element",
            "<safe-canary>{token}</safe-canary>",
            "Inert custom element for checking HTML output encoding; no script or event handler.",
        ),
        (
            "html-special-characters",
            "'{token}\"&<>",
            "Special-character canary for checking context-aware output encoding.",
        ),
    ),
    "sqli": (
        (
            "single-quote-boundary",
            "{token}'",
            "Single-quote boundary probe; no SQL operator, comment, union, or timing logic.",
        ),
        (
            "double-quote-boundary",
            '{token}\"',
            "Double-quote boundary probe; no SQL operator, comment, union, or timing logic.",
        ),
        (
            "closing-parenthesis-boundary",
            "{token})",
            "Closing-parenthesis boundary probe only; no query logic.",
        ),
        (
            "backslash-boundary",
            "{token}\\",
            "Backslash boundary probe only; no query logic.",
        ),
    ),
    "command": (
        (
            "semicolon-boundary",
            "{token};",
            "Trailing shell metacharacter probe only; no command follows it.",
        ),
        (
            "and-boundary",
            "{token}&&",
            "Trailing shell metacharacter probe only; no command follows it.",
        ),
        (
            "pipe-boundary",
            "{token}|",
            "Trailing shell metacharacter probe only; no command follows it.",
        ),
    ),
}


def encode_value(value: str, encoding: str = "none") -> str:
    """Encode a built-in inert probe string using a named representation."""
    if not isinstance(value, str):
        raise ValueError("value must be text")
    if encoding not in ENCODINGS:
        raise ValueError(f"unsupported encoding: {encoding}")
    if encoding == "none":
        return value
    if encoding == "url":
        return quote(value, safe="")
    if encoding == "base64":
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    if encoding == "hex":
        return value.encode("utf-8").hex()
    # Escape each code point explicitly so the output is portable ASCII.
    return "".join(f"\\u{ord(char):04x}" for char in value)


def generate_cases(
    category: str,
    encoding: str = "none",
    token: str | None = None,
) -> list[dict[str, object]]:
    """Return fixed probes for one category; never accepts arbitrary payloads."""
    if category not in ALL_CATEGORIES:
        raise ValueError(f"unsupported category: {category}")
    if token is None:
        token = secrets.token_hex(4)
    if not isinstance(token, str) or _TOKEN_PATTERN.fullmatch(token) is None:
        raise ValueError("token must be 4-32 ASCII letters, digits, '_' or '-'")

    cases: list[dict[str, object]] = []
    for case_id, template, purpose in _PROBES[category]:
        source = template.format(token=token)
        cases.append(
            {
                "category": category,
                "id": case_id,
                "token": token,
                "input": encode_value(source, encoding),
                "encoding": encoding,
                "purpose": purpose,
                "requires_authorized_lab": True,
            }
        )
    return cases


def render_cases(cases: list[dict[str, object]], output_format: str = "text") -> str:
    """Render generated cases as readable text or JSON."""
    if output_format == "json":
        return json.dumps(cases, ensure_ascii=False, indent=2) + "\n"
    if output_format != "text":
        raise ValueError(f"unsupported output format: {output_format}")

    sections = []
    for case in cases:
        sections.append(
            "\n".join(
                (
                    f"[{str(case['category']).upper()}] {case['id']}",
                    f"  input:   {case['input']}",
                    f"  encoding: {case['encoding']}",
                    f"  purpose: {case['purpose']}",
                    "  scope:   authorized lab only",
                )
            )
        )
    return "\n\n".join(sections) + ("\n" if sections else "")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate fixed, inert input-boundary probes for offline/authorized lab validation. "
            "No network requests or command execution are performed."
        )
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--xss", dest="category", action="store_const", const="xss")
    selection.add_argument("--sqli", dest="category", action="store_const", const="sqli")
    selection.add_argument("--command", "--cmd", dest="category", action="store_const", const="command")
    selection.add_argument("--all", dest="category", action="store_const", const="all")
    parser.set_defaults(category="all")
    parser.add_argument(
        "--encode",
        "--encoding",
        choices=ENCODINGS,
        default="none",
        help="representation for the fixed probe strings (default: none)",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path, help="write to a new file; existing files are never overwritten")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    categories = ALL_CATEGORIES if args.category == "all" else (args.category,)
    token = secrets.token_hex(4)
    cases = [
        case
        for category in categories
        for case in generate_cases(category, encoding=args.encode, token=token)
    ]
    output = render_cases(cases, args.format)

    if args.output is None:
        sys.stdout.write(output)
        return 0

    try:
        if args.output.exists() or args.output.is_symlink():
            parser.error(f"refusing to overwrite existing file: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8", newline="\n")
    except OSError as exc:
        parser.error(f"could not write output: {exc}")
    print(f"Wrote {len(cases)} case(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
