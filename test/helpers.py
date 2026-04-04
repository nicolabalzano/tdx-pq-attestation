from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
GUEST_ROOT = ROOT / "confidential-computing.tdx.tdx-guest"
DCAP_ROOT = ROOT / "confidential-computing.tee.dcap"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def assert_contains_all(text: str, patterns: list[str]) -> None:
    missing = [pattern for pattern in patterns if pattern not in text]
    if missing:
        raise AssertionError(f"Missing expected patterns: {missing}")


def extract_block(text: str, anchor: str, lookahead: str) -> str:
    pattern = re.compile(rf"{re.escape(anchor)}(?P<body>.*?)(?={lookahead})", re.S)
    match = pattern.search(text)
    if not match:
        raise AssertionError(f"Could not extract block starting at {anchor!r}")
    return anchor + match.group("body")
