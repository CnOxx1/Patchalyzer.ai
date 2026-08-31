"""Markdown helpers shared by report assembly."""
from __future__ import annotations

import re

_H1_OR_H2 = re.compile(r"^#{1,2}(?!#)\s+", re.M)


def demote_h2(text: str) -> str:
    """Specialist notes must not introduce report-level # / ## headings."""
    return _H1_OR_H2.sub("### ", text or "")
