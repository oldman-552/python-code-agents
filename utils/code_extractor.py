"""
Utility helpers shared across agents.
"""

from __future__ import annotations

import re


def extract_python_code(text: str) -> str:
    """Extract Python code from an LLM response.

    Handles the common case where the model wraps code inside a
    fenced code block (```python … ```).  If no fenced block is
    found the raw text is returned as-is (trimmed).
    """
    # Try fenced blocks first (```python … ``` or ``` … ```)
    pattern = r"```(?:python)?\s*\n(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    if matches:
        return matches[-1].strip()

    return text.strip()
