"""Unit tests for the code extraction utility."""

from utils.code_extractor import extract_python_code


class TestExtractPythonCode:

    def test_extracts_python_fenced_block(self):
        text = "Sure!\n```python\ndef hello():\n    return 'hi'\n```\nEnjoy!"
        assert extract_python_code(text) == "def hello():\n    return 'hi'"

    def test_extracts_plain_fenced_block(self):
        text = "```\nx = 42\n```"
        assert extract_python_code(text) == "x = 42"

    def test_returns_raw_when_no_fences(self):
        text = "def add(a, b):\n    return a + b"
        assert extract_python_code(text) == text

    def test_picks_last_block_when_multiple(self):
        text = (
            "```python\nx = 1\n```\n"
            "Wait, better version:\n"
            "```python\nx = 2\n```"
        )
        assert extract_python_code(text) == "x = 2"

    def test_strips_whitespace(self):
        text = "```python\n  x = 1  \n```"
        assert extract_python_code(text) == "x = 1"

    def test_empty_string(self):
        assert extract_python_code("") == ""

    def test_preserves_multiline_code(self):
        code = "def f():\n    x = 1\n    y = 2\n    return x + y"
        text = f"```python\n{code}\n```"
        assert extract_python_code(text) == code

    def test_handles_fences_with_extra_whitespace(self):
        text = "```python   \ndef f():\n    pass\n```"
        result = extract_python_code(text)
        assert "def f():" in result
