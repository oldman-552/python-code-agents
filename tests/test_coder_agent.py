"""
Unit tests for the Coder Agent.

All tests use a MockLLMClient so no real API calls are made.
"""

import pytest

from agents.coder import coder_agent, SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from llm.client import MockLLMClient
from state.shared_state import SharedState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_state(request: str = "write a function that adds two numbers") -> SharedState:
    return SharedState(user_request=request)


# ---------------------------------------------------------------------------
# Core behaviour
# ---------------------------------------------------------------------------

class TestCoderAgentBasic:
    """Verify that the agent produces valid code from an LLM response."""

    def test_extracts_code_from_fenced_block(self):
        raw = "Here you go:\n```python\ndef add(a, b):\n    return a + b\n```\nDone!"
        client = MockLLMClient(response=raw)
        state = coder_agent(_make_state(), llm_client=client)

        assert "def add(a, b):" in state.code
        assert "return a + b" in state.code
        # Should NOT contain the surrounding prose
        assert "Here you go" not in state.code
        assert "Done!" not in state.code

    def test_extracts_code_from_plain_fenced_block(self):
        """Fenced block without the 'python' language tag."""
        raw = "```\ndef hello():\n    return 'hi'\n```"
        client = MockLLMClient(response=raw)
        state = coder_agent(_make_state(), llm_client=client)

        assert "def hello():" in state.code
        assert "return 'hi'" in state.code

    def test_returns_raw_text_when_no_fences(self):
        raw = "def greet():\n    return 'hello'"
        client = MockLLMClient(response=raw)
        state = coder_agent(_make_state(), llm_client=client)

        assert state.code == raw.strip()

    def test_handles_any_user_request(self):
        """No hardcoded keywords — arbitrary requests are forwarded to the LLM."""
        expected = "def fibonacci(n):\n    if n <= 1: return n\n    return fibonacci(n-1) + fibonacci(n-2)"
        client = MockLLMClient(response=f"```python\n{expected}\n```")

        state = coder_agent(_make_state("generate a fibonacci function"), llm_client=client)

        assert "fibonacci" in state.code
        assert state.code == expected

    def test_arabic_request(self):
        expected = "def calculate_sum(numbers):\n    return sum(numbers)"
        client = MockLLMClient(response=f"```python\n{expected}\n```")

        state = coder_agent(
            _make_state("اكتب لي كود Python لجمع الأرقام"),
            llm_client=client,
        )

        assert "calculate_sum" in state.code

    def test_state_other_fields_untouched(self):
        """Agent should only write state.code, not other fields."""
        client = MockLLMClient(response="```python\nx = 1\n```")
        state = _make_state()
        state.review = "original review"
        state.test_results = "original test results"
        state.final_status = "pending"

        coder_agent(state, llm_client=client)

        assert state.review == "original review"
        assert state.test_results == "original test results"
        assert state.final_status == "pending"


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

class TestCoderAgentPrompts:
    """Verify the correct prompt is sent to the LLM."""

    def test_user_request_is_included_in_prompt(self):
        calls = []
        client = MockLLMClient(response="x = 1", calls_log=calls)
        request = "build a REST API with Flask"

        coder_agent(_make_state(request), llm_client=client)

        assert len(calls) == 1
        prompt_sent, _ = calls[0]
        assert request in prompt_sent

    def test_system_prompt_is_passed(self):
        calls = []
        client = MockLLMClient(response="x = 1", calls_log=calls)

        coder_agent(_make_state(), llm_client=client)

        _, system_sent = calls[0]
        assert system_sent == SYSTEM_PROMPT

    def test_system_prompt_instructs_code_only(self):
        """The system prompt should ask for code, not prose."""
        assert "code" in SYSTEM_PROMPT.lower()
        assert "python" in SYSTEM_PROMPT.lower()


# ---------------------------------------------------------------------------
# Default client fallback
# ---------------------------------------------------------------------------

class TestCoderAgentDefaultClient:
    """When no client is injected, the agent uses the env-based factory."""

    def test_uses_echo_client_by_default(self, monkeypatch):
        """With no LLM_PROVIDER set, the EchoLLMClient is used."""
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        state = _make_state("anything")
        result = coder_agent(state)

        # Echo client returns a valid Python snippet
        assert result.code  # non-empty
        # It should be parseable Python
        compile(result.code, "<echo>", "exec")

    def test_raises_for_unknown_provider(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "nonexistent")
        with pytest.raises(ValueError, match="Unknown LLM_PROVIDER"):
            coder_agent(_make_state())


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestCoderAgentEdgeCases:
    def test_empty_llm_response(self):
        client = MockLLMClient(response="")
        state = coder_agent(_make_state(), llm_client=client)
        assert state.code == ""

    def test_multiple_fenced_blocks_picks_last(self):
        """If the model outputs multiple blocks, we take the last one."""
        raw = (
            "```python\nx = 1\n```\n"
            "And here's the corrected version:\n"
            "```python\ndef real():\n    return 42\n```"
        )
        client = MockLLMClient(response=raw)
        state = coder_agent(_make_state(), llm_client=client)

        assert "def real():" in state.code
        assert "x = 1" not in state.code

    def test_llm_called_exactly_once(self):
        calls = []
        client = MockLLMClient(response="x = 1", calls_log=calls)
        coder_agent(_make_state(), llm_client=client)

        assert len(calls) == 1
