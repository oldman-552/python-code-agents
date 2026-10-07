"""Unit tests for the LLM client abstraction."""

import pytest

from llm.client import BaseLLMClient, EchoLLMClient, MockLLMClient, create_llm_client


class TestEchoLLMClient:

    def test_returns_valid_python(self):
        client = EchoLLMClient()
        result = client.generate("anything")
        compile(result, "<echo>", "exec")

    def test_accepts_system_prompt(self):
        client = EchoLLMClient()
        result = client.generate("prompt", system_prompt="system")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_is_base_llm_client(self):
        assert isinstance(EchoLLMClient(), BaseLLMClient)


class TestMockLLMClient:

    def test_returns_configured_response(self):
        client = MockLLMClient(response="def foo(): pass")
        assert client.generate("prompt") == "def foo(): pass"

    def test_logs_calls(self):
        log = []
        client = MockLLMClient(response="x", calls_log=log)

        client.generate("first prompt", system_prompt="sys1")
        client.generate("second prompt")

        assert len(log) == 2
        assert log[0] == ("first prompt", "sys1")
        assert log[1] == ("second prompt", None)

    def test_ignores_shared_log_when_none(self):
        client = MockLLMClient(response="x")
        result = client.generate("p")
        assert result == "x"
        # Internal log exists but wasn't provided externally
        assert len(client.calls_log) == 1

    def test_is_base_llm_client(self):
        assert isinstance(MockLLMClient(response="x"), BaseLLMClient)


class TestCreateLLMClient:

    def test_default_returns_echo(self, monkeypatch):
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        client = create_llm_client()
        assert isinstance(client, EchoLLMClient)

    def test_echo_explicit(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "echo")
        client = create_llm_client()
        assert isinstance(client, EchoLLMClient)

    def test_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "ECHO")
        client = create_llm_client()
        assert isinstance(client, EchoLLMClient)

    def test_unknown_provider_raises(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "magic")
        with pytest.raises(ValueError, match="Unknown LLM_PROVIDER"):
            create_llm_client()
