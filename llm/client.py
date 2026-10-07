"""
Provider-agnostic LLM client abstraction.

This module defines a minimal interface for sending prompts to a
language model and receiving text responses.  Concrete
implementations (OpenAI, Anthropic, local models, …) can be added
later without changing any agent code.

Configuration
-------------
LLM_PROVIDER  – selects which backend to use.
                Current values:
                  "echo" (default) – returns a placeholder; no
                                     network call, no API key needed.
                Future values:
                  "openai", "anthropic", "ollama", …

Environment variables specific to each provider (e.g.
OPENAI_API_KEY) are read by the corresponding concrete client, not
by this module.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class BaseLLMClient(ABC):
    """Minimal contract every LLM backend must fulfil."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        """Send *prompt* (with an optional *system_prompt*) and return
        the model's text response.
        """


# ---------------------------------------------------------------------------
# Built-in implementations
# ---------------------------------------------------------------------------

class EchoLLMClient(BaseLLMClient):
    """Fallback client that returns a deterministic placeholder.

    Used when no real provider is configured.  It never makes a
    network call and never requires an API key, which makes it safe
    for CI, smoke tests, and first-run demos.
    """

    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        return 'print("Hello from Echo LLM – no provider configured yet.")'


class MockLLMClient(BaseLLMClient):
    """Returns a fixed response – useful for unit tests.

    Parameters
    ----------
    response:
        The exact string the mock should return on every call.
    calls_log:
        If provided, every ``(prompt, system_prompt)`` pair is
        appended so tests can assert what was sent.
    """

    def __init__(
        self,
        response: str,
        calls_log: list[tuple[str, str | None]] | None = None,
    ) -> None:
        self._response = response
        self.calls_log: list[tuple[str, str | None]] = (
            calls_log if calls_log is not None else []
        )

    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        self.calls_log.append((prompt, system_prompt))
        return self._response


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_llm_client() -> BaseLLMClient:
    """Instantiate the client selected by the ``LLM_PROVIDER`` env var.

    Raises
    ------
    ValueError
        If the requested provider is not (yet) implemented.
    """
    provider = os.getenv("LLM_PROVIDER", "echo").lower()

    if provider == "echo":
        return EchoLLMClient()

    # Future providers go here, e.g.:
    # if provider == "openai":
    #     from llm.openai_client import OpenAILLMClient
    #     return OpenAILLMClient()

    raise ValueError(
        f"Unknown LLM_PROVIDER '{provider}'. "
        f"Supported values: echo (future: openai, anthropic, …)"
    )
