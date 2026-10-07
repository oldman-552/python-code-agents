"""
Coder Agent
===========

Receives the user's natural-language request and uses an LLM client
to generate Python code that fulfils it.

The agent is **provider-agnostic**: it talks to whatever backend is
configured via the ``LLM_PROVIDER`` environment variable (see
:mod:`llm.client`).  No paid-provider-specific code lives here.

Dependency injection
--------------------
``coder_agent`` accepts an optional *llm_client* argument.  When
``None`` (the default), the client is created from environment
configuration.  Tests pass a :class:`~llm.client.MockLLMClient`
directly so no network call is ever made.
"""

from __future__ import annotations

from llm.client import BaseLLMClient, create_llm_client
from state.shared_state import SharedState
from utils.code_extractor import extract_python_code

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are an expert Python programmer. "
    "The user will describe what they need in natural language. "
    "Your job is to produce clean, correct, self-contained Python "
    "code that fulfils the request. "
    "Return ONLY the code inside a single fenced ```python … ``` "
    "block. Do not include explanations, comments about your "
    "reasoning, or usage examples outside the code block."
)

USER_PROMPT_TEMPLATE = (
    "Write Python code for the following request:\n\n{request}"
)


# ---------------------------------------------------------------------------
# Agent entry point
# ---------------------------------------------------------------------------

def coder_agent(
    state: SharedState,
    llm_client: BaseLLMClient | None = None,
) -> SharedState:
    """Generate Python code for *state.user_request* using an LLM.

    Parameters
    ----------
    state:
        The shared pipeline state.  ``state.user_request`` is read;
        ``state.code`` is written.
    llm_client:
        Optional pre-built LLM client (useful for testing).
        When ``None`` a client is created from environment
        configuration via :func:`llm.client.create_llm_client`.
    """
    if llm_client is None:
        llm_client = create_llm_client()

    user_prompt = USER_PROMPT_TEMPLATE.format(
        request=state.user_request,
    )

    raw_response = llm_client.generate(
        prompt=user_prompt,
        system_prompt=SYSTEM_PROMPT,
    )

    state.code = extract_python_code(raw_response)

    return state
