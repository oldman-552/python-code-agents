"""Tests for the full agent pipeline and individual agents."""

from agents.coder import coder_agent
from llm.client import MockLLMClient
from state.shared_state import SharedState


SAMPLE_CODE = """
def calculate_sum(numbers):
    return sum(numbers)
""".strip()


def test_calculate_sum():
    """Coder agent produces working code when given a mocked LLM."""
    mock_client = MockLLMClient(response=f"```python\n{SAMPLE_CODE}\n```")

    state = SharedState(
        user_request="اكتب لي كود Python لجمع الأرقام"
    )

    state = coder_agent(state, llm_client=mock_client)

    namespace = {}
    exec(state.code, namespace)

    calculate_sum = namespace["calculate_sum"]

    assert calculate_sum([1, 2, 3]) == 6
    assert calculate_sum([10, 20]) == 30
    assert calculate_sum([]) == 0
    assert calculate_sum([-1, 1]) == 0
