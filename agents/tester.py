from state.shared_state import SharedState
from tools.python_runner import run_python_code


def tester_agent(state: SharedState) -> SharedState:
    """
    Runs the generated Python code.
    """

    result = run_python_code(state.code)

    state.test_results = result

    if result.startswith("ERROR"):
        state.errors.append(result)

    return state
