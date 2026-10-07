import subprocess
import sys
import tempfile

from state.shared_state import SharedState


def tester_agent(state: SharedState) -> SharedState:
    """
    Tests the exact code stored in SharedState.
    """

    test_code = f"""
{state.code}


def test_calculate_sum():
    assert calculate_sum([1, 2, 3]) == 6
    assert calculate_sum([10, 20]) == 30
    assert calculate_sum([]) == 0
    assert calculate_sum([-1, 1]) == 0
"""

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix="_test.py",
            delete=False
        ) as file:

            file.write(test_code)
            test_file = file.name

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                test_file,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        state.test_results = result.stdout + result.stderr

        if result.returncode != 0:
            state.errors.append(state.test_results)

    except subprocess.TimeoutExpired:
        state.test_results = "ERROR: Tests timed out."
        state.errors.append(state.test_results)

    except Exception as error:
        state.test_results = f"ERROR: {error}"
        state.errors.append(state.test_results)

    return state
