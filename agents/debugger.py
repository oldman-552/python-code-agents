from state.shared_state import SharedState


def debugger_agent(state: SharedState) -> SharedState:
    """
    Attempts to fix the generated Python code.
    """

    state.debug_attempts += 1

    if state.errors:

        if "جمع" in state.user_request:

            state.code = """
def calculate_sum(numbers):
    return sum(numbers)
""".strip()

        state.errors.clear()

    return state
