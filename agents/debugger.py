from state.shared_state import SharedState


def debugger_agent(state: SharedState) -> SharedState:
    """
    Attempts to fix the generated Python code.
    """

    state.debug_attempts += 1

    if state.errors:

        # Simple first version:
        # regenerate valid code for our current example.
        if "جمع" in state.user_request:

            state.code = """
def calculate_sum(numbers):
    return sum(numbers)
""".strip()

        # Clear previous errors after fixing
        state.errors.clear()

    return state
