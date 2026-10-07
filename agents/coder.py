from state.shared_state import SharedState


def coder_agent(state: SharedState) -> SharedState:
    """
    Generates Python code based on the user's request.
    """

    if "جمع" in state.user_request:
        state.code = """
def calculate_sum(numbers)
    return sum(numbers)
""".strip()

    else:
        state.code = """
def hello():
    return "Hello from Python Agent"
""".strip()

    return state
