import ast

from state.shared_state import SharedState


def reviewer_agent(state: SharedState) -> SharedState:
    """
    Reviews the generated Python code.
    """

    try:
        ast.parse(state.code)

        state.review = "Code syntax is valid."

    except SyntaxError as error:
        state.review = f"Syntax error: {error}"
        state.errors.append(str(error))

    return state
