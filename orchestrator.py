from state.shared_state import SharedState

from agents.coder import coder_agent
from agents.reviewer import reviewer_agent
from agents.tester import tester_agent
from agents.debugger import debugger_agent


def run_agents(user_request: str) -> SharedState:

    state = SharedState(
        user_request=user_request
    )

    # 1. Generate code
    state = coder_agent(state)

    # 2. Review code
    state = reviewer_agent(state)

    # 3. Test code
    state = tester_agent(state)

    # 4. Debug and retry if necessary
    while state.errors and state.debug_attempts < 3:

        state = debugger_agent(state)

        # Review the fixed code again
        state = reviewer_agent(state)

        # Test again after debugging
        state = tester_agent(state)

    # Final status
    if state.errors:
        state.final_status = "failed"
    else:
        state.final_status = "success"

    return state
