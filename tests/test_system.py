from agents.coder import coder_agent
from state.shared_state import SharedState


def test_calculate_sum():
    state = SharedState(
        user_request="اكتب لي كود Python لجمع الأرقام"
    )

    state = coder_agent(state)

    namespace = {}
    exec(state.code, namespace)

    calculate_sum = namespace["calculate_sum"]

    assert calculate_sum([1, 2, 3]) == 6
    assert calculate_sum([10, 20]) == 30
    assert calculate_sum([]) == 0
