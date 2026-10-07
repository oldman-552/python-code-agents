from dataclasses import dataclass, field


@dataclass
class SharedState:
    user_request: str

    code: str = ""

    review: str = ""

    test_results: str = ""

    errors: list[str] = field(default_factory=list)

    debug_attempts: int = 0

    final_status: str = "pending"
