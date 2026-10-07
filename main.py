from orchestrator import run_agents


def main():

    request = input(
        "What Python code do you want to create?\n> "
    )

    state = run_agents(request)

    print("\n========== RESULT ==========")

    print("\nGenerated Code:")
    print(state.code)

    print("\nReview:")
    print(state.review)

    print("\nTest Results:")
    print(state.test_results)

    print("\nErrors:")
    print(state.errors)

    print("\nDebug Attempts:")
    print(state.debug_attempts)

    print("\nFinal Status:")
    print(state.final_status)


if __name__ == "__main__":
    main()
