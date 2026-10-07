import subprocess
import sys
import tempfile


def run_python_code(code: str) -> str:
    """
    Runs Python code in a temporary file.
    """

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False
        ) as file:

            file.write(code)
            file_path = file.name

        result = subprocess.run(
            [sys.executable, file_path],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return f"ERROR: {result.stderr}"

        return result.stdout or "Code executed successfully."

    except subprocess.TimeoutExpired:
        return "ERROR: Code execution timed out."

    except Exception as error:
        return f"ERROR: {error}"
