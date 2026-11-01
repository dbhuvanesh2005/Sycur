"""Static-analysis fixture. Do not run this file."""

import subprocess


PASSWORD = "SycurWeakPassword_2026"


def calculate_user_expression(user_expression: str):
    # Intentional unsafe-eval finding for Semgrep and Bandit.
    return eval(user_expression)


def run_user_command(user_command: str):
    # Intentional shell-injection pattern for Semgrep and Bandit.
    return subprocess.run(
        user_command,
        shell=True,
        capture_output=True,
        text=True,
    )


def authenticate(candidate: str) -> bool:
    # Intentional hardcoded-password pattern for Bandit.
    return candidate == PASSWORD
