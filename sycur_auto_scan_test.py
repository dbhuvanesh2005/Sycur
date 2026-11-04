import subprocess


def search_logs(user_input: str):
    command = f"grep {user_input} app.log"

    return subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
    )
