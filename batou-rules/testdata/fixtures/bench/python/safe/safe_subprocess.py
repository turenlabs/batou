import subprocess
import shlex
import os
from pathlib import Path

ALLOWED_COMMANDS = {"ls", "df", "uptime", "whoami", "date"}

# SAFE: subprocess with list arguments (no shell=True)
def resize_image(width: int, height: int, input_path: str, output_path: str) -> None:
    if not (1 <= width <= 4096 and 1 <= height <= 4096):
        raise ValueError("Invalid dimensions")
    subprocess.run(
        ["convert", input_path, "-resize", f"{width}x{height}", output_path],
        check=True,
        timeout=30,
    )


# SAFE: Allowlisted command with no user input in command itself
def run_system_command(command_name: str) -> str:
    if command_name not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command_name}")
    result = subprocess.run(
        [command_name], capture_output=True, text=True, timeout=10
    )
    return result.stdout


# SAFE: subprocess.run with explicit argument list
def git_log(repo_path: str, count: int = 10) -> str:
    clean_path = Path(repo_path).resolve()
    if not clean_path.is_dir():
        raise ValueError("Not a valid directory")
    result = subprocess.run(
        ["git", "log", f"--max-count={count}", "--oneline"],
        cwd=str(clean_path),
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout


# SAFE: Hardcoded command with no user input
def get_disk_usage() -> str:
    result = subprocess.run(
        ["df", "-h"], capture_output=True, text=True, timeout=5
    )
    return result.stdout
