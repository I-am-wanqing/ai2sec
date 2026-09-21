import subprocess
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class SandboxResult:
    tool: str
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str


class SandboxPolicyError(ValueError):
    pass


class DockerSandbox:
    """Safe MVP sandbox facade with allowlisted local commands.

    The class owns the interface expected by agents. A future production build can
    replace `run_terminal` internals with a Docker exec implementation while keeping
    the agent contract stable.
    """

    def __init__(self) -> None:
        self.allowed: Dict[str, List[str]] = {
            "python_runtime": ["python3", "--version"],
            "terminal": ["pwd"],
            "browser": ["python3", "--version"],
            "proxy": ["python3", "--version"],
        }

    def run_terminal(self, tool: str, command: List[str], timeout: int = 10) -> SandboxResult:
        allowed = self.allowed.get(tool)
        if command != allowed:
            raise SandboxPolicyError(f"Command is not allowlisted for tool: {tool}")
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return SandboxResult(
            tool=tool,
            command=command,
            exit_code=completed.returncode,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
        )

    def describe(self) -> Dict[str, str]:
        return {
            "terminal": "allowlisted command execution facade",
            "browser": "reserved browser automation facade",
            "proxy": "reserved HTTP proxy facade",
            "python_runtime": "allowlisted Python runtime facade",
            "mode": "safe-mvp",
        }
