from __future__ import annotations

from dataclasses import dataclass
import shlex
import subprocess
from typing import Sequence


@dataclass(frozen=True)
class CommandResult:
    """The observable result of one external command."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0


class CommandRunner:
    """Run commands without invoking a shell.

    Keeping this boundary small makes system operations auditable and easy to
    replace with a fake runner in tests.
    """

    def run(self, args: Sequence[str], *, timeout: float = 10) -> CommandResult:
        completed = subprocess.run(
            tuple(args),
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        return CommandResult(
            args=tuple(args),
            returncode=completed.returncode,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
        )


def render_command(args: Sequence[str]) -> str:
    """Render an argv sequence for humans without making it executable."""

    return shlex.join(args)
