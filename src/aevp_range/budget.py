"""Budget governor (Oracle Spec section 7).

Adaptive, multi-trial campaigns against a paid endpoint burn tokens fast. The
governor is a correctness-of-cost control, not polish: when the ceiling is hit
the campaign HALTS and reports partial results with a truncation flag, rather
than overrunning silently.
"""
from dataclasses import dataclass, field


class BudgetExceeded(RuntimeError):
    """Raised when a campaign hits its declared ceiling."""


@dataclass
class Budget:
    max_calls: int = 2000
    max_prompt_tokens: int = 2_000_000
    max_completion_tokens: int = 500_000

    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    truncated: bool = field(default=False)

    def charge(self, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        """Record one model call. Raises BudgetExceeded once a ceiling is passed."""
        self.calls += 1
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        if (self.calls > self.max_calls
                or self.prompt_tokens > self.max_prompt_tokens
                or self.completion_tokens > self.max_completion_tokens):
            self.truncated = True
            raise BudgetExceeded(
                f"budget ceiling reached: calls={self.calls}/{self.max_calls} "
                f"prompt={self.prompt_tokens}/{self.max_prompt_tokens} "
                f"completion={self.completion_tokens}/{self.max_completion_tokens}"
            )

    def summary(self) -> dict:
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "truncated": self.truncated,
        }
