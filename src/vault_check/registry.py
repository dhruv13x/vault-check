from typing import Any, Callable, Dict, List, Optional


class VerifierRegistry:
    """A registry for verifier checks."""

    def __init__(self):
        self.checks: List[Dict[str, Any]] = []

    def add(
        self,
        name: str,
        callable: Callable,
        args: Optional[List[Any]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        is_warn_only: bool = False,
    ):
        """
        Adds a verifier check to the registry.

        Args:
            name: The name of the check.
            callable: The verifier function or method to call.
            args: Positional arguments for the callable.
            kwargs: Keyword arguments for the callable.
            is_warn_only: If True, failures will be treated as warnings.
        """
        self.checks.append(
            {
                "name": name,
                "callable": callable,
                "args": args or [],
                "kwargs": kwargs or {},
                "is_warn_only": is_warn_only,
            }
        )
