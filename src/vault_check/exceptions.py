class VerificationError(Exception):
    """
    Exception raised when a verification check fails.

    Attributes:
        message (str): The failure message.
        fix_suggestion (str | None): An actionable suggestion to fix the issue.
    """
    def __init__(self, message: str, fix_suggestion: str | None = None):
        self.message = message
        self.fix_suggestion = fix_suggestion
        super().__init__(message)
