"""Source-neutral error contracts used by retrieval and evidence publication."""


class SourceError(RuntimeError):
    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable
