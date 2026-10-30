class BackdoorWatchError(Exception):
    """Base for errors surfaced to the API with a user-readable message."""


class NotFoundError(BackdoorWatchError):
    pass


class ActionRefusedError(BackdoorWatchError):
    """A safety policy blocked the action (e.g. killing a critical system process)."""


class ActionFailedError(BackdoorWatchError):
    """The operating system rejected the action."""


class CaptureUnavailableError(BackdoorWatchError):
    pass
