"""Policy constants used by controlled tools."""

from sandbox.versions import POLICY_VERSION as POLICY_VERSION

__all__ = [
    "MAX_COMMAND_LENGTH",
    "MAX_FILE_BYTES",
    "POLICY_VERSION",
    "VIRTUAL_ROOT",
]

VIRTUAL_ROOT = "/workspace"
MAX_FILE_BYTES = 64 * 1024
MAX_COMMAND_LENGTH = 4_096
