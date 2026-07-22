"""Re-export the canonical protocol used by both host and container.

Tests import the source package directly. The Docker image copies the same
source file to ``shared_protocol.py`` during its build.
"""

try:  # Host-side tests (``src`` is on PYTHONPATH).
    from sandbox.protocol import *  # noqa: F403
except ModuleNotFoundError:  # Runtime image.
    from shared_protocol import *  # type: ignore[no-redef]  # noqa: F403

