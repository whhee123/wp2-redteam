"""Container-local JSON-RPC helper used by the Docker Exec transport."""

from __future__ import annotations

import base64
import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m app.rpc_client <base64-request>", file=sys.stderr)
        return 2
    token = os.environ.get("SANDBOX_TOKEN")
    if not token:
        print("SANDBOX_TOKEN is missing", file=sys.stderr)
        return 3
    try:
        body = base64.urlsafe_b64decode(sys.argv[1].encode("ascii"))
        request = urllib.request.Request(
            "http://127.0.0.1:8080/rpc",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Protocol-Version": "1",
                "X-Sandbox-Token": token,
            },
        )
        with urllib.request.urlopen(request, timeout=5.0) as response:
            sys.stdout.buffer.write(response.read(1024 * 1024))
        return 0
    except (ValueError, urllib.error.URLError) as exc:
        print(f"RPC request failed: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
