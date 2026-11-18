#!/usr/bin/python3 -I
"""Git remote helper dispatcher for independently installed local OCS receivers."""

import os
import re
import sys
from pathlib import Path

CLIENT_ROOT = Path("/usr/local/libexec/ocs-safe-push")
INSTANCE = re.compile(r"[a-z][a-z0-9-]{0,22}")


def dispatch(args, client_root=CLIENT_ROOT):
    # Git supplies the remote name and the address after 'ocs::'. The remote
    # name is display metadata; only a valid instance can select an installation.
    if len(args) != 2 or not INSTANCE.fullmatch(args[1]):
        raise ValueError("expected an OCS remote address of the form ocs::INSTANCE")
    instance = args[1]
    client = client_root / instance / "socket_client.py"
    os.execv(
        "/usr/bin/python3",
        ["/usr/bin/python3", "-I", "-B", str(client), "--git-helper", instance],
    )


if __name__ == "__main__":
    try:
        dispatch(sys.argv[1:])
    except (OSError, ValueError) as exc:
        print("OCS Git remote: " + str(exc), file=sys.stderr)
        sys.exit(1)
