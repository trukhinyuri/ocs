"""Start the ordinary session/stream executor behind the pod's authenticated API tunnel."""

import json
import os
import sys
from pathlib import Path

keys = Path("/var/run/ocs/interaction")
os.environ["OCS_FIXTURE_IDENTITIES"] = json.dumps(
    {
        (keys / "probe").read_text().strip(): {"owner": "alice", "admin": False},
        (keys / "other").read_text().strip(): {"owner": "bob", "admin": False},
    }
)
os.execv(
    sys.executable,
    [
        sys.executable,
        "-E",
        "-s",
        "/app/reference/interaction/server.py",
        "--database",
        "/data/interaction.sqlite",
        "--port",
        "17539",
    ],
)
