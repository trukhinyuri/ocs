"""Independent in-cluster client for the published native provider contract."""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workload import Stand

keys = Path("/var/run/ocs/client")
api = Stand(
    "https://ocs-provider." + os.environ["POD_NAMESPACE"] + ".svc/ocs",
    keys / "ca.crt",
    keys / "probe",
)
desc = api.describe()
result = api.call("provider.describe", {})
print(
    json.dumps(
        {
            "package": desc["packageId"],
            "pin": desc["manifestDigest"],
            "provider": result["provider"],
            "routes": result["routes"],
            "caSha256": api.ca_hash,
            "jsonBytes": api.last_metrics,
            "dns": api.url,
        }
    )
)
