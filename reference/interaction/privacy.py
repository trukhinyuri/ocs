"""An owner-partitioned, time-bounded participant state and diagnostic store."""

import time
from threading import Event, RLock, Thread

from state import Refusal


class PrivateObservations:
    REGION = "local-cell"

    def __init__(self, stamp):
        self.stamp = stamp
        self.lock = RLock()
        self.states = {}
        self.diagnostics = {}
        self.closed = Event()
        self.worker = Thread(target=self.sweep, name="ocs-retention", daemon=True)
        self.worker.start()

    def purge(self):
        tick = time.monotonic()
        for store in (self.states, self.diagnostics):
            for key, row in list(store.items()):
                if row["until"] <= tick:
                    del store[key]

    def sweep(self):
        while not self.closed.wait(0.05):
            with self.lock:
                self.purge()

    def close(self):
        self.closed.set()
        self.worker.join(timeout=1)

    def operate(self, owner, epoch, action, data):
        if owner != data["owner"]:
            raise Refusal("denied", "Private records belong to a different tenant.")
        key = (owner, data["key"])
        with self.lock:
            if action != "counts":
                self.purge()
            if action == "save":
                if key not in self.states and sum(k[0] == owner for k in self.states) >= 32:
                    raise Refusal("busy", "Private record capacity exhausted.")
                until = time.monotonic() + data["retentionMs"] / 1000
                common = {"until": until, "visible": True}
                self.states[key] = {**common, "value": data["value"]}
                self.diagnostics[key] = {
                    **common,
                    "value": {
                        "tenant": owner,
                        "operation": "example.privacy.save",
                        "revision": "1.0.0",
                        "grantEpoch": epoch,
                        "observedAt": self.stamp(time.time()),
                        "decision": "admitted",
                        "region": self.REGION,
                    },
                }
                return {"accepted": True}
            if action == "counts":
                return {
                    "states": int(key in self.states),
                    "diagnostics": int(key in self.diagnostics),
                    "region": self.REGION,
                    "sweepMs": 50,
                }
            state = self.states.get(key)
            if not state:
                raise Refusal("denied", "The scoped retention interval has elapsed.")
            if action == "withdraw":
                state["visible"] = self.diagnostics[key]["visible"] = False
                return {"accepted": True}
            if not state["visible"]:
                raise Refusal("denied", "Subject withdrew access to this record.")
            return {
                "value": state["value"],
                "diagnostic": self.diagnostics[key]["value"],
                "region": self.REGION,
            }
