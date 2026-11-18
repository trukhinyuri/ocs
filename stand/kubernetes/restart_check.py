#!/usr/bin/env python3
"""Crash and independently observe only the dedicated repository-owned local node."""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deploy import APP, DEFAULT_CONFIG, LABEL, POLICY, Cluster
from local import LABEL as NODE_LABEL
from workload import now_stamp, save


def output(*args, timeout=15):
    return subprocess.check_output(args, text=True, timeout=timeout).strip()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--local-owned-node", action="store_true", required=True)
    options = p.parse_args()
    c = Cluster(DEFAULT_CONFIG, "ocs-local", POLICY["workload"]["namespace"])
    name = POLICY["local"]["container"]
    old = json.loads(output("docker", "inspect", name))[0]
    if (
        old["Config"]["Labels"].get(NODE_LABEL) != "1"
        or old["Config"]["Image"] != POLICY["local"]["image"]
    ):
        raise ValueError("unexpected node ownership or image")
    if (
        old["HostConfig"]["RestartPolicy"]["Name"] != "always"
        or output("systemctl", "is-enabled", "docker") != "enabled"
    ):
        raise ValueError("missing local boot or restart policy")
    pods = json.loads(c.command("get", "pods", "--all-namespaces", "-o", "json").stdout)
    for pod in pods["items"]:
        m = pod["metadata"]
        owned = m["namespace"] == c.namespace and m.get("labels", {}).get(LABEL) == APP
        system = m["namespace"] == "kube-system" and (
            any(
                m["name"].startswith(x)
                for x in ("coredns-", "local-path-provisioner-", "helper-pod-")
            )
            or (
                m["name"].startswith("helm-install-gateway-api-crd-")
                and m.get("labels", {}).get("helmcharts.helm.cattle.io/chart") == "gateway-api-crd"
            )
        )
        if not owned and not system:
            raise ValueError(
                "foreign pod present, control-plane crash requires a separate test cluster"
            )
    cluster_uid = c.get("namespace", "kube-system")["metadata"]["uid"]
    pvc = c.get("pvc", "ocs-provider-data")["metadata"]["uid"]
    # pidfd and cgroup check prevent hitting a reused host PID.
    kill_program = """import os,sys,signal,pathlib
pid=int(sys.argv[1]); fd=os.pidfd_open(pid)
if sys.argv[2] not in pathlib.Path(f'/proc/{pid}/cgroup').read_text(): raise SystemExit('node cgroup mismatch')
signal.pidfd_send_signal(fd,signal.SIGKILL)
os.close(fd)"""
    start = time.monotonic()
    subprocess.run(
        ["sudo", "-n", "python3", "-c", kill_program, str(old["State"]["Pid"]), old["Id"]],
        check=True,
        timeout=10,
    )
    until = start + POLICY["workload"]["recoveryLimitSeconds"]
    while time.monotonic() < until:
        new = json.loads(output("docker", "inspect", name))[0]
        if new["RestartCount"] > old["RestartCount"] and new["State"]["Running"]:
            ready = c.command(
                "--request-timeout=2s", "get", "--raw=/readyz", check=False, timeout=5
            )
            if ready.returncode == 0 and ready.stdout.strip() == b"ok":
                break
        time.sleep(1)
    else:
        raise RuntimeError("node failed to recover under its restart policy")
    c.command("rollout", "status", "deployment/ocs-provider", "--timeout=90s")
    if (
        cluster_uid != c.get("namespace", "kube-system")["metadata"]["uid"]
        or pvc != c.get("pvc", "ocs-provider-data")["metadata"]["uid"]
    ):
        raise ValueError("cluster or persistence identity changed during recovery")
    seconds = time.monotonic() - start
    if seconds > POLICY["workload"]["recoveryLimitSeconds"]:
        raise ValueError("recovery exceeded the approved bound")
    save(
        options.report,
        {
            "status": "pass",
            "scope": "dedicated local node only",
            "clusterUID": cluster_uid,
            "pvcUID": pvc,
            "observedAt": now_stamp(),
            "image": old["Config"]["Image"],
            "node": name,
            "startup": output("systemctl", "is-enabled", "docker"),
            "engineRestart": output("systemctl", "show", "docker", "-p", "Restart", "--value"),
            "nodeRestart": "always",
            "previousRestartCount": old["RestartCount"],
            "newRestartCount": new["RestartCount"],
            "recoverySeconds": seconds,
            "upstreamVersion": json.loads(c.command("get", "--raw=/version").stdout)["gitVersion"],
        },
    )
    print(f"Recovered the isolated node and its original PVC in {seconds:.2f} seconds.")


if __name__ == "__main__":
    main()
