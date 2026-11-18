#!/usr/bin/env python3
"""Start the isolated local Kubernetes node and write a private dedicated kubeconfig."""

import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

POLICY = json.loads(Path(__file__).with_name("policy.json").read_text())["local"]
LABEL = "org.ocs.qualification.local"
DEFAULT_CONFIG = (
    Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "ocs/kubernetes/config"
)


def run(*args, check=True, timeout=120):
    return subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, timeout=timeout
    )


def write_config(data, path):
    # Convert the node-owned credential in private storage and never emit it to a log.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
        staged = Path(out.name)
        out.write(data)
    try:
        cfg = json.loads(
            run(
                "kubectl", "--kubeconfig", str(staged), "config", "view", "--raw", "-o", "json"
            ).stdout
        )
        cfg["clusters"][0]["name"] = "ocs-local"
        cfg["clusters"][0]["cluster"]["server"] = f"https://127.0.0.1:{POLICY['port']}"
        cfg["users"][0]["name"] = "ocs-local-admin"
        cfg["contexts"] = [
            {"name": "ocs-local", "context": {"cluster": "ocs-local", "user": "ocs-local-admin"}}
        ]
        cfg["current-context"] = "ocs-local"
        staged.write_text(json.dumps(cfg) + "\n")
        staged.replace(path)
    finally:
        staged.unlink(missing_ok=True)


def start(path, latest):
    if latest:
        with urlopen("https://dl.k8s.io/release/stable.txt", timeout=12) as response:
            upstream = response.read(80).decode().strip()
        if upstream != POLICY["upstream"]:
            raise ValueError(f"review and update the node image pin for upstream {upstream}")
    name = POLICY["container"]
    info = run("docker", "container", "inspect", name, check=False)
    if info.returncode:
        run("docker", "pull", POLICY["image"], timeout=300)
        run(
            "docker",
            "run",
            "-d",
            "--privileged",
            "--restart",
            "always",
            "--name",
            name,
            "--hostname",
            "ocs-qualification",
            "--label",
            LABEL + "=1",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/var/run",
            "--ulimit",
            "nofile=65535:65535",
            "--ulimit",
            "nproc=65535:65535",
            "--volume",
            name + "-data:/var/lib/rancher/k3s",
            "--publish",
            f"127.0.0.1:{POLICY['port']}:6443/tcp",
            POLICY["image"],
            "server",
            "--disable",
            "traefik,servicelb,metrics-server",
            "--tls-san",
            "127.0.0.1",
        )
    else:
        obj = json.loads(info.stdout)[0]
        if obj["Config"]["Labels"].get(LABEL) != "1" or obj["Config"]["Image"] != POLICY["image"]:
            raise ValueError("local node name belongs to a different deployment or revision")
        run("docker", "update", "--restart", "always", name)
        if not obj["State"]["Running"]:
            run("docker", "start", name)
    until = time.monotonic() + 180
    while time.monotonic() < until:
        result = run(
            "docker", "exec", name, "cat", "/etc/rancher/k3s/k3s.yaml", check=False, timeout=10
        )
        if result.returncode == 0 and result.stdout:
            write_config(result.stdout, path)
            ready = run(
                "kubectl",
                "--kubeconfig",
                str(path),
                "--request-timeout=4s",
                "get",
                "--raw=/readyz",
                check=False,
                timeout=8,
            )
            if ready.returncode == 0 and ready.stdout.strip() == b"ok":
                break
        time.sleep(2)
    else:
        raise RuntimeError("local control plane did not become ready")
    k = ["kubectl", "--kubeconfig", str(path), "--context=ocs-local"]
    run(*k, "wait", "--for=condition=Ready", "node", "--all", "--timeout=120s", timeout=130)
    actual = json.loads(run(*k, "get", "--raw=/version").stdout)["gitVersion"]
    if actual.split("+")[0] != POLICY["upstream"]:
        raise ValueError(f"node version {actual} differs from {POLICY['upstream']}")
    print(f"{actual} ready; kubeconfig {path}, context ocs-local")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--verify-latest", action="store_true")
    options = parser.parse_args()
    try:
        start(options.kubeconfig, options.verify_latest)
    except subprocess.CalledProcessError as exc:
        parser.exit(
            1,
            f"local bootstrap failed at {exc.cmd[0]} {exc.cmd[1]}: {exc.stderr.decode(errors='replace')[:420]}\n",
        )
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"local bootstrap failed: {exc}\n")
