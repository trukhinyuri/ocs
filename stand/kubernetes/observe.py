#!/usr/bin/env python3
"""Qualify a live, explicitly bound Kubernetes workload including failure recovery."""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import secrets
import selectors
import ssl
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from urllib import error, request

HERE = Path(__file__).resolve().parent
SUBJECT = Path(os.environ.get("OCS_SUBJECT_ROOT", HERE.parents[1])).resolve()
sys.path.insert(0, str(HERE))
from deploy import APP, DEFAULT_CONFIG, LABEL, POLICY, Cluster, image_inputs
from oci import accepted_ids
from workload import NoRedirect, Stand, now_stamp, save

LIMITS = POLICY["workload"]


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


@contextmanager
def forward(cluster, port=None, resource="service/ocs-provider", destination=443, target_port=8443):
    arg = (str(port) if port else "") + ":" + str(destination)
    process = subprocess.Popen(
        [*cluster.cmd, "port-forward", "--address=127.0.0.1", resource, arg],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(12):
                raise ValueError("API port-forward was not ready")
            line = process.stdout.readline().strip()
            match = re.fullmatch(
                r"Forwarding from 127\.0\.0\.1:([0-9]+) -> " + str(target_port), line
            )
            require(match, "unexpected API port-forward result")
            yield int(match.group(1))
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()


def pods(cluster, app="ocs-provider"):
    obj = json.loads(
        cluster.command("get", "pod", "-l", "app.kubernetes.io/name=" + app, "-o", "json").stdout
    )
    return [
        p
        for p in obj["items"]
        if not p["metadata"].get("deletionTimestamp")
        and any(
            c["type"] == "Ready" and c["status"] == "True"
            for c in p.get("status", {}).get("conditions", [])
        )
    ]


def read_http(url, ca, token=None):
    context = ssl.create_default_context(cafile=str(ca))
    headers = {"Authorization": "Bearer " + token} if token else {}
    opener = request.build_opener(
        request.ProxyHandler({}), request.HTTPSHandler(context=context), NoRedirect()
    )
    with opener.open(request.Request(url, headers=headers), timeout=5) as result:
        return result.status, result.read(1_048_577)


def job_read(cluster, image):
    name = "ocs-observe-" + secrets.token_hex(5)
    pod = {
        "metadata": {"labels": {LABEL: APP}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65532,
                "runAsGroup": 65532,
                "fsGroup": 65532,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "volumes": [
                {
                    "name": "keys",
                    "secret": {
                        "secretName": "ocs-service-identity",
                        "defaultMode": 288,
                        "items": [
                            {"key": "ca.crt", "path": "ca.crt"},
                            {"key": "probe", "path": "probe"},
                        ],
                    },
                }
            ],
            "containers": [
                {
                    "name": "independent-client",
                    "image": image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "-I", "/app/stand/kubernetes/incluster.py"],
                    "env": [{"name": "POD_NAMESPACE", "value": cluster.namespace}],
                    "securityContext": {
                        "readOnlyRootFilesystem": True,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "volumeMounts": [
                        {"name": "keys", "mountPath": "/var/run/ocs/client", "readOnly": True}
                    ],
                }
            ],
        },
    }
    obj = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "namespace": cluster.namespace, "labels": {LABEL: APP}},
        "spec": {
            "activeDeadlineSeconds": 90,
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": 300,
            "template": pod,
        },
    }
    cluster.command("create", "-f", "-", data=json.dumps(obj).encode())
    cluster.command("wait", "--for=condition=complete", "job/" + name, "--timeout=95s", timeout=105)
    observation = json.loads(cluster.command("logs", "job/" + name).stdout)
    require(
        observation["dns"] == "https://ocs-provider." + cluster.namespace + ".svc/ocs",
        "in-cluster destination changed",
    )
    return {"jobUID": cluster.get("job", name)["metadata"]["uid"], **observation}


def actual_inputs(cluster, pod, declared):
    # Challenge the bytes in the running container independently of its declared image label.
    expected = image_inputs(SUBJECT)
    require(expected == declared, "incomplete or stale submitted build input inventory")
    code = "import hashlib,json,pathlib,sys; print(json.dumps({n:hashlib.sha256((pathlib.Path('/app')/n).read_bytes()).hexdigest() for n in json.load(sys.stdin)}))"
    got = json.loads(
        cluster.command(
            "exec",
            "-i",
            pod,
            "-c",
            "provider",
            "--",
            "python",
            "-I",
            "-c",
            code,
            data=json.dumps(list(expected)).encode(),
        ).stdout
    )
    require(got == expected, "running container source differs from requested subject")
    return hashlib.sha256(
        json.dumps(got, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def timed_cancel(port, token):
    sys.path.insert(0, str(HERE.parents[1] / "reference/interaction"))
    from client import Caller

    caller = Caller(f"http://127.0.0.1:{port}/ocs", token)
    caller.describe()
    rid = secrets.token_hex(16)
    connection, response = caller.stream(rid, credit=1, seconds=5)
    try:
        tag, first = caller.sse(response)
        require(
            tag == "chunk" and first["params"]["seq"] == 1 and first["params"]["requestId"] == rid,
            "missing first stream chunk",
        )
        begin = time.monotonic_ns()
        require(
            caller.notify("ocs.cancel", {"requestId": rid}) == 204,
            "stream cancellation was not admitted",
        )
        tag, terminal = caller.sse(response)
        require(
            tag == "response"
            and terminal["id"] == rid
            and terminal["error"]["data"]["kind"] == "cancelled"
            and caller.sse(response) is None,
            "wrong or repeated terminal outcome",
        )
        return {
            "requestId": rid,
            "receivedChunks": 1,
            "accepted": 204,
            "terminalCode": terminal["error"]["code"],
            "elapsedMs": (time.monotonic_ns() - begin) / 1e6,
            "transport": "Kubernetes authenticated API tunnel to actual stream executor",
        }
    finally:
        connection.close()


def qualify(cluster, deploy, output, browser=True):
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "scope": "owner-selected live Kubernetes stand",
        "checks": [],
        "observedAt": now_stamp(),
        "status": "fail",
    }

    def record(id, claims, data):
        report["checks"].append(
            {
                "id": id,
                "level": "deployment",
                "claims": claims,
                "status": "pass",
                "observedAt": now_stamp(),
                "observed": data,
            }
        )

    try:
        require(
            (deploy["namespace"], deploy["context"]) == (cluster.namespace, cluster.context),
            "stand binding differs",
        )
        api = json.loads(cluster.command("get", "--raw=/version").stdout)
        cluster_uid = cluster.get("namespace", "kube-system")["metadata"]["uid"]
        service = cluster.owned("service", "ocs-provider")
        deployment = cluster.owned("deployment", "ocs-provider")
        (prior,) = pods(cluster)
        require(
            cluster_uid == deploy["clusterUID"]
            and service["metadata"]["uid"] == deploy["serviceUID"]
            and deployment["metadata"]["uid"] == deploy["deploymentUID"],
            "Kubernetes owner binding changed",
        )
        require(
            deployment["spec"]["template"]["spec"]["containers"][0]["image"] == deploy["image"],
            "bound OCI digest changed",
        )
        declared = image_inputs(SUBJECT)
        require(deploy["inputs"] == declared, "incomplete or stale deployed source inventory")
        actual_revision = subprocess.check_output(
            ["git", "-C", str(SUBJECT), "rev-parse", "HEAD"], text=True
        ).strip()
        require(
            deploy["sourceRevision"] == actual_revision,
            "deployment revision differs from qualified checkout",
        )
        relay_dep = cluster.owned("deployment", "ocs-relay")
        relay_svc = cluster.owned("service", "ocs-relay")
        (relay,) = pods(cluster, "ocs-relay")
        require(
            relay_dep["metadata"]["uid"] == deploy["relayDeploymentUID"]
            and relay_svc["metadata"]["uid"] == deploy["relayServiceUID"],
            "relay authority changed",
        )

        def check_owner(pod, controller):
            ref = next(x for x in pod["metadata"]["ownerReferences"] if x.get("controller"))
            require(ref["kind"] == "ReplicaSet", "unexpected pod controller")
            rs = cluster.get("replicaset", ref["name"])
            require(
                rs["metadata"]["uid"] == ref["uid"]
                and any(
                    x.get("controller") and x["uid"] == controller["metadata"]["uid"]
                    for x in rs["metadata"]["ownerReferences"]
                ),
                "pod belongs to another deployment",
            )
            require(
                all(c["image"] == deploy["image"] for c in pod["spec"]["containers"]),
                "unbound container image in pod",
            )
            ids = {c["name"]: c["imageID"] for c in pod["status"]["containerStatuses"]}
            require(
                ids and all(re.search(r"sha256:[0-9a-f]{64}", v) for v in ids.values()),
                "missing resolved image ID",
            )
            node = cluster.get("node", pod["spec"]["nodeName"])
            arch = node["status"]["nodeInfo"]["architecture"]
            permitted = accepted_ids(deploy["image"], deploy["ociManifests"], arch)
            if any(v.split("@")[-1].split("://")[-1] not in permitted for v in ids.values()):
                raise ValueError("runtime image ID is not in the authenticated OCI manifest")
            return ids

        old_images = check_owner(prior, deployment)
        check_owner(relay, relay_dep)
        evidence_sha = actual_inputs(cluster, prior["metadata"]["name"], declared)
        binary = (
            cluster.command(
                "exec",
                prior["metadata"]["name"],
                "-c",
                "provider",
                "--",
                "sha256sum",
                "/usr/local/bin/ocs-go",
            )
            .stdout.decode()
            .split()[0]
        )
        executable = cluster.command(
            "exec",
            prior["metadata"]["name"],
            "-c",
            "provider",
            "--",
            "/usr/local/bin/ocs-go",
            "--manifest",
            "/app/examples/status/ocs.json",
            "--resource",
            "demo",
        )
        require(
            re.fullmatch("([0-9a-f]{64})", binary)
            and json.loads(executable.stdout) == {"resourceId": "demo", "state": "ready"},
            "live Go executable failed the published read",
        )
        volume = cluster.owned("pvc", "ocs-provider-data")
        report["target"] = {
            "apiVersion": api["gitVersion"],
            "clusterUID": cluster_uid,
            "serviceUID": deploy["serviceUID"],
            "namespace": cluster.namespace,
            "image": deploy["image"],
            "imageID": prior["status"]["containerStatuses"][0]["imageID"],
            "sourceRevision": deploy["sourceRevision"],
            "inputSha256": evidence_sha,
            "pvcUID": volume["metadata"]["uid"],
            "goExecutableSha256": binary,
            "actualOCIIdentities": old_images,
            "relayPodUID": relay["metadata"]["uid"],
            "relayServiceUID": deploy["relayServiceUID"],
        }
        keys = cluster.owned("secret", "ocs-service-identity")["data"]
        for field, filename in (
            ("standCaSha256", "ca.crt"),
            ("serverCertificateSha256", "tls.crt"),
            ("relayCertificateSha256", "relay.crt"),
        ):
            actual = hashlib.sha256(base64.b64decode(keys[filename], validate=True)).hexdigest()
            require(actual == deploy[field], "TLS origin changed since deployment: " + field)
            report["target"][field] = actual

        with tempfile.TemporaryDirectory() as tmp:
            files = Path(tmp)
            for name in ("probe", "other", "relay-client", "relay-upstream", "ca.crt", "tls.crt"):
                (files / name).write_bytes(base64.b64decode(keys[name], validate=True))
                (files / name).chmod(0o600)
            expected_pin = hashlib.sha256(
                (SUBJECT / "reference/provider/ocs.json").read_bytes()
            ).hexdigest()

            def identity(value, pod):
                require(
                    value
                    == {
                        "manifestDigest": expected_pin,
                        "pod": pod["metadata"]["uid"],
                        "namespace": cluster.namespace,
                        "role": "probe",
                        "sourceRevision": actual_revision,
                    },
                    "authenticated runtime identity mismatch",
                )

            with (
                forward(cluster) as port,
                forward(cluster, resource="service/ocs-relay") as relay_port,
            ):
                url = f"https://127.0.0.1:{port}"
                token = (files / "probe").read_text()
                ident = json.loads(read_http(url + "/identity", files / "ca.crt", token)[1])
                identity(ident, prior)
                try:
                    read_http(url + "/identity", files / "ca.crt", "invalid-tenant-token")
                except error.HTTPError as exc:
                    require(exc.code == 401, "unexpected denial")
                else:
                    raise ValueError("an unauthenticated read succeeded")
                record(
                    "stand.tls",
                    ["W-08.tls"],
                    {
                        "identity": ident,
                        "wrongCredentialStatus": 401,
                        "serviceJob": job_read(cluster, deploy["image"]),
                    },
                )
                state = files / "state.json"
                cmd = [
                    sys.executable,
                    "-I",
                    str(HERE / "workload.py"),
                    "--url",
                    url,
                    "--ca",
                    str(files / "ca.crt"),
                    "--token-file",
                    str(files / "probe"),
                    "--state",
                    str(state),
                ]
                live_cmd = cmd + [
                    "--relay-url",
                    f"https://127.0.0.1:{relay_port}",
                    "--relay-token-file",
                    str(files / "relay-client"),
                ]
                work_report = files / "live.json"
                subprocess.run([*live_cmd, "--report", str(work_report)], check=True, timeout=90)
                work = json.loads(work_report.read_text())
                require(work.get("status") == "pass", "initial provider qualification failed")
                report["checks"].extend(work["checks"])
                account = json.loads(state.read_text())["accountId"]
                metrics = next(x for x in work["checks"] if x["id"] == "G-04.comparison")[
                    "observed"
                ]
                require(
                    relay["metadata"]["uid"] in json.dumps(metrics),
                    "inference comparison missed the designated relay pod",
                )
                api_probe = Stand(url, files / "ca.crt", files / "probe")
                api_probe.describe()
                terms = api_probe.call("example.product.terms", {"accountId": account})
                second = Stand(url, files / "ca.crt", files / "other")
                second.describe()
                second.call("limits.read", {"accountId": account}, expected="denied")
                require(
                    terms["owner"] == "qualification-account"
                    and terms["scope"]["id"] == account
                    and terms["basis"] == "organization"
                    and terms["currency"] == "USD"
                    and terms["retentionSeconds"] > 0,
                    "invalid scoped product terms",
                )
                require(
                    volume["status"]["phase"] == "Bound"
                    and "ReadWriteOnce" in volume["spec"]["accessModes"]
                    and volume["spec"].get("storageClassName"),
                    "unqualified capacity or storage placement",
                )
                record(
                    "stand.resource",
                    ["L-01.policy"],
                    {
                        "node": prior["spec"]["nodeName"],
                        "placement": cluster.namespace,
                        "availableReplicas": deployment["status"]["availableReplicas"],
                        "resourceLimits": prior["spec"]["containers"][0]["resources"],
                        "storageClass": volume["spec"]["storageClassName"],
                        "volume": volume["spec"]["volumeName"],
                        "provisionedCapacity": volume["status"]["capacity"],
                        "accessModes": volume["spec"]["accessModes"],
                        "terms": terms,
                        "otherPrincipal": "denied",
                        "standRegion": "single selected cluster",
                        "lifecycle": "single-owner PVC, coherent export and scoped recovery checked on this observation",
                    },
                )

                def timed_read(_):
                    stand = Stand(url, files / "ca.crt", files / "probe")
                    begin = time.monotonic_ns()
                    result = stand.call("limits.read", {"accountId": account})
                    require(result["accountId"] == account, "different account under load")
                    return (time.monotonic_ns() - begin) / 1e6

                with ThreadPoolExecutor(max_workers=LIMITS["concurrency"]) as pool:
                    samples = list(pool.map(timed_read, range(LIMITS["replicates"])))
                p95 = sorted(samples)[math.ceil(0.95 * len(samples)) - 1]
                require(
                    p95 <= LIMITS["p95LimitMs"] and max(samples) <= LIMITS["requestDeadlineMs"],
                    "real workload latency threshold exceeded",
                )
                native = json.loads(
                    cluster.command(
                        "exec",
                        prior["metadata"]["name"],
                        "--",
                        "python",
                        "-I",
                        "/app/stand/kubernetes/node_probe.py",
                        "--account",
                        account,
                    ).stdout
                )
                with forward(
                    cluster,
                    resource="pod/" + prior["metadata"]["name"],
                    destination=17539,
                    target_port=17539,
                ) as streamport:
                    cancellation = timed_cancel(streamport, token)
                require(
                    cancellation["elapsedMs"] <= LIMITS["requestDeadlineMs"],
                    "cancellation did not complete within the selected budget",
                )
                record(
                    "stand.load",
                    ["B-07.domain", "L-04.tail"],
                    {
                        "samplesMs": samples,
                        "p95Ms": p95,
                        "concurrency": LIMITS["concurrency"],
                        "operation": "limits.read",
                        "comparison": native,
                        "cancellation": cancellation,
                        "node": prior["spec"]["nodeName"],
                        "resourceLimits": prior["spec"]["containers"][0]["resources"],
                    },
                )
                if browser:
                    ui = output.with_name(output.stem + "-browser.json")
                    subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            str(HERE / "browser.py"),
                            "--url",
                            url,
                            "--ca",
                            str(files / "ca.crt"),
                            "--cert",
                            str(files / "tls.crt"),
                            "--token-file",
                            str(files / "probe"),
                            "--report",
                            str(ui),
                        ],
                        check=True,
                        timeout=90,
                    )
                    report["checks"].extend(json.loads(ui.read_text())["checks"])
                else:
                    report["checks"].append(
                        {
                            "id": "stand.accessibility",
                            "level": "deployment",
                            "claims": ["U-03.accessibility"],
                            "status": "open",
                            "observed": "Browser observation required.",
                        }
                    )
            old_uid = prior["metadata"]["uid"]
            # Delete only the owned pod with its exact resource UID as a precondition.
            own = cluster.get("pod", prior["metadata"]["name"])
            require(
                own["metadata"]["uid"] == old_uid and own["metadata"]["labels"].get(LABEL) == APP,
                "pod ownership changed",
            )
            path = f"/api/v1/namespaces/{cluster.namespace}/pods/{own['metadata']['name']}"
            opts = {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "gracePeriodSeconds": 2,
                "preconditions": {"uid": old_uid},
            }
            start = time.monotonic()
            cluster.command("delete", "--raw", path, "-f", "-", data=json.dumps(opts).encode())
            while time.monotonic() - start < LIMITS["recoveryLimitSeconds"]:
                candidates = [p for p in pods(cluster) if p["metadata"]["uid"] != old_uid]
                if len(candidates) == 1:
                    break
                time.sleep(1)
            else:
                raise ValueError("owned pod recovery deadline elapsed")
            with forward(cluster, port):
                after = json.loads(read_http(url + "/identity", files / "ca.crt", token)[1])
                identity(after, candidates[0])
                require(
                    check_owner(candidates[0], deployment) == old_images
                    and actual_inputs(cluster, candidates[0]["metadata"]["name"], declared)
                    == evidence_sha,
                    "recovered target runs different bytes",
                )
                require(
                    cluster.get("pvc", "ocs-provider-data")["metadata"]["uid"]
                    == volume["metadata"]["uid"]
                    and cluster.get("service", "ocs-provider")["metadata"]["uid"]
                    == deploy["serviceUID"]
                    and cluster.get("deployment", "ocs-provider")["metadata"]["uid"]
                    == deploy["deploymentUID"],
                    "recovery changed persistent state or ownership",
                )
                recovered = files / "recovered.json"
                subprocess.run(
                    [*cmd, "--resume", "--report", str(recovered)], check=True, timeout=90
                )
                rr = json.loads(recovered.read_text())
                require(rr.get("status") == "pass", "durable readback failed")
                require(
                    time.monotonic() - start <= LIMITS["recoveryLimitSeconds"],
                    "functional recovery exceeded the deadline",
                )
                require(
                    native["availableBeforeBackupBytes"] >= native["requiredBackupBytes"] > 0
                    and native["availableBeforeRestoreBytes"] >= native["requiredRestoreBytes"] > 0
                    and native["revokedPreviouslyGrantedScope"]
                    and native["sourceStateRetained"]
                    and native["revokedOperationState"] == "not-applied"
                    and native["restoredReceiptState"] == "applied"
                    and native["distinctEffectSpends"] == 1
                    and native["restoredMeterCount"] > 0,
                    "insufficient backup, grant or effect recovery evidence",
                )
                for row in rr["checks"]:
                    row["observed"]["controller"] = {
                        "oldPodUID": old_uid,
                        "newPodUID": after["pod"],
                        "pvcUID": volume["metadata"]["uid"],
                        "backupSha256": native["databaseBackupSha256"],
                        "standRestore": {k: v for k, v in native.items() if not k.endswith("Ms")},
                        "verifiedRestoredTenantIsolation": native["verifiedTenantIsolation"],
                        "elapsedMs": (time.monotonic() - start) * 1000,
                    }
                    report["checks"].append(row)
        satisfied = {
            c
            for row in report["checks"]
            if row["status"] == "pass"
            for c in row.get("claims", row.get("obligations", []))
        }
        missing = set(POLICY["deploymentClaims"]) - satisfied
        require(not missing, "missing deployment evidence: " + ", ".join(sorted(missing)))
        report["status"] = "pass"
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
        KeyError,
        ssl.SSLError,
    ) as exc:
        report["failure"] = str(exc)
    finally:
        report["finishedAt"] = now_stamp()
        save(output, report)
    print(
        report["status"], "live Kubernetes qualification", len(report["checks"]), output, flush=True
    )
    if report["status"] != "pass":
        print(report.get("failure", "missing evidence"), file=sys.stderr)
    return int(report["status"] != "pass")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kubeconfig", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("--context", default="ocs-local")
    p.add_argument("--namespace", default=LIMITS["namespace"])
    p.add_argument("--deployment", type=Path, default=SUBJECT / "out/kubernetes/deployment.json")
    p.add_argument("--report", type=Path, default=SUBJECT / "out/kubernetes/observation.json")
    p.add_argument(
        "--without-browser",
        action="store_true",
        help="diagnostic run with an explicit open UI obligation",
    )
    cfg = p.parse_args()
    raise SystemExit(
        qualify(
            Cluster(cfg.kubeconfig, cfg.context, cfg.namespace),
            json.loads(cfg.deployment.read_text()),
            cfg.report,
            not cfg.without_browser,
        )
    )
