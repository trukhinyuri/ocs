#!/usr/bin/env python3
"""Read an independent stand enrollment from the selected cluster and source checkout."""

import argparse
import base64
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from trust import save, subject_identity
from verify_receipt import (
    approved_rules,
    decoded,
    digest,
    enrolled,
    full_revision,
    public_pem,
    read_file,
    require,
)


def public_tls(cluster):
    # Ask kubectl to emit public PEM material only. Never put bearer values,
    # certificate private keys or the Secret document into the enrollment.
    fields = ("ca.crt", "tls.crt", "relay.crt")
    template = '{{index .metadata.labels "app.kubernetes.io/part-of"}}\n' + "\n".join(
        '{{index .data "' + name + '"}}' for name in fields
    )
    printed = cluster.command(
        "get", "secret", "ocs-service-identity", "-o", "go-template=" + template
    ).stdout.splitlines()
    require(len(printed) == 4 and printed[0] == b"ocs-qualification", "unbound public TLS identity")
    public = [base64.b64decode(value, validate=True) for value in printed[1:]]
    with tempfile.TemporaryDirectory(prefix="ocs-public-pki-") as folder:
        paths = [Path(folder) / name for name in fields]
        for path, value in zip(paths, public, strict=True):
            path.write_bytes(value)
        for service, leaf_path in zip(("ocs-provider", "ocs-relay"), paths[1:], strict=True):
            check = subprocess.run(
                [
                    "openssl",
                    "verify",
                    "-x509_strict",
                    "-verify_hostname",
                    f"{service}.{cluster.namespace}.svc",
                    "-CAfile",
                    str(paths[0]),
                    str(leaf_path),
                ],
                capture_output=True,
                timeout=10,
            )
            require(
                check.returncode == 0,
                "public stand leaf is not valid for the independently selected DNS origin",
            )
    pins = dict(
        zip(
            ("standCaSha256", "serverCertificateSha256", "relayCertificateSha256"),
            map(digest, public),
            strict=True,
        )
    )
    leaf = re.search(
        r"-----BEGIN CERTIFICATE-----[\\s\\S]+?-----END CERTIFICATE-----", public[1].decode("ascii")
    )
    require(leaf is not None, "invalid deployed public leaf PEM")
    return pins, digest(ssl.PEM_cert_to_DER_cert(leaf.group()))


def ready_owner(cluster, pod, controller, service, image):
    require(
        pod.get("status", {}).get("phase") == "Running"
        and pod["metadata"]["namespace"] == cluster.namespace
        and pod["metadata"].get("labels", {}).get("app.kubernetes.io/part-of")
        == "ocs-qualification",
        "enrollment requires a running owned pod in the selected namespace",
    )
    selector = service.get("spec", {}).get("selector")
    require(
        selector
        and all(pod["metadata"].get("labels", {}).get(k) == v for k, v in selector.items()),
        "service selector does not address its observed pod",
    )
    ref = [x for x in pod["metadata"].get("ownerReferences", []) if x.get("controller")]
    require(len(ref) == 1 and ref[0]["kind"] == "ReplicaSet", "unexpected pod controller")
    rs = cluster.get("replicaset", ref[0]["name"])
    require(
        rs["metadata"]["uid"] == ref[0]["uid"]
        and any(
            x.get("controller")
            and x["uid"] == controller["metadata"]["uid"]
            and x["kind"] == "Deployment"
            for x in rs["metadata"].get("ownerReferences", [])
        ),
        "pod/deployment ownership differs",
    )
    containers = pod["spec"]["containers"]
    require(
        all(c["image"] == image for c in containers)
        and all(c["image"] == image for c in controller["spec"]["template"]["spec"]["containers"]),
        "live pod or controller uses an unapproved image",
    )
    statuses = pod["status"]["containerStatuses"]
    require(
        {x["name"] for x in statuses} == {c["name"] for c in containers}
        and all(
            s.get("ready") is True and s.get("state", {}).get("running") is not None
            for s in statuses
        ),
        "incomplete running container inventory",
    )
    return {s["name"]: s["imageID"] for s in statuses}


def actual_oci(cluster, pod, ids, image, blobs, collect, accepted_ids):
    normalized = {s.split("@")[-1].split("://")[-1] for s in ids.values()}
    require(
        all(re.fullmatch(r"sha256:[0-9a-f]{64}", d) for d in normalized),
        "incomplete OCI runtime identities",
    )
    top = image.rsplit("@", 1)[1]
    if normalized == {top}:
        return blobs
    if blobs is None:
        # A child/config ID supplied by a multi-platform runtime must still be
        # reachable from the operator-selected content-addressed manifest.
        def fetch(repo, ref):
            cp = subprocess.run(
                ["docker", "buildx", "imagetools", "inspect", "--raw", repo + "@" + ref],
                capture_output=True,
                timeout=45,
            )
            require(
                cp.returncode == 0,
                "cannot read selected OCI manifest; supply --oci-proof from the trusted registry",
            )
            return cp.stdout

        blobs = collect(image, fetch)
    node = cluster.get("node", pod["spec"]["nodeName"])
    arch = node["status"]["nodeInfo"]["architecture"]
    require(
        normalized <= accepted_ids(image, blobs, arch),
        "live OCI runtime digest is not bound to the selected image",
    )
    return blobs


def enroll(args):
    rev = full_revision(args.checker_commit)
    source_rev = full_revision(args.subject_revision)
    subject = args.subject_root.resolve()
    # All required deployment check bindings and thresholds must already exist
    # in the separately approved Git revision. No registry is inferred from a report.
    approved_rules(args.checker_repo, rev)
    expected_image = args.image
    require(
        re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", expected_image),
        "supply an immutable OCI image",
    )
    identity = subject_identity(subject)
    require(
        identity["revision"] == source_rev and not identity["dirty"],
        "source enrollment requires the selected clean Git checkout",
    )
    key = public_pem(args.public_key)
    if args.public_key_sha256:
        require(
            digest(key) == args.public_key_sha256,
            "independent observer public-key fingerprint changed",
        )
    blobs = decoded(read_file(args.oci_proof)) if args.oci_proof else None
    with tempfile.TemporaryDirectory(prefix="ocs-enroll-") as tmp:
        old = Path(tmp) / "checker"
        archive = Path(tmp) / "checker.zip"
        cmd = [
            "git",
            "--no-replace-objects",
            "-C",
            str(args.checker_repo),
            "archive",
            "--format=zip",
            "-o",
            str(archive),
            rev,
            "stand/kubernetes",
            "reference/contracts.py",
            "reference/provider/ocs.json",
            "schemas",
            "spec/profiles/operations.json",
            "assurance/provider/criteria.json",
        ]
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)
        with ZipFile(archive) as data:
            data.extractall(old)
        # The frozen observer's helper computes the manifest from this
        # independently selected source tree, not from cluster annotations.
        os.environ["OCS_SUBJECT_ROOT"] = str(subject)
        sys.path.insert(0, str(old / "stand/kubernetes"))
        from deploy import Cluster, image_inputs
        from observe import actual_inputs, pods
        from oci import accepted_ids, collect

        require(
            all(
                Path(sys.modules[x].__file__).resolve().is_relative_to(old)
                for x in ("deploy", "oci", "observe")
            ),
            "stand helper import did not originate in the approved checker",
        )
        cluster = Cluster(args.kubeconfig, args.context, args.namespace)
        uid = cluster.get("namespace", "kube-system")["metadata"]["uid"]
        version = json.loads(cluster.command("get", "--raw=/version").stdout)["gitVersion"]
        required = {}
        for kind, name in [
            ("service", "ocs-provider"),
            ("deployment", "ocs-provider"),
            ("service", "ocs-relay"),
            ("deployment", "ocs-relay"),
            ("pvc", "ocs-provider-data"),
        ]:
            obj = cluster.owned(kind, name)
            require(
                obj and obj["metadata"]["namespace"] == args.namespace,
                "missing owned " + kind + "/" + name,
            )
            required[kind, name] = obj
        services = {name: required["service", name] for name in ("ocs-provider", "ocs-relay")}
        pvs = required["pvc", "ocs-provider-data"]
        require(pvs["status"]["phase"] == "Bound", "owned persistent volume claim is not bound")
        live = {}
        images = {}
        for name in ("ocs-provider", "ocs-relay"):
            instances = pods(cluster, name)
            require(len(instances) == 1, "expected one ready " + name + " pod")
            pod = instances[0]
            ids = ready_owner(
                cluster, pod, required["deployment", name], services[name], expected_image
            )
            blobs = actual_oci(cluster, pod, ids, expected_image, blobs, collect, accepted_ids)
            live[name] = pod
            images[name] = ids
        provider = live["ocs-provider"]
        relay = live["ocs-relay"]
        container = "provider"
        require(
            any(
                v.get("persistentVolumeClaim", {}).get("claimName") == pvs["metadata"]["name"]
                for v in provider["spec"].get("volumes", [])
            ),
            "ready provider is not attached to the enrolled PVC",
        )
        declared = image_inputs(subject)
        tree = actual_inputs(cluster, provider["metadata"]["name"], declared)
        image_revision = (
            cluster.command(
                "exec",
                provider["metadata"]["name"],
                "-c",
                container,
                "--",
                "printenv",
                "OCS_REVISION",
            )
            .stdout.decode()
            .strip()
        )
        require(
            image_revision == source_rev,
            "running provider source revision differs from the enrollment",
        )
        binary = (
            cluster.command(
                "exec",
                provider["metadata"]["name"],
                "-c",
                container,
                "--",
                "sha256sum",
                "/usr/local/bin/ocs-go",
            )
            .stdout.decode()
            .split()[0]
        )
        tls, leaf_der = public_tls(cluster)
        for pod, name, path, field in (
            (provider, "provider", "/var/run/ocs/keys/tls.crt", "serverCertificateSha256"),
            (relay, "relay", "/var/run/ocs/relay/ca.crt", "standCaSha256"),
            (relay, "relay", "/var/run/ocs/relay/relay.crt", "relayCertificateSha256"),
        ):
            mounted = (
                cluster.command(
                    "exec", pod["metadata"]["name"], "-c", name, "--", "sha256sum", path
                )
                .stdout.decode()
                .split()[0]
            )
            require(
                mounted == tls[field], "mounted public certificate differs from the API binding"
            )
        target = {
            "apiVersion": version,
            "clusterUID": uid,
            "serviceUID": services["ocs-provider"]["metadata"]["uid"],
            "namespace": args.namespace,
            "image": expected_image,
            "imageID": provider["status"]["containerStatuses"][0]["imageID"],
            "sourceRevision": source_rev,
            "inputSha256": tree,
            "pvcUID": pvs["metadata"]["uid"],
            "goExecutableSha256": binary,
            "actualOCIIdentities": images["ocs-provider"],
            "relayPodUID": relay["metadata"]["uid"],
            "relayServiceUID": services["ocs-relay"]["metadata"]["uid"],
            **tls,
        }
        for name in live:
            again = pods(cluster, name)
            require(
                len(again) == 1 and again[0]["metadata"]["uid"] == live[name]["metadata"]["uid"],
                "ready pod changed while collecting enrollment",
            )
        require(subject_identity(subject) == identity, "trusted source changed during enrollment")
        out = {
            "format": "ocs.stand-enrollment/1",
            "acceptedVerifier": rev,
            "operatorKey": digest(key),
            "subject": {
                "revision": source_rev,
                "treeSha256": identity["treeSha256"],
                "fileCount": identity["fileCount"],
            },
            "target": target,
            "readyPods": {
                "provider": provider["metadata"]["uid"],
                "relay": relay["metadata"]["uid"],
            },
            "providerManifestSha256": digest(
                (subject / "reference/provider/ocs.json").read_bytes()
            ),
            "serverCertificateDerSha256": leaf_der,
            "enrolledAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "context": args.context,
        }
        enrolled(out)
        return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--checker-commit", required=True)
    p.add_argument("--checker-repo", type=Path, default=HERE.parent)
    p.add_argument("--subject-root", type=Path, required=True)
    p.add_argument("--subject-revision", required=True)
    p.add_argument("--kubeconfig", type=Path, required=True)
    p.add_argument("--context", required=True)
    p.add_argument("--namespace", required=True)
    p.add_argument("--image", required=True, help="independently selected name@sha256:digest")
    p.add_argument("--public-key", type=Path, required=True)
    p.add_argument("--public-key-sha256", help="optional additional out-of-band PEM pin")
    p.add_argument(
        "--oci-proof",
        type=Path,
        help="optional content-addressed OCI blob map obtained independently",
    )
    p.add_argument(
        "--output", type=Path, required=True, help="operator-controlled enrollment location"
    )
    args = p.parse_args()
    require_out = {p.resolve() for p in (args.public_key, args.kubeconfig, args.oci_proof) if p}
    if args.output.resolve() in require_out:
        p.error("enrollment output cannot overwrite a trust input")
    try:
        obj = enroll(args)
        save(args.output, obj)
        print(
            "Enrolled ready Kubernetes target",
            obj["target"]["clusterUID"],
            obj["target"]["namespace"],
        )
    except (
        ValueError,
        KeyError,
        TypeError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        # Avoid logging arbitrary HTTP/Kubernetes error payloads or mounted Secret records.
        detail = str(exc)[:260] if isinstance(exc, ValueError) else type(exc).__name__
        if isinstance(exc, RuntimeError):
            detail = (
                "API read or pod-exec permission denied on the selected context"
                if "forbidden" in str(exc).lower()
                else "selected Kubernetes read command failed"
            )
        print("FAIL stand enrollment:", detail, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
