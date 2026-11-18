#!/usr/bin/env python3
"""Build and install the namespaced OCS workload on an explicitly selected cluster."""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("OCS_SUBJECT_ROOT", HERE.parents[1])).resolve()
POLICY = json.loads((HERE / "policy.json").read_text())
sys.path.insert(0, str(HERE))
from local import DEFAULT_CONFIG, start
from oci import collect as collect_oci

LABEL = "app.kubernetes.io/part-of"
APP = "ocs-qualification"


def run(args, *, data=None, timeout=180, check=True):
    p = subprocess.run(
        args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
    )
    if check and p.returncode:
        # All credential material is supplied through standard input or mounted
        # paths, never CLI flags. Avoid dumping an entire rejected secret manifest.
        summary = p.stderr.decode(errors="replace").splitlines()[:3]
        raise RuntimeError(f"{args[0]} failed ({p.returncode}): " + " ".join(summary)[:400])
    return p


class Cluster:
    def __init__(self, config, context, namespace):
        if (
            not config.is_file()
            or not context
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", namespace)
        ):
            raise ValueError("supply a readable kubeconfig, context and valid namespace")
        self.namespace = namespace
        self.context = context
        self.cmd = ["kubectl", "--kubeconfig", str(config), "--context", context, "-n", namespace]

    def command(self, *args, **opts):
        return run([*self.cmd, *args], **opts)

    def get(self, kind, name, optional=False):
        args = ["get", kind, name, "-o", "json"]
        if optional:
            args.append("--ignore-not-found")
        data = self.command(*args).stdout
        return json.loads(data) if data.strip() else None

    def owned(self, kind, name):
        obj = self.get(kind, name, optional=True)
        if obj and obj["metadata"].get("labels", {}).get(LABEL) != APP:
            raise ValueError(f"{kind}/{name} already exists and belongs to another deployment")
        return obj

    def apply(self, data):
        self.command(
            "apply", "--server-side", "--field-manager=ocs-qualification", "-f", "-", data=data
        )


def create_identity(cluster):
    previous = cluster.owned("secret", "ocs-service-identity")
    with tempfile.TemporaryDirectory(prefix="ocs-tls-") as tmp:
        path = Path(tmp)
        leaves = {"tls": "ocs-provider", "relay": "ocs-relay"}
        tokens = ("probe", "work", "other", "relay-client", "relay-upstream")
        if previous and all(
            k in previous["data"]
            for k in (*tokens, "ca.crt", "tls.crt", "relay.crt", "tls.key", "relay.key")
        ):
            for n in ("ca.crt", "tls.crt", "relay.crt"):
                (path / n).write_bytes(base64.b64decode(previous["data"][n], validate=True))
            good = all(
                run(
                    [
                        "openssl",
                        "verify",
                        "-x509_strict",
                        "-verify_hostname",
                        hostname,
                        "-CAfile",
                        str(path / "ca.crt"),
                        str(path / (leaf + ".crt")),
                    ],
                    check=False,
                ).returncode
                == 0
                and run(
                    ["openssl", "x509", "-checkend", "86400", "-in", str(path / (leaf + ".crt"))],
                    check=False,
                ).returncode
                == 0
                for leaf, hostname in leaves.items()
            )
            if good:
                return hashlib.sha256(
                    (path / "tls.crt").read_bytes() + (path / "relay.crt").read_bytes()
                ).hexdigest()
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "30",
                "-subj",
                "/CN=OCS qualification CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
                "-keyout",
                str(path / "ca.key"),
                "-out",
                str(path / "ca.crt"),
            ]
        )
        values = {"ca.crt": (path / "ca.crt").read_bytes()}
        for leaf, service in leaves.items():
            run(
                [
                    "openssl",
                    "req",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-subj",
                    "/CN=" + service,
                    "-keyout",
                    str(path / (leaf + ".key")),
                    "-out",
                    str(path / "leaf.csr"),
                ]
            )
            (path / "extensions").write_text(
                f"subjectAltName=DNS:{service},DNS:{service}.{cluster.namespace}.svc,"
                f"DNS:{service}.{cluster.namespace}.svc.cluster.local,DNS:localhost,IP:127.0.0.1\n"
                "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n"
                "authorityKeyIdentifier=keyid:always\nsubjectKeyIdentifier=hash\n"
            )
            run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(path / "leaf.csr"),
                    "-CA",
                    str(path / "ca.crt"),
                    "-CAkey",
                    str(path / "ca.key"),
                    "-set_serial",
                    str(secrets.randbits(126) + 1),
                    "-days",
                    "30",
                    "-extfile",
                    str(path / "extensions"),
                    "-out",
                    str(path / (leaf + ".crt")),
                ]
            )
            for suffix in (".key", ".crt"):
                values[leaf + suffix] = (path / (leaf + suffix)).read_bytes()
        values.update(
            {
                n: base64.b64decode(previous["data"][n], validate=True)
                if previous and n in previous["data"]
                else secrets.token_hex(32).encode()
                for n in tokens
            }
        )
        meta = {
            "namespace": cluster.namespace,
            "name": "ocs-service-identity",
            "labels": {LABEL: APP},
        }
        if previous:
            meta["resourceVersion"] = previous["metadata"]["resourceVersion"]
        cluster.command(
            "replace" if previous else "create",
            "-f",
            "-",
            data=json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "type": "Opaque",
                    "metadata": meta,
                    "data": {k: base64.b64encode(v).decode() for k, v in values.items()},
                }
            ).encode(),
        )
        return hashlib.sha256(values["tls.crt"] + values["relay.crt"]).hexdigest()


def image_inputs(root=ROOT):
    names = [".dockerignore", "go.mod", "uv.lock", "LICENSE", "assurance/provider/criteria.json"]
    for directory in ("reference", "examples", "schemas", "spec", "stand/kubernetes"):
        for path in sorted((root / directory).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                names.append(path.relative_to(root).as_posix())
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(names)}


def local_image():
    digests = image_inputs()
    tree = hashlib.sha256(
        json.dumps(digests, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    repo = "docker.io/library/ocs-qualification"
    tag = repo + ":" + tree[:24]
    node = POLICY["local"]["container"]
    platform = (
        run(["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"])
        .stdout.decode()
        .strip()
    )
    command = [
        "docker",
        "buildx",
        "build",
        "--platform",
        platform,
        "--provenance=false",
        "--load",
        "--label",
        "org.ocs.image-inputs=" + tree,
        "--tag",
        tag,
        "-f",
        str(HERE / "Dockerfile"),
        str(ROOT),
    ]
    subprocess.run(command, check=True, timeout=900)
    # Use a file so that both image transfer processes have independently checked exits.
    with tempfile.TemporaryDirectory(prefix="ocs-oci-") as tmp:
        archive = str(Path(tmp) / "image.tar")
        run(["docker", "save", "-o", archive, tag], timeout=180)
        with open(archive, "rb") as data:
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "-i",
                    node,
                    "/bin/ctr",
                    "--address",
                    "/run/k3s/containerd/containerd.sock",
                    "--namespace",
                    "k8s.io",
                    "images",
                    "import",
                    "--platform",
                    platform,
                    "-",
                ],
                stdin=data,
                check=True,
                timeout=180,
                stdout=subprocess.DEVNULL,
            )
    info = (
        run(
            [
                "docker",
                "exec",
                node,
                "/bin/ctr",
                "--address",
                "/run/k3s/containerd/containerd.sock",
                "--namespace",
                "k8s.io",
                "images",
                "ls",
            ]
        )
        .stdout.decode()
        .splitlines()
    )
    matching = [line.split() for line in info if line.split() and line.split()[0] == tag]
    if len(matching) != 1 or not re.fullmatch("sha256:[0-9a-f]{64}", matching[0][2]):
        raise RuntimeError("imported OCI manifest digest unavailable")
    image = repo + "@" + matching[0][2]
    run(
        [
            "docker",
            "exec",
            node,
            "/bin/ctr",
            "--address",
            "/run/k3s/containerd/containerd.sock",
            "--namespace",
            "k8s.io",
            "images",
            "tag",
            "--force",
            tag,
            image,
        ]
    )
    if image_inputs() != digests:
        raise ValueError("subject changed while building the image; rebuild the selected revision")
    return image


def install(cluster, image, revision, storage):
    if not re.fullmatch(r"[\w./:-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("a published image digest is required")
    if not cluster.owned("namespace", cluster.namespace):
        cluster.apply(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {"name": cluster.namespace, "labels": {LABEL: APP}},
                }
            ).encode()
        )
    certificate = create_identity(cluster)
    for kind, name in (
        ("pvc", "ocs-provider-data"),
        ("deployment", "ocs-provider"),
        ("service", "ocs-provider"),
        ("service", "ocs-relay"),
        ("deployment", "ocs-relay"),
    ):
        cluster.owned(kind, name)
    yaml = (
        (HERE / "resources.yaml")
        .read_text()
        .replace("OCS_IMAGE_REF", image)
        .replace("OCS_SOURCE_REVISION", revision)
        .replace("OCS_CERTIFICATE_SHA256", certificate)
    )
    if storage:
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", storage):
            raise ValueError("invalid storage class name")
        yaml = yaml.replace(
            "  accessModes: [ReadWriteOnce]",
            "  storageClassName: " + storage + "\n  accessModes: [ReadWriteOnce]",
        )
    cluster.apply(yaml.encode())
    cluster.command("rollout", "status", "deployment/ocs-provider", "--timeout=180s", timeout=190)
    cluster.command("rollout", "status", "deployment/ocs-relay", "--timeout=180s", timeout=190)
    actual = cluster.get("deployment", "ocs-provider")
    if (
        actual["spec"]["template"]["spec"]["containers"][0]["image"] != image
        or actual["status"].get("availableReplicas") != 1
    ):
        raise RuntimeError("deployment readback differs from the requested target")
    return {
        "context": cluster.context,
        "namespace": cluster.namespace,
        "image": image,
        "sourceRevision": revision,
        "deploymentUID": actual["metadata"]["uid"],
        "relayDeploymentUID": cluster.get("deployment", "ocs-relay")["metadata"]["uid"],
        "relayServiceUID": cluster.get("service", "ocs-relay")["metadata"]["uid"],
        "serviceUID": cluster.get("service", "ocs-provider")["metadata"]["uid"],
        "clusterUID": cluster.get("namespace", "kube-system")["metadata"]["uid"],
        "inputs": image_inputs(),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--context")
    parser.add_argument("--namespace", default=POLICY["workload"]["namespace"])
    parser.add_argument("--image")
    parser.add_argument(
        "--oci-proof", type=Path, help="offline bundle of digest-verified OCI manifest blobs"
    )
    parser.add_argument("--storage-class")
    parser.add_argument("--report", type=Path, default=ROOT / "out/kubernetes/deployment.json")
    opts = parser.parse_args()
    if opts.local and (opts.kubeconfig or opts.context):
        parser.error("choose the dedicated local cluster or an explicit kubeconfig/context pair")
    if not opts.local and not (opts.kubeconfig and opts.context and opts.image):
        parser.error("remote deployment requires --kubeconfig --context --image")
    try:
        if opts.local:
            start(DEFAULT_CONFIG, False)
        c = Cluster(opts.kubeconfig or DEFAULT_CONFIG, opts.context or "ocs-local", opts.namespace)
        ref = opts.image or local_image()
        revision = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.decode().strip()
        evidence = install(c, ref, revision, opts.storage_class)
        if opts.oci_proof:
            blobs = json.loads(opts.oci_proof.read_text())
            def fetch(repo, d):
                return base64.b64decode(blobs[d], validate=True)
        elif opts.local:

            def fetch(repo, d):
                return run(
                    [
                        "docker",
                        "exec",
                        POLICY["local"]["container"],
                        "/bin/ctr",
                        "--address",
                        "/run/k3s/containerd/containerd.sock",
                        "--namespace",
                        "k8s.io",
                        "content",
                        "get",
                        d,
                    ]
                ).stdout
        else:

            def fetch(repo, d):
                return run(
                    ["docker", "buildx", "imagetools", "inspect", "--raw", repo + "@" + d]
                ).stdout

        evidence["ociManifests"] = collect_oci(ref, fetch)
        opts.report.parent.mkdir(parents=True, exist_ok=True)
        opts.report.write_text(json.dumps(evidence, indent=2) + "\n")
        print(f"{c.context}/{c.namespace} serving {ref}")
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"deployment failed: {exc}\n")
