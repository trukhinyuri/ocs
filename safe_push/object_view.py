"""Transfer only the Git objects of selected trees when receive-pack holds them privately."""

import base64
import binascii
import hashlib
import os
import subprocess
import tempfile
import unicodedata
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from authority import Decision, digest, framed, require
from scope import (
    FULL_ID,
    LIMIT,
    ScopeError,
    check_name,
    git_args,
    read_object,
    resolve_link,
    tree_records,
)

FORMAT = "ocs.safe-push.git-object-view/1"
MAX_TRANSFER = 24 * 1024 * 1024
MAX_OBJECTS = 16384


def bindings(args):
    require(
        isinstance(args, dict), "method.object-binding", "invalid authorized operands"
    )
    subject, context = args.get("subject"), args.get("context")
    if subject is None and context is None:
        raise Decision("method.object-binding", "no authenticated revision")

    def oid(s):
        require(
            isinstance(s, str) and FULL_ID.fullmatch(s),
            "method.object-binding",
            "missing full Git commit identity",
            "rejected",
        )
        return s

    ids = []
    if context is not None:
        require(
            isinstance(context, dict),
            "method.object-binding",
            "missing authenticated comparison",
            "rejected",
        )
        ids = [oid(context.get("parent")), oid(context.get("candidate"))]
        require(
            ids[0] != ids[1] and len(ids[0]) == len(ids[1]),
            "method.object-binding",
            "invalid parent and child identities",
            "rejected",
        )
    if subject is not None:
        require(
            isinstance(subject, dict),
            "method.object-binding",
            "missing authenticated subject",
            "rejected",
        )
        selected = oid(subject.get("revision"))
        require(
            not ids or ids[-1] == selected,
            "method.object-binding",
            "subject differs from the selected candidate",
            "rejected",
        )
        if not ids:
            ids = [selected]
    return ids


def environment():
    return {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


class Missing(Exception):
    pass


@dataclass(frozen=True)
class Node:
    kind: str
    size: int
    sha256: str
    prefix: bytes
    raw: bytes | None


@contextmanager
def from_git(repo, env, export):
    programs = []
    try:
        for mode in ("--batch-check=%(objectname) %(objecttype)", "--batch"):
            programs.append(
                subprocess.Popen(
                    [*git_args(repo), "cat-file", mode],
                    env=env,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
            )
        metadata, contents = programs

        def get(oid, kind):
            metadata.stdin.write(oid.encode() + b"\n")
            metadata.stdin.flush()
            header = metadata.stdout.readline(192).split()
            if header == [oid.encode(), b"missing"]:
                raise Missing(oid)
            require(
                header == [oid.encode(), kind.encode()],
                "method.object-type",
                "unexpected object type",
                "rejected",
            )
            keep = export or kind in ("commit", "tree")
            record, prefix, raw = read_object(contents, oid, kind, keep=keep)
            return Node(
                kind, record["size"], record["sha256"], prefix, raw if keep else None
            )

        yield get
    finally:
        for process in programs:
            if process.poll() is None:
                process.terminate()
            process.wait()
            process.stdin.close()
            process.stdout.close()


def commit_headers(data, oid):
    head, sep, _ = data.partition(b"\n\n")
    lines = head.splitlines()
    require(
        sep and lines and lines[0].startswith(b"tree "),
        "method.object-commit",
        "invalid commit headers",
        "rejected",
    )
    trees = [s[5:] for s in lines if s.startswith(b"tree ")]
    parents = [s[7:] for s in lines if s.startswith(b"parent ")]
    require(len(trees) == 1, "method.object-commit", "ambiguous root tree", "rejected")
    try:
        decoded = [v.decode("ascii") for v in [*trees, *parents]]
    except UnicodeDecodeError as exc:
        raise Decision(
            "method.object-commit", "invalid Git header identity", "rejected"
        ) from exc
    require(
        all(len(v) == len(oid) and FULL_ID.fullmatch(v) for v in decoded),
        "method.object-commit",
        "wrong Git header identity",
        "rejected",
    )
    return decoded[0], decoded[1:]


def collect(args, get, transfer):
    revisions = bindings(args)
    nodes, ancestry = {}, {}
    raw_total = 0

    def load(oid, kind):
        nonlocal raw_total
        if oid not in nodes:
            node = get(oid, kind)
            raw_total += node.size
            if transfer:
                require(
                    raw_total <= MAX_TRANSFER and len(nodes) < MAX_OBJECTS,
                    "method.object-limit",
                    "selected object view exceeds its wire budget",
                )
            nodes[oid] = node
        require(
            nodes[oid].kind == kind,
            "method.object-type",
            "changed tree object interpretation",
            "rejected",
        )
        return nodes[oid]

    for rev in revisions:
        root, parents = commit_headers(load(rev, "commit").raw, rev)
        ancestry[rev] = parents
        paths = {}
        aliases = set()
        expanded = 0
        pending = [(b"", iter(tree_records(load(root, "tree").raw, len(rev) // 2)))]
        while pending:
            prefix, children = pending[-1]
            child = next(children, None)
            if child is None:
                pending.pop()
                continue
            mode, kind, oid, component = child
            pathname = prefix + component
            name = check_name(pathname)
            alias = unicodedata.normalize("NFC", name).casefold()
            require(
                alias not in aliases,
                "method.object-path",
                "duplicate portable Git path",
                "rejected",
            )
            aliases.add(alias)
            require(
                len(aliases) <= LIMIT["entries"],
                "method.object-limit",
                "selected tree exceeds its entry budget",
            )
            require(
                mode != "160000",
                "method.object-closure",
                "external gitlink has no selected object closure",
            )
            node = load(oid, kind)
            expanded += node.size
            require(
                expanded <= LIMIT["totalBytes"],
                "method.object-limit",
                "expanded tree exceeds its byte budget",
            )
            entry = {"type": kind, "sha256": node.sha256}
            if kind == "tree":
                pending.append(
                    (pathname + b"/", iter(tree_records(node.raw, len(rev) // 2)))
                )
            elif mode == "120000":
                require(
                    0 < node.size == len(node.prefix),
                    "method.object-closure",
                    "unsupported link target",
                )
                try:
                    entry.update(type="link", target=node.prefix.decode())
                except UnicodeDecodeError as exc:
                    raise Decision(
                        "method.object-closure", "nonportable link target"
                    ) from exc
            else:
                require(
                    not node.prefix.startswith(
                        b"version https://git-lfs.github.com/spec/v1"
                    ),
                    "method.object-closure",
                    "external large-file pointer has no admitted content",
                )
            paths[name] = entry
        files = {}
        for name, entry in paths.items():
            target = resolve_link(name, paths) if entry["type"] == "link" else entry
            if target["type"] == "blob":
                files[name] = target["sha256"]
        if rev == revisions[-1]:
            context = args.get("context") or {}
            subject = args.get("subject") or {}
            require(
                ("tree" not in context or context["tree"] == root)
                and (
                    "sourceSha256" not in context
                    or context["sourceSha256"] == framed(files)
                )
                and (
                    "treeSha256" not in subject
                    or subject["treeSha256"] == framed(files)
                )
                and (
                    "fileCount" not in subject
                    or type(subject["fileCount"]) is int
                    and subject["fileCount"] == len(files)
                )
                and ("dirty" not in subject or subject["dirty"] is False),
                "method.object-binding",
                "tree differs from the authenticated subject",
                "rejected",
            )
    if len(revisions) == 2:
        require(
            ancestry[revisions[1]] == revisions[:1],
            "method.object-binding",
            "comparison is not the admitted direct parent",
            "rejected",
        )
    return nodes, ancestry


def quarantine_environment(repo):
    q = os.environ.get("GIT_QUARANTINE_PATH")
    obj = os.environ.get("GIT_OBJECT_DIRECTORY")
    require(
        q and obj,
        "method.object-missing",
        "selected revision unavailable in the permanent repository",
    )
    permanent = subprocess.check_output(
        [
            *git_args(repo),
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ],
        env=environment(),
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    store = Path(os.fsdecode(permanent.rstrip(b"\n"))).resolve(strict=True)

    def owned(value):
        # Git can export a relative path when it is launched in a bare repository.
        path = Path(value)
        return (path if path.is_absolute() else Path(repo) / path).resolve(strict=True)

    quarantine = owned(q)
    require(
        quarantine == owned(obj) and quarantine.parent == store and quarantine.is_dir(),
        "method.object-quarantine",
        "private object store belongs to another repository",
        "rejected",
    )
    # Ignore ambient alternates and replacements. The sole alternate is the existing object store.
    return {
        **environment(),
        "GIT_OBJECT_DIRECTORY": str(quarantine),
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(store),
    }


def maybe_export(repo: Path, args: dict):
    revisions = bindings(args)
    try:
        with from_git(repo, environment(), False) as read:
            collect(args, read, False)
        return None
    except Missing:
        pass
    try:
        with from_git(repo, quarantine_environment(repo), True) as read:
            nodes, _ = collect(args, read, True)
    except Missing as exc:
        raise Decision(
            "method.object-missing",
            "selected object unavailable from the trusted quarantine",
        ) from exc
    objects = {
        oid: {
            "type": n.kind,
            "size": n.size,
            "sha256": n.sha256,
            "data": base64.b64encode(n.raw).decode("ascii"),
        }
        for oid, n in nodes.items()
    }
    manifest = {o: [v["type"], v["size"], v["sha256"]] for o, v in objects.items()}
    return {
        "format": FORMAT,
        "revisions": revisions,
        "objectFormat": "sha1" if len(revisions[0]) == 40 else "sha256",
        "rawBytes": sum(n.size for n in nodes.values()),
        "closureSha256": framed(manifest),
        "objects": objects,
    }


def decode_packet(packet, args):
    revisions = bindings(args)
    shape = {
        "format",
        "revisions",
        "objectFormat",
        "rawBytes",
        "closureSha256",
        "objects",
    }
    algo = "sha1" if len(revisions[0]) == 40 else "sha256"
    require(
        isinstance(packet, dict)
        and set(packet) == shape
        and packet["format"] == FORMAT
        and packet["objectFormat"] == algo
        and packet["revisions"] == revisions,
        "method.object-binding",
        "projection belongs to a different authorized operand",
        "rejected",
    )
    entries = packet["objects"]
    require(
        isinstance(entries, dict)
        and len(entries) <= MAX_OBJECTS
        and type(packet["rawBytes"]) is int
        and 0 <= packet["rawBytes"] <= MAX_TRANSFER,
        "method.object-limit",
        "invalid or excessive object count or bytes",
    )
    nodes, manifest = {}, {}
    total = 0
    for oid, e in entries.items():
        require(
            isinstance(oid, str)
            and len(oid) == len(revisions[0])
            and FULL_ID.fullmatch(oid)
            and isinstance(e, dict)
            and set(e) == {"type", "size", "sha256", "data"}
            and e["type"] in ("commit", "tree", "blob"),
            "method.object-type",
            "invalid object definition",
            "rejected",
        )
        kind, size, data = e["type"], e["size"], e["data"]
        require(
            type(size) is int
            and 0 <= size <= LIMIT["structuredBytes"]
            and total + size <= MAX_TRANSFER
            and isinstance(data, str)
            and len(data) == 4 * ((size + 2) // 3),
            "method.object-limit",
            "invalid payload size",
        )
        try:
            raw = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise Decision(
                "method.object-payload", "invalid Git object encoding", "rejected"
            ) from exc
        total += size
        sha = digest(raw)
        h = hashlib.new(algo)
        h.update(f"{kind} {size}\0".encode())
        h.update(raw)
        require(
            size == len(raw) and sha == e["sha256"] and h.hexdigest() == oid,
            "method.object-payload",
            "object bytes do not match both digests",
            "rejected",
        )
        nodes[oid] = Node(kind, size, sha, raw[:4096], raw)
        manifest[oid] = [kind, size, sha]
    require(
        total == packet["rawBytes"] and framed(manifest) == packet["closureSha256"],
        "method.object-payload",
        "object manifest differs",
        "rejected",
    )

    def get(oid, kind):
        require(
            oid in nodes,
            "method.object-closure",
            "incomplete selected Git closure",
            "rejected",
        )
        return nodes[oid]

    selected, ancestry = collect(args, get, True)
    require(
        set(selected) == set(nodes),
        "method.object-closure",
        "unselected object in the projection",
        "rejected",
    )
    return selected, ancestry, algo


def materialize(packet: dict, args: dict, destination: Path) -> Path:
    try:
        nodes, parents, algo = decode_packet(packet, args)
    except ScopeError as exc:
        raise Decision("method.object-closure", str(exc), exc.outcome) from exc
    dest = Path(destination)
    require(
        dest.parent.is_dir()
        and not dest.parent.is_symlink()
        and not dest.exists()
        and not dest.is_symlink(),
        "method.object-destination",
        "object projection needs a new private scratch location",
    )
    with tempfile.TemporaryDirectory(prefix="git-object-view-", dir=dest.parent) as td:
        stage = Path(td) / "repository.git"
        subprocess.run(
            [
                "git",
                "-c",
                "protocol.allow=never",
                "init",
                "--quiet",
                "--bare",
                "--template=",
                "--initial-branch=main",
                "--object-format=" + algo,
                str(stage),
            ],
            env=environment(),
            check=True,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        for oid, node in nodes.items():
            member = stage / "objects" / oid[:2] / oid[2:]
            member.parent.mkdir(exist_ok=True)
            with member.open("xb") as f:
                f.write(zlib.compress(f"{node.kind} {node.size}\0".encode() + node.raw))
        limits = sorted(
            r for r, pp in parents.items() if any(p not in parents for p in pp)
        )
        if limits:
            (stage / "shallow").write_text("\n".join(limits) + "\n", encoding="ascii")
        with from_git(stage, environment(), False) as reader:
            rebuilt, actual_parents = collect(args, reader, False)
        require(
            actual_parents == parents
            and {oid: node.sha256 for oid, node in rebuilt.items()}
            == {oid: node.sha256 for oid, node in nodes.items()},
            "method.object-readback",
            "rebuilt Git database differs from its selected closed view",
            "rejected",
        )
        for path in sorted(stage.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            path.chmod(0o555 if path.is_dir() else 0o444)
        os.rename(stage, dest)
        dest.chmod(0o555)
    return dest
