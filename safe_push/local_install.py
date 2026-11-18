#!/usr/bin/env python3
"""Install an independently administered, socket-activated Safe Push receiver on Linux."""

import argparse
import contextlib
import fcntl
import grp
import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

INSTANCE = re.compile(r"[a-z][a-z0-9-]{0,22}")
GROUP = re.compile(r"[a-zA-Z_][a-zA-Z0-9_-]{0,31}")
OBJECT = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
DIGEST = re.compile(r"[a-f0-9]{64}")
STATE_PARENT = Path("/var/lib/ocs-safe-push")
CLIENT_PARENT = Path("/usr/local/libexec/ocs-safe-push")
GIT_HELPER = Path("/usr/local/bin/git-remote-ocs")
UNIT_PARENT = Path("/etc/systemd/system")
PYTHON = "/usr/bin/python3"
INPUTS = (
    "safe_push/local_install.py",
    "safe_push/operator_cli.py",
    "safe_push/cost.py",
    "safe_push/cost_acquisition.py",
    "safe_push/receiver.py",
    "safe_push/method_worker.py",
    "safe_push/tests/status_adapter.py",
    "safe_push/admission.py",
    "safe_push/authority.py",
    "safe_push/object_view.py",
    "safe_push/evolution.py",
    "safe_push/scope.py",
    "safe_push/proof.py",
    "safe_push/qualification.py",
    "safe_push/socket_client.py",
    "safe_push/git_remote_ocs.py",
    "safe_push/coverage.json",
    "safe_push/criteria.json",
    "safe_push/metrics.json",
    "safe_push/Admission.lean",
    "assurance/structure.py",
    "assurance/interaction/lean_tools.py",
    "assurance/wire/toolchain.json",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(obj):
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest_file(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def run(*argv, env=None, **kwargs):
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        **(env or {}),
    }
    return subprocess.run(
        argv, check=True, env=environment, stdout=subprocess.PIPE, **kwargs
    ).stdout


def git(repo, *args):
    return run(
        "/usr/bin/git",
        "--no-replace-objects",
        "-c",
        "safe.directory=" + str(repo.resolve()),
        "-C",
        repo,
        *args,
    )


def private_paths(instance):
    require(INSTANCE.fullmatch(instance), "invalid native instance name")
    base = STATE_PARENT / instance
    return base, base / "state", base / "release", base / "lean"


def filesystem_entries(root):
    """Reject links to the outside and special files before trusting a deployment tree."""
    root = root.resolve(strict=True)
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            link = os.readlink(path)
            require(
                not os.path.isabs(link)
                and path.resolve(strict=True).is_relative_to(root),
                "absolute or escaping link in distribution: " + relative,
            )
            yield relative, "link", sha(os.fsencode(link))
        elif stat.S_ISREG(mode):
            yield relative, "executable" if mode & 0o111 else "file", digest_file(path)
        elif stat.S_ISDIR(mode):
            yield relative, "directory", ""
        else:
            raise ValueError("special file in distribution: " + relative)


def tree_digest(root):
    return sha(canonical(list(filesystem_entries(root))))


def install_release(source, rev, dest):
    require(
        rev
        and OBJECT.fullmatch(rev)
        and git(source, "cat-file", "-t", rev).strip() == b"commit",
        "select a full immutable receiver commit",
    )
    for name in INPUTS:
        entry = git(source, "ls-tree", rev, "--", name).split(b"\t", 1)
        require(
            len(entry) == 2
            and entry[0].split()[:2] in ([b"100644", b"blob"], [b"100755", b"blob"])
            and entry[1].rstrip(b"\n").decode() == name,
            "missing receiver file at selected commit: " + name,
        )
        contents = git(source, "cat-file", "blob", rev + ":" + name)
        if name == "safe_push/local_install.py":
            require(
                contents == Path(__file__).read_bytes(),
                "installer differs from the selected immutable commit",
            )
        output = dest / name
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as f:
            f.write(contents)
        output.chmod(0o444)


def pin_lean(dest, manifest, *, home=None, archive=None, expected_tree=None):
    require(bool(home) != bool(archive), "choose exactly one Lean source")
    host = platform.system() + "/" + platform.machine()
    require(host in manifest["builds"], "this host lacks an enrolled Lean release")
    build = manifest["builds"][host]
    if home:
        require(
            expected_tree and DIGEST.fullmatch(expected_tree),
            "enroll the SHA-256 of the entire Lean distribution",
        )
        require(
            tree_digest(home) == expected_tree,
            "source Lean tree differs from independent custodian enrollment",
        )
        shutil.copytree(home, dest, symlinks=True, copy_function=shutil.copy2)
        require(
            tree_digest(dest) == expected_tree,
            "copied Lean distribution differs from enrollment",
        )
        provenance = {
            "kind": "operator-enrolled distribution",
            "treeSha256": expected_tree,
        }
    else:
        with tempfile.TemporaryDirectory(dir=dest.parent, prefix=".lean-") as d:
            temp = Path(d)
            package = temp / "release.tar.zst"
            shutil.copyfile(archive, package)
            require(
                digest_file(package) == build["assetSha256"],
                "Lean archive differs from enrolled release",
            )
            expanded = temp / "extracted"
            expanded.mkdir()
            with subprocess.Popen(
                ["/usr/bin/zstd", "-q", "-d", "-c", package], stdout=subprocess.PIPE
            ) as codec:
                with tarfile.open(fileobj=codec.stdout, mode="r|") as tar:
                    tar.extractall(path=expanded, filter="data")
                codec.stdout.close()
                require(codec.wait() == 0, "could not unpack the verified Lean archive")
            roots = list(expanded.iterdir())
            require(
                len(roots) == 1 and roots[0].is_dir() and not roots[0].is_symlink(),
                "unrecognized release layout",
            )
            roots[0].rename(dest)
        provenance = {
            "kind": "pinned release archive",
            "archiveSha256": build["assetSha256"],
            "treeSha256": tree_digest(dest),
        }
    for rel, expected in build["files"].items():
        require(
            digest_file(dest / rel) == expected,
            "protected proof tool or library differs: " + rel,
        )
    require((dest / "lib/lean/Init.olean").is_file(), "missing Lean standard library")
    require(
        run(
            dest / "bin/lean",
            "--githash",
            env={"PATH": str(dest / "bin") + ":/usr/bin"},
        )
        .decode()
        .strip()
        == manifest["commit"],
        "selected Lean compiler differs from the enrolled commit",
    )
    return provenance


def locked_identity(name, *, create=True):
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        if not create:
            raise
        run(
            "/usr/bin/useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/bin/nologin",
            name,
        )
        account = pwd.getpwnam(name)
    require(
        account.pw_uid > 0
        and grp.getgrgid(account.pw_gid).gr_name == name
        and account.pw_shell.endswith("/nologin")
        and account.pw_dir == "/nonexistent"
        and set(os.getgrouplist(name, account.pw_gid)) == {account.pw_gid}
        and not any(
            p.pw_uid != account.pw_uid and p.pw_gid == account.pw_gid
            for p in pwd.getpwall()
        )
        and set(grp.getgrgid(account.pw_gid).gr_mem) <= {name},
        "dedicated service account or group has shared membership, login access or other privileges",
    )
    return account


def linux_identity(instance, client_group):
    name = "ocs-sp-" + instance
    require(
        GROUP.fullmatch(client_group)
        and client_group not in (name, "ocs-me-" + instance),
        "choose a separate existing client group",
    )
    clients = grp.getgrnam(client_group)
    publisher = locked_identity(name)
    require(
        publisher.pw_gid != clients.gr_gid,
        "publisher and ordinary client group must differ",
    )
    return name, publisher.pw_gid


def method_endpoint(instance):
    require(INSTANCE.fullmatch(instance), "invalid evaluator instance")
    return "/run/ocs-safe-push-method/" + instance + ".sock"


def broker_metadata(instance, publisher, evaluator):
    require(
        publisher.pw_uid > 0
        and evaluator.pw_uid > 0
        and evaluator.pw_uid != publisher.pw_uid
        and evaluator.pw_gid != publisher.pw_gid,
        "evaluator and publisher need distinct locked identities",
    )
    return {
        "format": "ocs.safe-push.method-broker/1",
        "socket": method_endpoint(instance),
        "publisherUid": publisher.pw_uid,
        "evaluatorUid": evaluator.pw_uid,
    }


def unit_text(instance, client_group, *, broker=True):
    require(
        INSTANCE.fullmatch(instance) and GROUP.fullmatch(client_group),
        "invalid unit identity",
    )
    _base, state, release, _ = private_paths(instance)
    service = f"""[Unit]
Description=OCS receive-pack connection for {instance}

[Service]
User=ocs-sp-{instance}
Group=ocs-sp-{instance}
ExecStart={PYTHON} -I -B {release}/safe_push/receiver.py socket {state}/receiver.json
StandardInput=socket
StandardOutput=socket
StandardError=journal
WorkingDirectory={state}
UMask=0027
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
ReadWritePaths={state}/journal {state}/repository.git/objects {state}/repository.git/reftable
ReadOnlyPaths={state}/repository.git/objects/info
"""
    socket = f"""[Unit]
Description=Private OCS Git transport for {instance}

[Socket]
ListenStream=/run/ocs-safe-push/{instance}.sock
Accept=yes
SocketUser=root
SocketGroup={client_group}
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
"""
    units = {
        f"ocs-safe-push-{instance}@.service": service,
        f"ocs-safe-push-{instance}.socket": socket,
    }
    if broker:
        # Only the connection service gets this supplementary group. Host state is read-only;
        # signing material and private authority state are masked even from its outer interpreter.
        units[f"ocs-safe-method-{instance}@.service"] = f"""[Unit]
Description=OCS enrolled method evaluator for {instance}

[Service]
User=ocs-me-{instance}
Group=ocs-me-{instance}
SupplementaryGroups=ocs-sp-{instance}
ExecStart={PYTHON} -I -B {release}/safe_push/method_worker.py serve {state}/receiver.json
StandardInput=socket
StandardOutput=socket
StandardError=journal
WorkingDirectory={state}
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateNetwork=yes
PrivatePIDs=yes
TemporaryFileSystem=/tmp:rw,nosuid,nodev,noexec,mode=1777,size=192M /var/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M /run:ro,nosuid,nodev,noexec,size=1M /dev/shm:rw,nosuid,nodev,noexec,mode=1777,size=32M
TemporaryFileSystem={state}/authority:ro,nosuid,nodev,noexec,mode=0555
BindReadOnlyPaths={state}/authority/root.json {state}/authority/broker.json -{state}/authority/rotations -{state}/authority/methods
ReadOnlyPaths={state}
InaccessiblePaths={state}/publishing {state}/journal {state}/witness {state}/hooks
CPUQuota=200%
MemoryMax=1G
TasksMax=128
RuntimeMaxSec=180s
TimeoutStopSec=5s
"""
        units[f"ocs-safe-method-{instance}.socket"] = f"""[Unit]
Description=Private OCS evaluator transport for {instance}

[Socket]
ListenStream={method_endpoint(instance)}
Accept=yes
SocketUser=root
SocketGroup=ocs-sp-{instance}
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=yes
MaxConnections=8

[Install]
WantedBy=sockets.target
"""
    return units


def protect(directory, gid, *, public=False, keep_links=False):
    """Make administrative content root-owned and readable by its consumer only."""
    for node in [directory, *directory.rglob("*")]:
        mode = node.lstat().st_mode
        if stat.S_ISLNK(mode):
            require(
                keep_links and node.resolve(strict=True).is_relative_to(directory),
                "unexpected administrative link",
            )
            os.chown(node, 0, gid, follow_symlinks=False)
            continue
        require(
            stat.S_ISDIR(mode) or stat.S_ISREG(mode),
            "unexpected special installation file",
        )
        os.chown(node, 0, gid)
        executable = stat.S_ISDIR(mode) or bool(mode & 0o111)
        node.chmod(
            (0o555 if executable else 0o444)
            if public
            else (0o550 if executable else 0o440)
        )


def grant_tree(directory, gid):
    directory.mkdir(parents=True, exist_ok=True)
    for path in [directory, *directory.rglob("*")]:
        require(
            not path.is_symlink() and (path.is_dir() or path.is_file()),
            "unexpected writable Git or journal object",
        )
        os.chown(path, 0, gid)
        path.chmod(0o2770 if path.is_dir() else 0o660)


def protect_state(state, gid):
    repo = state / "repository.git"
    require(
        git(repo, "rev-parse", "--show-ref-format").strip() == b"reftable",
        "writable references must use isolated reftable",
    )
    protect(state, gid)
    grant_tree(state / "journal", gid)
    lock = state / "journal/publication.lock"
    lock.touch(exist_ok=True)
    os.chown(lock, 0, gid)
    lock.chmod(0o660)
    grant_tree(repo / "reftable", gid)
    grant_tree(repo / "objects", gid)
    # Keep a submitted object writer from substituting an alternates configuration.
    info = repo / "objects/info"
    info.mkdir(exist_ok=True)
    protect(info, gid)
    (repo / "objects").chmod(0o3770)
    require(
        not (info / "alternates").exists() and not (info / "http-alternates").exists(),
        "receiver requires a self-contained Git object store",
    )


def independent_git(repo, hooks):
    for key, val in (
        ("core.hooksPath", str(hooks)),
        ("receive.denyDeletes", "true"),
        ("receive.denyNonFastForwards", "true"),
        ("receive.fsckObjects", "true"),
        ("core.logAllRefUpdates", "true"),
        ("core.fsync", "committed"),
        ("gc.auto", "0"),
    ):
        git(repo, "config", key, val)
    if git(repo, "rev-parse", "--show-ref-format").strip() != b"reftable":
        before = git(repo, "rev-parse", "refs/heads/main")
        git(
            repo,
            "-c",
            "core.hooksPath=/dev/null",
            "refs",
            "migrate",
            "--ref-format=reftable",
        )
        require(
            git(repo, "rev-parse", "refs/heads/main") == before,
            "offline reference-format migration changed main",
        )
    require(
        git(repo, "symbolic-ref", "HEAD").strip() == b"refs/heads/main"
        and git(repo, "for-each-ref", "--format=%(refname)").splitlines()
        == [b"refs/heads/main"],
        "native receiver must have exactly its enrolled main ref",
    )
    git(repo, "fsck", "--strict", "--no-progress")


def signed_config(path, *, expected):
    require(
        expected
        and DIGEST.fullmatch(expected)
        and path.name == "receiver.json"
        and not path.is_symlink(),
        "select an explicitly pinned prepared configuration",
    )
    raw = path.read_bytes()
    require(
        sha(raw) == expected, "prepared configuration differs from its operator pin"
    )
    source = path.resolve().parent
    cfg = json.loads(raw)
    require(
        json.loads((source / "sealed.json").read_bytes())
        == {"configuration": sha(canonical(cfg))},
        "prepared config seal mismatch",
    )
    for key, relative in (
        ("authority", "authority"),
        ("journal", "journal"),
        ("repo", "repository.git"),
        ("publishingKeys", "publishing"),
    ):
        require(
            cfg[key] == str(source / relative) and not (source / relative).is_symlink(),
            "prepared source escaped its selected administrative directory",
        )
    require(
        sha(canonical(json.loads((source / "authority/root.json").read_bytes())))
        == cfg["rootDigest"]
        and sha(canonical(json.loads((source / "authority/genesis.json").read_bytes())))
        == cfg["genesisDigest"],
        "prepared roots differ from selected configuration",
    )
    return source, cfg


def copy_regular(source, dest):
    """Snapshot private data safely from an offline, operator-selected prepared instance."""
    require(
        source.is_dir() and not source.is_symlink(),
        "missing regular prepared directory",
    )
    dest.mkdir(parents=True, exist_ok=True)
    fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:

        def on_error(error):
            raise error

        for rel, dirs, files, dir_fd in os.fwalk(".", dir_fd=fd, onerror=on_error):
            target = dest / rel
            target.mkdir(parents=True, exist_ok=True)
            for name in dirs:
                require(
                    stat.S_ISDIR(
                        os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode
                    ),
                    "linked prepared directory refused",
                )
            for name in files:
                with os.fdopen(
                    os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd
                    ),
                    "rb",
                ) as handle:
                    facts = os.fstat(handle.fileno())
                    require(
                        stat.S_ISREG(facts.st_mode), "special prepared file refused"
                    )
                    with (target / name).open("xb") as out:
                        shutil.copyfileobj(handle, out)
                    require(
                        (target / name).stat().st_size == facts.st_size
                        and os.fstat(handle.fileno()).st_mtime_ns == facts.st_mtime_ns,
                        "source file changed while being copied",
                    )
    finally:
        os.close(fd)


@contextlib.contextmanager
def prepared_lock(source):
    # Coordinate with the original receiver and operator_cli.stage before snapshotting an existing state.
    # A freshly installed genesis may have no lock inode yet; assign it to the source journal owner.
    journal = source / "journal"
    flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    path = journal / "publication.lock"
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o660)
        if os.geteuid() == 0:
            owner = journal.stat()
            os.fchown(fd, owner.st_uid, owner.st_gid)
    except FileExistsError:
        fd = os.open(path, flags | os.O_RDONLY)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "irregular prepared receiver lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def prepare_copy(config, expected, state, release, lean):
    source, cfg = signed_config(config, expected=expected)
    with prepared_lock(source):
        source, cfg = signed_config(config, expected=expected)
        return copy_locked_state(source, cfg, state, release, lean)


def copy_locked_state(source, cfg, state, release, lean):
    state.mkdir(mode=0o700)
    for part in ("authority", "journal", "publishing"):
        copy_regular(source / part, state / part)
    incoming = source / "repository.git"
    repo = state / "repository.git"
    require(
        not any(
            (incoming / "objects/info" / x).exists()
            for x in ("alternates", "http-alternates")
        ),
        "prepared source with external object alternates must be materialized",
    )
    # Parse only object/ref format as inert data. No Git command runs with the source's local
    # config; this excludes hooks, includes, fsmonitor, external commands and remote configuration.
    configs = run(
        "/usr/bin/git",
        "config",
        "--no-includes",
        "--null",
        "--file",
        incoming / "config",
        "--list",
    )
    formats = {}
    for line in configs.split(b"\0")[:-1]:
        key, _, value = line.partition(b"\n")
        if key in (b"extensions.refstorage", b"extensions.objectformat"):
            require(key not in formats, "ambiguous source Git format")
            formats[key] = value.decode()
    refkind = formats.get(b"extensions.refstorage", "files")
    fmt = formats.get(b"extensions.objectformat", "sha1")
    if refkind == "files":
        require(
            (incoming / "HEAD").read_bytes() == b"ref: refs/heads/main\n",
            "unexpected prepared HEAD",
        )
    require(
        refkind in ("files", "reftable") and fmt in ("sha1", "sha256"),
        "unsupported prepared Git format",
    )
    run(
        "/usr/bin/git",
        "init",
        "--bare",
        "--initial-branch=main",
        "--template=",
        "--object-format=" + fmt,
        "--ref-format=" + refkind,
        repo,
    )
    for child in ("objects", "refs", "logs", "reftable"):
        if (incoming / child).is_dir():
            if (repo / child).exists():
                shutil.rmtree(repo / child)
            copy_regular(incoming / child, repo / child)
    if refkind == "files" and (incoming / "packed-refs").is_file():
        require(
            not (incoming / "packed-refs").is_symlink(), "linked prepared refs refused"
        )
        shutil.copyfile(incoming / "packed-refs", repo / "packed-refs")
    # Do not trust a prepared hook command or any other source Git setting.
    for hook in ("pre-receive", "reference-transaction"):
        target = state / "hooks" / hook
        target.parent.mkdir(exist_ok=True)
        phase = f'#!/bin/sh\nexec {PYTHON} -I -B {release}/safe_push/receiver.py hook {state}/receiver.json {hook} "$@"\n'
        target.write_text(phase)
        target.chmod(0o750)
    main = git(repo, "rev-parse", "refs/heads/main").decode().strip()
    independent_git(repo, state / "hooks")
    require(
        git(repo, "rev-parse", "refs/heads/main").decode().strip() == main,
        "prepared main ref changed during copy",
    )
    old_witness = Path(cfg["witness"])
    require(
        old_witness.is_absolute(),
        "independent checkpoint must have an absolute location",
    )
    with os.fdopen(
        os.open(old_witness, os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDONLY), "rb"
    ) as f:
        facts = os.fstat(f.fileno())
        require(
            stat.S_ISREG(facts.st_mode) and 0 < facts.st_size <= 65536,
            "expected an independently operated checkpoint JSON file",
        )
        witness = f.read(facts.st_size + 1)
    floor = json.loads(witness)
    require(
        len(witness) == facts.st_size
        and set(floor) == {"epoch", "project", "policy", "branchFloor", "receiptDigest"}
        and floor["project"] == cfg["project"]
        and type(floor["epoch"]) is int
        and floor["epoch"] >= 0
        and all(DIGEST.fullmatch(floor[k]) for k in ("policy", "receiptDigest"))
        and OBJECT.fullmatch(floor["branchFloor"]),
        "invalid independent checkpoint",
    )
    new_witness = state / "witness/epoch.json"
    new_witness.parent.mkdir()
    new_witness.write_bytes(witness)
    cfg.update(
        repo=str(repo),
        authority=str(state / "authority"),
        journal=str(state / "journal"),
        publishingKeys=str(state / "publishing"),
        witness=str(new_witness),
        leanHome=str(lean),
    )
    (state / "receiver.json").write_bytes(canonical(cfg))
    (state / "sealed.json").write_bytes(
        canonical({"configuration": sha(canonical(cfg))})
    )
    return state / "receiver.json"


def as_publisher(name, gid, *argv, env=None):
    return run(
        "/usr/bin/setpriv",
        "--reuid=" + name,
        "--regid=" + str(gid),
        "--clear-groups",
        "--no-new-privs",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        *argv,
        env=env,
    )


def bootstrap(args, base, state, release, lean, publisher, gid):
    """Bootstrap the selected receiver and its enrolled observer as the dedicated service UID."""
    with tempfile.TemporaryDirectory(dir=base, prefix=".bootstrap-") as d:
        inputs = Path(d)
        policy = json.loads(args.policy.read_bytes())
        needed = [policy["genesis"], policy["assurancePin"]]
        require(
            all(isinstance(x, str) and OBJECT.fullmatch(x) for x in needed),
            "invalid enrolled Git identity",
        )
        repo = inputs / "input.git"
        fmt = git(args.source, "rev-parse", "--show-object-format").strip().decode()
        require(fmt in ("sha1", "sha256"), "unsupported input repository")
        run(
            "/usr/bin/git",
            "init",
            "--bare",
            "--initial-branch=main",
            "--template=",
            "--object-format=" + fmt,
            repo,
        )
        with tempfile.TemporaryFile() as pack:
            subprocess.run(
                [
                    "/usr/bin/git",
                    "--no-replace-objects",
                    "-c",
                    "safe.directory=" + str(args.source.resolve()),
                    "-C",
                    args.source,
                    "pack-objects",
                    "--stdout",
                    "--revs",
                    "--quiet",
                ],
                input=("\n".join(needed) + "\n").encode(),
                stdout=pack,
                check=True,
            )
            pack.seek(0)
            run(
                "/usr/bin/git",
                "-C",
                repo,
                "index-pack",
                "--strict",
                "--stdin",
                stdin=pack,
            )
        for tag, rev in zip(("main", "oracle"), needed, strict=True):
            git(repo, "update-ref", "refs/heads/" + tag, rev)
        (inputs / "policy.json").write_bytes(canonical(policy))
        shutil.copyfile(args.publisher_key, inputs / "publisher.key")
        copy_regular(args.evidence, inputs / "evidence")
        cmd = [
            PYTHON,
            "-I",
            "-B",
            release / "safe_push/operator_cli.py",
            "install",
            "--root",
            state,
            "--source",
            repo,
            "--policy",
            inputs / "policy.json",
            "--evidence",
            inputs / "evidence",
            "--publisher-key",
            inputs / "publisher.key",
            "--lean-home",
            lean,
        ]
        if args.cost_baseline:
            shutil.copyfile(args.cost_baseline, inputs / "cost-baseline.json")
            cmd.extend(["--cost-baseline", inputs / "cost-baseline.json"])
        for flag, paths in (
            ("--observer-key", args.observer_key),
            ("--method", args.method),
        ):
            for i, file in enumerate(paths):
                dest = inputs / (flag[2:] + str(i))
                shutil.copyfile(file, dest)
                cmd.extend([flag, dest])
        protect(inputs, gid)
        # The installer creates a fresh state, while sticky protection keeps existing
        # root-owned release, toolchain and private provisioning inputs in place.
        os.chown(base, 0, gid)
        base.chmod(0o3770)
        try:
            as_publisher(
                publisher,
                gid,
                *cmd,
                env={
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "safe.directory",
                    "GIT_CONFIG_VALUE_0": str(repo),
                },
            )
        finally:
            base.chmod(0o550)
    independent_git(state / "repository.git", state / "hooks")
    return state / "receiver.json"


def protected_parent(path, public=True):
    path.mkdir(mode=0o755 if public else 0o750, parents=True, exist_ok=True)
    require(
        path.resolve() == path
        and path.stat().st_uid == 0
        and not path.stat().st_mode & 0o022,
        "native installation path must have independent root ownership: " + str(path),
    )


def verify_service_uid(instance, publisher, gid):
    _base, state, release, lean = private_paths(instance)
    script = """
import os, sys
from pathlib import Path
root, config = map(Path,sys.argv[1:3])
sys.path.insert(0,str(root/"safe_push"))
from admission import state
from authority import signature,public_der,digest,authentic
cfg,authority,journal,repo,policy=state(config)
key=Path(cfg["publishingKeys"])/(digest(public_der(policy["keys"]["publisher"]))+".key")
challenge={"nativeReceiver":"readback","project":policy["project"]}
assert authentic(signature(challenge,key),policy["keys"]["publisher"],"native.publisher")==challenge
assert all(os.access(p,os.R_OK) and not os.access(p,os.W_OK) for p in (key, authority,authority/"root.json",config,
    config.parent/"sealed.json",Path(cfg["witness"]),repo,repo/"config",repo/"HEAD",repo/"objects/info",root/"safe_push/receiver.py",
    config.parent/"hooks",config.parent/"hooks/pre-receive",Path(cfg["leanHome"])/"lib/lean/Init.olean"))
assert all(os.access(p,os.W_OK) for p in (journal,repo/"objects",repo/"reftable"))
"""
    as_publisher(
        publisher,
        gid,
        PYTHON,
        "-I",
        "-B",
        "-c",
        script,
        release,
        state / "receiver.json",
    )
    output = as_publisher(
        publisher,
        gid,
        PYTHON,
        "-I",
        "-B",
        release / "safe_push/receiver.py",
        "audit",
        state / "receiver.json",
        env={"SAFE_PUSH_LEAN_HOME": str(lean)},
    )
    return json.loads(output)


def protected_public_file(path, expected, *, executable, owner=0):
    """Check existing bytes and ownership without ever following or modifying an existing entry."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ValueError(
            "refusing an unrelated or linked Git transport file at " + str(path)
        ) from exc
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        access = 0o555 if executable else 0o444
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == owner
            and not info.st_mode & 0o7022
            and info.st_mode & access == access
            and info.st_size == len(expected)
            and source.read(len(expected) + 1) == expected,
            "existing Git transport file has different contents or unsafe ownership/mode: "
            + str(path),
        )
    return True


def install_shared_helper(path, expected, *, owner=0):
    require(
        os.geteuid() == owner,
        "shared Git helper requires its independent administrator",
    )
    if protected_public_file(path, expected, executable=True, owner=owner):
        return
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=".ocs-git-", delete=False
    ) as tmp:
        staging = Path(tmp.name)
        try:
            tmp.write(expected)
            tmp.flush()
            os.fchmod(tmp.fileno(), 0o555)
            os.fsync(tmp.fileno())
            try:
                os.link(staging, path)
            except FileExistsError:
                require(
                    protected_public_file(path, expected, executable=True, owner=owner),
                    "shared Git helper disappeared during publication",
                )
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            staging.unlink(missing_ok=True)


def install(args):
    require(
        os.geteuid() == 0 and platform.system() == "Linux",
        "native provisioning requires the Linux administrator",
    )
    base, state, release, lean = private_paths(args.instance)
    units = unit_text(args.instance, args.client_group)
    client = CLIENT_PARENT / args.instance
    protected_parent(STATE_PARENT)
    protected_parent(CLIENT_PARENT)
    protected_parent(GIT_HELPER.parent)
    protected_parent(UNIT_PARENT)
    require(OBJECT.fullmatch(args.revision), "select a full immutable receiver commit")
    helper_bytes = git(
        args.source, "cat-file", "blob", args.revision + ":safe_push/git_remote_ocs.py"
    )
    protected_public_file(GIT_HELPER, helper_bytes, executable=True)

    require(
        not any(
            p.exists() or p.is_symlink()
            for p in (base, client, *(UNIT_PARENT / n for n in units))
        ),
        "refusing to replace an existing instance, client or unit",
    )
    publisher, gid = linux_identity(args.instance, args.client_group)
    evaluator = locked_identity("ocs-me-" + args.instance)
    method_broker = broker_metadata(args.instance, pwd.getpwnam(publisher), evaluator)
    require(
        evaluator.pw_gid != grp.getgrnam(args.client_group).gr_gid,
        "evaluator cannot be a client identity",
    )
    base.mkdir(mode=0o700)
    touched = []
    try:
        os.chown(base, 0, gid)
        base.chmod(0o750)
        install_release(args.source, args.revision, release)
        protect(release, gid)
        manifest = json.loads((release / "assurance/wire/toolchain.json").read_bytes())
        provenance = pin_lean(
            lean,
            manifest,
            home=args.lean_home,
            archive=args.lean_archive,
            expected_tree=args.lean_tree_sha256,
        )
        protect(lean, gid, keep_links=True)
        if args.op == "prepare":
            config = prepare_copy(args.config, args.config_sha256, state, release, lean)
        else:
            config = bootstrap(args, base, state, release, lean, publisher, gid)
        # This describes the newly selected native deployment, even when its initial private
        # snapshot came from a different installation. No source-side metadata is modified.
        (state / "authority/broker.json").write_bytes(canonical(method_broker))
        protect_state(state, gid)
        verified = verify_service_uid(args.instance, publisher, gid)
        client.mkdir(mode=0o755)
        touched.append(client)
        shutil.copyfile(
            release / "safe_push/socket_client.py", client / "socket_client.py"
        )
        protect(client, 0, public=True)
        for name, body in units.items():
            path = UNIT_PARENT / name
            with path.open("x") as f:
                f.write(body)
            path.chmod(0o644)
            touched.append(path)
        run(
            "/usr/bin/systemd-analyze",
            "verify",
            *(UNIT_PARENT / name for name in units),
        )
        info = {
            "format": "ocs.safe-push.native-install/1",
            "instance": args.instance,
            "release": args.revision,
            "runtimeTreeSha256": tree_digest(release),
            "lean": provenance,
            "publisher": publisher,
            "methodBroker": method_broker,
            "clientGroup": args.client_group,
            "config": str(config),
            "client": str(client / "socket_client.py"),
            "gitHelperSha256": sha(helper_bytes),
            "remoteUrl": "ocs::" + args.instance,
            "socket": "/run/ocs-safe-push/" + args.instance + ".sock",
            "units": {n: sha(v.encode()) for n, v in units.items()},
            "gitRefStorage": "reftable",
            "initialReadback": verified,
        }
        (base / "native.json").write_bytes(canonical(info))
        os.chown(base / "native.json", 0, gid)
        (base / "native.json").chmod(0o440)
        base.chmod(0o550)
        # Publish the shared launcher after every instance-private asset has passed its readback.
        install_shared_helper(GIT_HELPER, helper_bytes)
        return info
    except BaseException:
        for path in reversed(touched):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        shutil.rmtree(base)
        raise


def protected_broker_file(path, expected, gid):
    facts = path.lstat()
    return (
        stat.S_ISREG(facts.st_mode)
        and facts.st_uid == 0
        and facts.st_gid == gid
        and stat.S_IMODE(facts.st_mode) == 0o440
        and path.read_bytes() == canonical(expected)
    )


def native_record(instance):
    base, state, release, lean = private_paths(instance)
    require(
        base.resolve() == base
        and base.stat().st_uid == 0
        and not base.stat().st_mode & 0o022,
        "receiver base ownership differs",
    )
    native = base / "native.json"
    require(
        not native.is_symlink()
        and native.stat().st_uid == 0
        and not native.stat().st_mode & 0o022,
        "receiver installation receipt is administratively unprotected",
    )
    record = json.loads(native.read_bytes())
    require(
        record["format"] == "ocs.safe-push.native-install/1"
        and record["instance"] == instance
        and record["config"] == str(state / "receiver.json")
        and record["runtimeTreeSha256"] == tree_digest(release)
        and record["lean"]["treeSha256"] == tree_digest(lean),
        "fixed runtime differs from its installed receipt",
    )
    for directory in (CLIENT_PARENT, CLIENT_PARENT / instance, GIT_HELPER.parent):
        require(
            directory.is_dir()
            and directory.resolve() == directory
            and directory.stat().st_uid == 0
            and not directory.stat().st_mode & 0o022,
            "public transport directory is administratively unprotected",
        )
    public_client = CLIENT_PARENT / instance / "socket_client.py"
    require(
        record["client"] == str(public_client)
        and protected_public_file(
            public_client,
            (release / "safe_push/socket_client.py").read_bytes(),
            executable=False,
        ),
        "per-instance public socket client differs from its installed release",
    )
    source_helper = release / "safe_push/git_remote_ocs.py"
    if source_helper.exists():
        expected = source_helper.read_bytes()
        require(
            record.get("remoteUrl") == "ocs::" + instance
            and record.get("gitHelperSha256") == sha(expected)
            and protected_public_file(GIT_HELPER, expected, executable=True),
            "shared Git remote helper differs from its installed release",
        )
    uses_broker = (release / "safe_push/method_worker.py").is_file()
    if uses_broker:
        evaluator = locked_identity("ocs-me-" + instance, create=False)
        pub = locked_identity(record["publisher"], create=False)
        broker = broker_metadata(instance, pub, evaluator)
        require(
            record.get("methodBroker") == broker
            and protected_broker_file(
                state / "authority/broker.json", broker, pub.pw_gid
            ),
            "evaluator endpoint or independently installed identities differ",
        )
    units = unit_text(instance, record["clientGroup"], broker=uses_broker)
    require(
        record["units"] == {n: sha(v.encode()) for n, v in units.items()}
        and all(
            not (UNIT_PARENT / n).is_symlink()
            and (UNIT_PARENT / n).stat().st_uid == 0
            and not (UNIT_PARENT / n).stat().st_mode & 0o022
            and (UNIT_PARENT / n).read_text() == v
            for n, v in units.items()
        ),
        "native service units differ from the independent configuration",
    )
    return record


def verify_live(record, caller):
    instance = record["instance"]
    base, state, _, _ = private_paths(instance)
    whose = pwd.getpwnam(caller)
    publisher = pwd.getpwnam(record["publisher"])
    group = grp.getgrnam(record["clientGroup"])
    require(
        whose.pw_uid not in (0, publisher.pw_uid)
        and group.gr_gid in os.getgrouplist(caller, whose.pw_gid),
        "read back using a distinct non-root client-group member",
    )
    socket = Path(record["socket"])
    mode = socket.lstat()
    require(
        stat.S_ISSOCK(mode.st_mode)
        and stat.S_IMODE(mode.st_mode) == 0o660
        and mode.st_uid == 0
        and mode.st_gid == group.gr_gid,
        "unexpected native socket access",
    )
    user = [
        "/usr/bin/setpriv",
        "--reuid=" + caller,
        "--regid=" + str(whose.pw_gid),
        "--init-groups",
        "--no-new-privs",
    ]
    private = run(
        *user,
        PYTHON,
        "-I",
        "-c",
        "import os,sys;print(int(all(not os.access(p,os.R_OK) and not os.access(p,os.W_OK) for p in sys.argv[1:])))",
        base,
        state / "publishing",
        state / "journal",
        state / "repository.git",
        state / "authority",
    )
    require(private.strip() == b"1", "client can access protected receiver state")
    method_probe = None
    if "methodBroker" in record:
        broker = record["methodBroker"]
        sock = Path(broker["socket"])
        meta = sock.lstat()
        require(
            sock != socket
            and stat.S_ISSOCK(meta.st_mode)
            and stat.S_IMODE(meta.st_mode) == 0o660
            and meta.st_uid == 0
            and meta.st_gid == publisher.pw_gid,
            "private evaluator socket ownership or access differs",
        )
        # A client holding only the public transport grant must not reach the private observer socket.
        denied = run(
            *user,
            PYTHON,
            "-I",
            "-c",
            "import os,sys;print(int(not os.access(sys.argv[1],os.W_OK)))",
            sock,
        )
        require(
            denied.strip() == b"1",
            "ordinary transport client can access the evaluator socket",
        )
        _, _, release, _ = private_paths(instance)
        method_probe = json.loads(
            as_publisher(
                publisher.pw_name,
                publisher.pw_gid,
                PYTHON,
                "-I",
                "-B",
                release / "safe_push/method_worker.py",
                "selftest",
                state / "receiver.json",
            )
        )
        require(
            method_probe["status"] == "pass"
            and method_probe["diagnosticOnly"] is True
            and method_probe["publisherUid"] == broker["publisherUid"]
            and method_probe["subject"]
            == json.loads((state / "receiver.json").read_bytes())["genesis"]
            and method_probe["evaluatorUid"] == broker["evaluatorUid"]
            and all(
                method_probe[k] is False
                for k in (
                    "publisherKeyReadable",
                    "journalReadable",
                    "witnessReadable",
                    "refWritable",
                )
            ),
            "separate evaluator failed protected-state readback",
        )
        result = method_probe["result"]
        require(
            set(result["claims"]) == {"S-01", "S-02", "S-03", "S-04"}
            and set(result["metrics"]) == {"wire.octets"}
            and result["metrics"]["wire.octets"]["direction"] == "min"
            and int(result["metrics"]["wire.octets"]["value"]) > 0,
            "independently executed four-frame method omitted its observations",
        )
    legacy_url = f"ext::{PYTHON} -I {record['client']} {record['socket']} %S"
    url = record.get("remoteUrl", legacy_url)
    opts = [] if "remoteUrl" in record else ["-c", "protocol.ext.allow=always"]
    remote = run(
        *user,
        "/usr/bin/git",
        *opts,
        "ls-remote",
        url,
        "refs/heads/main",
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        cwd="/",
    ).split()
    readback = verify_service_uid(instance, publisher.pw_name, publisher.pw_gid)
    require(
        remote == [readback["tip"].encode(), b"refs/heads/main"],
        "socket and independently read Git tip differ",
    )
    return {
        "socket": str(socket),
        "caller": caller,
        "publisher": publisher.pw_name,
        "tip": readback["tip"],
        "clientStateAccess": "denied",
        "methodEvaluator": method_probe,
        "url": url,
        "legacyUrl": legacy_url,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    cli = p.add_subparsers(dest="op", required=True)
    lean = cli.add_parser("lean-digest")
    lean.add_argument("directory", type=Path)
    for verb in ("install", "prepare"):
        c = cli.add_parser(verb)
        c.add_argument("--instance", required=True)
        c.add_argument("--client-group", required=True)
        c.add_argument("--source", type=Path, required=True)
        c.add_argument("--revision", required=True)
        how = c.add_mutually_exclusive_group(required=True)
        how.add_argument("--lean-archive", type=Path)
        how.add_argument("--lean-home", type=Path)
        c.add_argument("--lean-tree-sha256")
        if verb == "install":
            c.add_argument("--cost-baseline", type=Path)
            for arg in ("policy", "evidence", "publisher-key"):
                c.add_argument("--" + arg, required=True, type=Path)
            c.add_argument("--observer-key", action="append", default=[], type=Path)
            c.add_argument("--method", action="append", default=[], type=Path)
        else:
            c.add_argument("--config", type=Path, required=True)
            c.add_argument("--config-sha256", required=True)
    for op in ("activate", "verify"):
        c = cli.add_parser(op)
        c.add_argument("--instance", required=True)
        c.add_argument("--caller", required=True)
        if op == "activate":
            c.add_argument("--enable", action="store_true")
    a = p.parse_args()
    if a.op == "lean-digest":
        print(tree_digest(a.directory))
        return
    if a.op in ("install", "prepare"):
        print(json.dumps(install(a), indent=2))
        return
    require(
        os.geteuid() == 0, "native unit inspection requires administrative readback"
    )
    record = native_record(a.instance)
    if a.op == "activate":
        run("/usr/bin/systemctl", "daemon-reload")
        run(
            "/usr/bin/systemctl",
            *(["enable", "--now"] if a.enable else ["start"]),
            *(
                [f"ocs-safe-method-{a.instance}.socket"]
                if "methodBroker" in record
                else []
            ),
            f"ocs-safe-push-{a.instance}.socket",
        )
    print(json.dumps(verify_live(record, a.caller), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        print("Native receiver: " + str(error), file=sys.stderr)
        sys.exit(1)
