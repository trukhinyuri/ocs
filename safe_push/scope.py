"""Derive admission obligations from complete, authenticated Git trees as data."""

import codecs
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import unicodedata
from pathlib import Path

GUARDIAN = Path(__file__).resolve().parents[1]


class ScopeError(ValueError):
    """A reproducible incompatibility is rejected. Missing knowledge is undetermined."""

    def __init__(self, outcome, message):
        super().__init__(message)
        self.outcome = outcome


def rejected(message):
    return ScopeError("rejected", message)


def unknown(message):
    return ScopeError("undetermined", message)


def unique(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise rejected("repeated JSON member: " + name)
        value[name] = item
    return value


def parse(raw):
    def nonfinite(value):
        raise rejected("nonfinite JSON number: " + value)

    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def fingerprint(value):
    data = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(data.encode()).hexdigest()


POLICY = parse((GUARDIAN / "safe_push/coverage.json").read_bytes())
LIMIT = POLICY["limits"]
FULL_ID = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")


def git_args(repo):
    root = str(Path(repo).resolve())
    return [
        "git",
        "--no-replace-objects",
        "-c",
        "protocol.allow=never",
        "-c",
        "safe.directory=" + root,
        "-C",
        root,
    ]


def git_env():
    # receive-pack provides these object stores. Candidate blobs never supply Git configuration.
    kept = {
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_QUARANTINE_PATH",
    }
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") or k in kept}
    env.update(
        LC_ALL="C",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_TERMINAL_PROMPT="0",
        GIT_NO_LAZY_FETCH="1",
    )
    return env


def check_name(raw):
    if len(raw) > LIMIT["pathBytes"]:
        raise unknown("path exceeds the enrolled byte budget")
    try:
        name = raw.decode("utf-8")
    except UnicodeError as exc:
        raise unknown("path is outside the enrolled UTF-8 representation") from exc
    for part in name.split("/"):
        if not part or part in (".", "..") or part.casefold() == ".git":
            raise rejected("unsafe tree path: " + repr(name))
        if any(ord(c) < 32 or ord(c) == 127 for c in part):
            raise rejected("control character in tree path: " + repr(name))
        if any(c in '\\:<>|"?*' for c in part) or part.endswith((" ", ".")):
            raise unknown(
                "path lacks an enrolled portable interpretation: " + repr(name)
            )
        if re.fullmatch(
            r"con|prn|aux|nul|com[1-9]|lpt[1-9]", part.split(".")[0], re.IGNORECASE
        ):
            raise unknown("device name lacks a portable interpretation: " + repr(name))
    return name


def tree_records(raw, oid_bytes):
    """Read original modes/names from the authenticated Git tree object."""
    kinds = {
        b"40000": ("040000", "tree"),
        b"100644": ("100644", "blob"),
        b"100755": ("100755", "blob"),
        b"120000": ("120000", "blob"),
        b"160000": ("160000", "commit"),
    }
    offset, previous = 0, None
    while offset < len(raw):
        space = raw.find(b" ", offset)
        end = raw.find(b"\0", space + 1) if space != -1 else -1
        if space == -1 or end == -1 or end + 1 + oid_bytes > len(raw):
            raise rejected("malformed Git tree entry")
        candidate_mode = raw[offset:space]
        if candidate_mode not in kinds:
            raise unknown("unenrolled Git tree mode: " + repr(candidate_mode))
        mode, kind = kinds[candidate_mode]
        name = raw[space + 1 : end]
        if not name or b"/" in name:
            raise rejected("invalid Git component name")
        key = name + (b"/" if kind == "tree" else b"")
        if previous is not None and key <= previous:
            raise rejected("duplicate or unordered Git tree entries")
        offset = end + 1 + oid_bytes
        previous = key
        yield mode, kind, raw[end + 1 : offset].hex(), name


def read_object(process, oid, kind, keep=False):
    process.stdin.write(oid.encode("ascii") + b"\n")
    process.stdin.flush()
    header = process.stdout.readline(192).split()
    if len(header) != 3 or header[:2] != [oid.encode(), kind.encode()]:
        raise unknown(f"required {kind} object unavailable: {oid}")
    size = int(header[2])
    if not 0 <= size <= LIMIT["objectBytes"]:
        raise unknown(f"{kind} object outside the enrolled byte budget: {oid}")
    if keep and size > LIMIT["structuredBytes"]:
        raise unknown(f"structured object outside the enrolled byte budget: {oid}")
    gh = hashlib.new("sha1" if len(oid) == 40 else "sha256")
    gh.update(f"{kind} {size}\0".encode())
    content = hashlib.sha256()
    raw = bytearray()
    prefix = bytearray()
    decoder = codecs.getincrementaldecoder("utf-8")()
    text = kind == "blob"
    left = size
    while left:
        chunk = process.stdout.read(min(left, 262144))
        if not chunk:
            raise rejected("truncated Git object: " + oid)
        left -= len(chunk)
        content.update(chunk)
        gh.update(chunk)
        if keep:
            raw.extend(chunk)
        if len(prefix) < 4096:
            prefix.extend(chunk[: 4096 - len(prefix)])
        if text:
            try:
                decoder.decode(chunk, final=not left)
                text = b"\0" not in chunk
            except UnicodeError:
                text = False
    if process.stdout.read(1) != b"\n" or gh.hexdigest() != oid:
        raise rejected("object bytes do not match the Git identity: " + oid)
    return (
        {
            "oid": oid,
            "type": kind,
            "sha256": content.hexdigest(),
            "size": size,
            "text": text,
        },
        bytes(prefix),
        bytes(raw),
    )


def inventory(repo, commit):
    if not isinstance(commit, str) or not FULL_ID.fullmatch(commit):
        raise rejected("expected a full commit object ID")
    git, env = git_args(repo), git_env()
    objects = subprocess.Popen(
        [*git, "cat-file", "--batch"],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        _, _, body = read_object(objects, commit, "commit", keep=True)
        first = body.partition(b"\n")[0].decode("ascii").split(" ")
        if (
            len(first) != 2
            or first[0] != "tree"
            or len(first[1]) != len(commit)
            or not FULL_ID.fullmatch(first[1])
        ):
            raise rejected("invalid commit tree identity")
        _, _, root = read_object(objects, first[1], "tree", keep=True)
        result = {}
        spellings = set()
        cache = {}
        total = 0
        pending = [(b"", iter(tree_records(root, len(commit) // 2)))]
        while pending:
            parent_path, children = pending[-1]
            child = next(children, None)
            if child is None:
                pending.pop()
                continue
            mode, kind, oid, component = child
            path = parent_path + component
            name = check_name(path)
            portable = unicodedata.normalize("NFC", name).casefold()
            if portable in spellings:
                raise rejected("duplicate or portable path collision: " + name)
            spellings.add(portable)
            if len(spellings) > LIMIT["entries"]:
                raise unknown("tree exceeds the enrolled entry budget")
            if mode == "160000" and kind == "commit":
                # A gitlink records an object name in another repository.
                entry = {
                    "type": "gitlink",
                    "oid": oid,
                    "sha256": hashlib.sha256(bytes.fromhex(oid)).hexdigest(),
                    "size": len(oid) // 2,
                    "text": False,
                }
            else:
                identity = kind, oid
                if identity not in cache:
                    cache[identity] = read_object(
                        objects, oid, kind, keep=kind == "tree"
                    )
                record, prefix, subtree = cache[identity]
                entry = dict(record)
                if kind == "tree":
                    pending.append(
                        (path + b"/", iter(tree_records(subtree, len(commit) // 2)))
                    )
                if mode == "120000":
                    if len(prefix) != entry["size"] or not entry["text"] or not prefix:
                        raise unknown("invalid portable link target at " + name)
                    entry.update(type="link", target=prefix.decode())
                elif kind == "blob" and prefix.startswith(
                    b"version https://git-lfs.github.com/spec/v1"
                ):
                    entry["external"] = "lfs"
                if prefix.startswith(b"\0asm\x01\0\0\0"):
                    entry["encoding"] = "wasm-v1"
            total += entry["size"]
            if total > LIMIT["totalBytes"]:
                raise unknown("tree exceeds the enrolled expanded byte budget")
            result[name] = {"mode": mode, **entry}
        return result
    except (OSError, ValueError) as exc:
        if isinstance(exc, ScopeError):
            raise
        raise unknown("cannot read selected Git objects: " + str(exc)) from exc
    finally:
        objects.stdin.close()
        if objects.poll() is None:
            objects.terminate()
        objects.wait()
        objects.stdout.close()


def bound(repo, commit, supplied):
    actual = inventory(repo, commit)
    if fingerprint(actual) != fingerprint(supplied):
        raise rejected("supplied inventory belongs to another committed tree")
    return actual


def resolve_link(name, entries):
    pending = name.split("/")
    prefix = []
    seen = set()
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if not prefix:
                raise unknown("link escapes the admitted tree: " + name)
            prefix.pop()
            continue
        prefix.append(part)
        path = "/".join(prefix)
        node = entries.get(path)
        if node is None:
            raise unknown("link has no admitted target: " + name)
        if node["type"] == "link":
            state = (path, tuple(pending))
            if state in seen or len(seen) > len(entries):
                raise unknown("link cycle or unbounded expansion: " + name)
            seen.add(state)
            target = node["target"]
            if (
                target.startswith("/")
                or "\\" in target
                or "\0" in target
                or ":" in target
            ):
                raise unknown("external or nonportable link target: " + name)
            prefix.pop()
            pending = target.split("/") + pending
        elif pending and node["type"] != "tree":
            raise unknown("link traverses a non-directory: " + name)
    return entries["/".join(prefix)] if prefix else {"type": "tree"}


def subject(repo, commit, entries):
    entries = bound(repo, commit, entries)
    files = {}
    for path, entry in entries.items():
        actual = resolve_link(path, entries) if entry["type"] == "link" else entry
        if actual["type"] == "gitlink" or "external" in actual:
            raise unknown(
                "external content has no independently enrolled closure: " + path
            )
        if actual["type"] == "blob":
            files[path] = actual["sha256"]
    # Identical to assurance/trust.subject_identity on a clean checkout.
    return {
        "revision": commit,
        "dirty": False,
        "treeSha256": fingerprint(files),
        "fileCount": len(files),
    }


def content(repo, entries, name):
    item = entries.get(name)
    if (
        item is None
        or item["type"] != "blob"
        or not item["text"]
        or item["size"] > LIMIT["structuredBytes"]
    ):
        raise unknown("missing or unsuitable protected text input: " + name)
    proc = subprocess.run(
        [*git_args(repo), "cat-file", "blob", item["oid"]],
        check=False,
        env=git_env(),
        capture_output=True,
        timeout=60,
    )
    if (
        proc.returncode
        or len(proc.stdout) != item["size"]
        or hashlib.sha256(proc.stdout).hexdigest() != item["sha256"]
    ):
        raise rejected("protected text does not match its inventory: " + name)
    return proc.stdout


class GitView:
    """Read-only adapter for the enrolled normative checker. Paths refer only to blobs."""

    def __init__(self, repo, entries, name=None):
        self.repo, self.entries, self.name = repo, entries, name

    def __truediv__(self, name):
        if not isinstance(name, str) or check_name(name.encode()) != name:
            raise rejected("invalid normative path")
        return GitView(self.repo, self.entries, name)

    def read_bytes(self):
        return content(self.repo, self.entries, self.name)

    def read_text(self):
        return self.read_bytes().decode()


def guarded_module(name):
    # These sources are part of the enrolled guardian installation. Never import
    # from a proposed object, candidate checkout, user plugin, or candidate config.
    filename = GUARDIAN / "assurance" / (name + ".py")
    spec = importlib.util.spec_from_file_location(
        "safe_push_enrolled_" + name, filename
    )
    if spec is None or spec.loader is None:
        raise unknown("missing installed normative checker " + name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def classify(path, entry):
    if entry["type"] == "tree":
        if path.split("/", 1)[0] not in POLICY["directoryRoots"]:
            raise unknown("unclassified directory: " + path)
        return {"id": "directory", "policy": False, "requirements": ["tree.object"]}
    if entry["type"] == "gitlink" or entry.get("external"):
        raise unknown("independent external object closure missing: " + path)
    matches = [c for c in POLICY["classes"] if re.fullmatch(c["pattern"], path)]
    if not matches:
        raise unknown("unclassified tree object: " + path)
    rule = matches[0]
    if entry["type"] == "link":
        return {
            **rule,
            "requirements": sorted(
                set(rule["requirements"])
                | {"tree.object", "artifact.provenance", "platform.portability"}
            ),
        }
    if rule["id"] == "wasm":
        if entry.get("encoding") != "wasm-v1":
            raise unknown("binary does not match its enrolled format: " + path)
    elif not entry["text"]:
        raise unknown("unexpected binary content in a text category: " + path)
    if entry["mode"] == "100755" and not (
        path.endswith((".py", ".sh"))
        or path == "reference/go/run"
        or rule["id"] in {"guardian", "wasm"}
    ):
        raise unknown("unenrolled executable interpretation: " + path)
    return rule


def json_file(repo, entries, name):
    try:
        return parse(content(repo, entries, name))
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ScopeError):
            raise
        raise rejected("invalid protected JSON: " + name) from exc


def subset(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            k in actual and subset(v, actual[k]) for k, v in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(subset(a, b) for a, b in zip(expected, actual))
        )
    return type(expected) is type(actual) and expected == actual


def by_id(rows, label):
    if not isinstance(rows, list) or any(
        not isinstance(r, dict) or not isinstance(r.get("id"), str) or not r["id"]
        for r in rows
    ):
        raise rejected("invalid " + label + " identity")
    mapping = {r["id"]: r for r in rows}
    if len(mapping) != len(rows):
        raise rejected("duplicate " + label + " identity")
    return mapping


def check_cases(previous, proposed):
    old, new = by_id(previous, "case"), by_id(proposed, "case")
    for name, case in old.items():
        if name not in new:
            raise rejected("removed published case: " + name)
        updated = new[name]
        if case.get("rule") != updated.get("rule"):
            raise rejected("changed published rule attribution: " + name)
        remaining = iter(updated["steps"])
        for n, oldstep in enumerate(case["steps"], 1):
            request = {k: v for k, v in oldstep.items() if k != "expect"}
            for step in remaining:
                new_request = {k: v for k, v in step.items() if k != "expect"}
                if fingerprint(request) == fingerprint(new_request) and subset(
                    oldstep.get("expect"), step.get("expect")
                ):
                    break
            else:
                raise rejected(
                    f"removed or weakened published interaction: {name} (step {n})"
                )
    return new


def scenario_links(scenarios):
    links = {}
    for doc, rules in scenarios["requirements"].items():
        check_name(doc.encode())
        for rule, names in rules.items():
            if (
                rule in links
                or not names
                or len(set(names)) != len(names)
                or not set(names) <= scenarios["scenarios"].keys()
            ):
                raise rejected("invalid scenario links for rule " + rule)
            links[rule] = set(names)
    return links


def atoms(catalog, scenarios):
    groups = catalog["groups"]
    links = scenario_links(scenarios)
    if set(links) | set(catalog["extraLocators"]) != set(groups):
        raise rejected("unaccounted normative or additional rule")
    claims = {}
    for rule, group in groups.items():
        for name, c in by_id(group["claims"], rule).items():
            levels = c["levels"]
            if (
                not levels
                or len(levels) != len(set(levels))
                or not all(isinstance(level, str) and level for level in levels)
            ):
                raise rejected("invalid evidence levels for " + rule + "." + name)
            claims[rule + "." + name] = {
                "rule": rule,
                "role": group["role"],
                "profile": group["profile"],
                "criterion": c["expected"],
                "levels": sorted(levels),
            }
    return claims


def retained_sets(previous, proposed, label):
    if not isinstance(previous, dict) or not isinstance(proposed, dict):
        raise rejected("invalid protected map: " + label)
    for key, names in proposed.items():
        if not isinstance(names, list) or not all(
            isinstance(n, str) and n for n in names
        ):
            raise rejected("invalid protected members: " + label + "/" + key)
        if len(names) != len(set(names)):
            raise rejected("duplicate protected member: " + label + "/" + key)
    for key, names in previous.items():
        if key not in proposed:
            raise rejected("removed protected identity: " + label + "/" + key)
        missing = set(names) - set(proposed[key])
        if missing:
            raise rejected(
                "removed protected attribution: "
                + label
                + "/"
                + key
                + "/"
                + ", ".join(sorted(missing))
            )


def semantic_checks(repo, before, after):
    """Reconstruct published obligations from data before considering independent reviews."""
    remarks = {}
    corpus = "conformance/cases/core.json"
    ledger = "conformance/scenarios.json"
    catalog = "assurance/obligations.json"

    def retained(name):
        if name in before and name not in after:
            raise rejected("removed protected contract file: " + name)
        return name in after

    if retained(corpus):
        cases = check_cases(
            json_file(repo, before, corpus) if corpus in before else [],
            json_file(repo, after, corpus),
        )
    else:
        cases = {}
    old_index = (
        json_file(repo, before, ledger)
        if ledger in before
        else {"requirements": {}, "scenarios": {}}
    )
    index = json_file(repo, after, ledger) if retained(ledger) else old_index
    old_links = scenario_links(old_index)
    new_links = scenario_links(index)
    for rule, names in old_links.items():
        if rule not in new_links or names - new_links[rule]:
            raise rejected("lost published scenario attribution: " + rule)
    for name, s in old_index["scenarios"].items():
        if name not in index["scenarios"]:
            raise rejected("removed published scenario: " + name)
        new = index["scenarios"][name]
        if s["checks"] and not new["checks"]:
            raise rejected("published scenario lost all checks: " + name)
        missing = {test for test in s["checks"] if "#" not in test} - set(new["checks"])
        if missing:
            raise rejected(
                f"removed public scenario link {name}: {', '.join(sorted(missing))}"
            )
        if any(s.get(k) != new.get(k) for k in ("scope", "expect", "qualification")):
            remarks["scenario:" + name] = [fingerprint(s), fingerprint(new)]
        relocated = set(s["checks"]) - set(new["checks"])
        if relocated:
            remarks["scenario-check:" + name] = sorted(relocated)
    if ledger in after:
        for name, c in cases.items():
            names = [
                n
                for rules in index["requirements"].values()
                for n in rules.get(c["rule"], [])
            ]
            if not any(
                name in index["scenarios"].get(n, {}).get("checks", []) for n in names
            ):
                raise rejected("unaccounted executable case: " + name)
    current_claims = {}
    owners = {}
    if retained(catalog):
        new_catalog = json_file(repo, after, catalog)
        current_claims = atoms(new_catalog, index)
        for candidate in (old_index, index):
            for document, rules in candidate["requirements"].items():
                owners.setdefault(document, set()).update(rules)
        for doc_catalog in [new_catalog] + (
            [json_file(repo, before, catalog)] if catalog in before else []
        ):
            for rule, locator in doc_catalog["extraLocators"].items():
                owners.setdefault(locator[0], set()).add(rule)
        if catalog in before:
            old_catalog = json_file(repo, before, catalog)
            old_claims = atoms(old_catalog, old_index)
            for atom, old in old_claims.items():
                if atom not in current_claims:
                    raise rejected("removed atomic obligation: " + atom)
                new = current_claims[atom]
                if set(old["levels"]) - set(new["levels"]):
                    raise rejected("weakened required evidence level: " + atom)
                if (old["role"], old["profile"], old["criterion"]) != (
                    new["role"],
                    new["profile"],
                    new["criterion"],
                ):
                    remarks["atom:" + atom] = [fingerprint(old), fingerprint(new)]
    else:
        new_catalog = {
            "groups": {k: {} for d in index["requirements"].values() for k in d}
        }
    if retained("version.json"):
        structure = guarded_module("structure")
        if catalog not in after:
            new_catalog["groups"].update(
                {
                    k: {}
                    for k in (
                        *structure.EXTRA.values(),
                        *structure.INTRO.values(),
                        "wire.error-table",
                    )
                }
            )
            for p in json_file(repo, after, "version.json")["normative"]:
                if p.endswith(".md"):
                    for k in re.findall(
                        r"\*\*([A-Z]-[0-9]{2})\b", content(repo, after, p).decode()
                    ):
                        new_catalog["groups"][k] = {}
        for table in (before, after):
            if "version.json" in table:
                version = json_file(repo, table, "version.json")
                files = version["normative"]
                if not isinstance(files, list) or len(files) != len(set(files)):
                    raise rejected("invalid normative inventory")
                normative_sources = {
                    name
                    for name, entry in table.items()
                    if entry["type"] != "tree"
                    and name.startswith(("spec/", "schemas/"))
                }
                if normative_sources != set(files):
                    difference = sorted(normative_sources ^ set(files))
                    raise unknown(
                        "normative source lacks an enrolled edition interpretation: "
                        + ", ".join(difference)
                    )
                for f in files:
                    if f.endswith(".json"):
                        json_file(repo, table, f)
        if "version.json" in before:
            old_catalog = (
                json_file(repo, before, catalog) if catalog in before else new_catalog
            )
            old_struct = structure.inventory(GitView(repo, before), old_catalog)
            new_struct = structure.inventory(GitView(repo, after), new_catalog)
            for problem in structure.compare(old_struct, new_struct):
                if problem.startswith("removed normative item "):
                    raise rejected(problem)
                remarks["normative:" + problem] = True
    if "assurance/scope.json" in before:
        if not retained("assurance/scope.json"):
            raise rejected("removed accepted qualification scope")
        old = json_file(repo, before, "assurance/scope.json")
        new = json_file(repo, after, "assurance/scope.json")
        if fingerprint(old) != fingerprint(new):
            remarks["accepted-contour"] = [fingerprint(old), fingerprint(new)]
    evidence_index = "assurance/evidence-index.json"
    if retained(evidence_index):
        new = json_file(repo, after, evidence_index)
        old = (
            json_file(repo, before, evidence_index) if evidence_index in before else {}
        )
        for field in ("controlIds", "checks"):
            retained_sets(old.get(field, {}), new[field], evidence_index + "/" + field)
    return current_claims, remarks, owners


def proof_only(repo, name, old, new):
    """Preserve the enrolled language and every existing public theorem proposition."""
    tools = guarded_module("interaction/lean_tools")
    before = content(repo, old, name).decode()
    after = content(repo, new, name).decode()
    try:
        tools.protected_lean_unit(before, after, name)
        previous, proposed = tools.declarations(before), tools.declarations(after)
    except (ValueError, IndexError):
        return False
    return all(
        proposed.get(theorem) == challenge for theorem, challenge in previous.items()
    )


def only_editorial_contract(repo, name, old, new):
    """A narrowly recognized equality. A change outside it needs a contract proof."""
    if (
        name not in old
        or name not in new
        or old[name]["type"] != "blob"
        or new[name]["type"] != "blob"
    ):
        return False
    if old[name]["mode"] != new[name]["mode"]:
        return False
    if name.endswith(".json"):
        return fingerprint(json_file(repo, old, name)) == fingerprint(
            json_file(repo, new, name)
        )

    def normative_lines(source):
        informative = False
        fenced = False
        result = []
        for line in source.decode().splitlines():
            if line.startswith(("~~~", chr(96) * 3)):
                fenced = not fenced
            if not fenced and line.startswith("#"):
                informative = bool(
                    re.fullmatch(r"## (?:Informative references|Run the checks)", line)
                )
                result.append(line)
            elif not informative:
                result.append(line)
        return result

    return normative_lines(content(repo, old, name)) == normative_lines(
        content(repo, new, name)
    )


def change_requirements(repo, parent, candidate, old_inventory, new_inventory):
    old = bound(repo, parent, old_inventory)
    new = bound(repo, candidate, new_inventory)
    # A previously unclassified committed entry cannot become an exemption just
    # because its bytes did not change in this transition.
    assigned = []
    for entries in (old, new):
        coverage = {}
        for name, entry in entries.items():
            coverage[name] = classify(name, entry)
            if entry["type"] == "link":
                resolve_link(name, entries)
        assigned.append(coverage)
    old_classes, new_classes = assigned
    try:
        claims, remarks, owners = semantic_checks(repo, old, new)
    except ScopeError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError, OSError) as exc:
        raise rejected(
            "invalid or unclassified normative interpretation: " + str(exc)
        ) from exc
    changes = []
    associated = {rid: set() for rid in POLICY["base"]}
    policy_change = False
    for name in sorted(old.keys() | new.keys()):
        a, b = old.get(name), new.get(name)
        if a == b:
            continue
        old_class, new_class = old_classes.get(name), new_classes.get(name)
        classes = [c for c in (old_class, new_class) if c]
        action = (
            "add"
            if a is None
            else "remove"
            if b is None
            else "type"
            if a["type"] != b["type"]
            else "mode"
            if a["mode"] != b["mode"]
            else "modify"
        )
        categories = sorted({c["id"] for c in classes})
        # An ordinary directory OID changes when its contents change. Retain that
        # fact in the inventory/diff but qualify substantive leaf changes below.
        directory_only = (
            a is not None and b is not None and a["type"] == b["type"] == "tree"
        )
        req = (
            set()
            if directory_only
            else {req for c in classes for req in c["requirements"]}
        )
        if not directory_only and (a is None or b is None or a["mode"] != b["mode"]):
            req.add("tree.object")
        if (
            not directory_only
            and action in ("remove", "type")
            and a["type"] != "tree"
            and "documentation" not in categories
        ):
            req.add("change.retirement")
        if (
            "contract" in categories or "delivery" in categories
        ) and only_editorial_contract(repo, name, old, new):
            req.discard("contract.relation")
            req.add("docs.meaning")
        if not directory_only and any(c["id"] != "directory" for c in classes):
            req.update(POLICY["scientificDisposition"])
        protected = any(c["policy"] for c in classes)
        if "corpus" in categories and name.endswith((".py", "_test.go")):
            # Executable assertions, setup, test discovery and shared helpers
            # determine future oracle behavior. Keep the incumbent authoritative.
            protected = True
        if "proof" in categories and (
            name not in POLICY["pureProofSubjects"]
            or not a
            or not b
            or not proof_only(repo, name, old, new)
        ):
            protected = True
        if protected:
            policy_change = True
            req.update(("policy.transition", "policy.independent"))
        delta = {
            "path": name,
            "action": action,
            "categories": categories,
            "before": a,
            "after": b,
            "requirements": sorted(req),
        }
        changes.append(delta)
        for rid in req:
            associated.setdefault(rid, set()).add(name)
    all_paths = {r["path"] for r in changes if r["categories"] != ["directory"]}
    if remarks:
        policy_change = True
        for rid in (
            "contract.relation",
            "contract.domain",
            "policy.transition",
            "policy.independent",
        ):
            associated.setdefault(rid, set()).update(all_paths)
    diff_digest = fingerprint(changes)
    requirements = {}
    levels = {cid: row["levels"] for cid, row in sorted(claims.items())}
    for rid, names in sorted(associated.items()):
        template = POLICY["templates"][rid]
        paths = sorted(names or all_paths)
        # A provider, program, shared test or checker can affect consumers in
        # every profile. Only a directly attributed prose change is narrower.
        attributable = (
            rid in ("contract.domain", "docs.meaning")
            and bool(paths)
            and all(p in owners for p in paths)
        )
        affected = set().union(*(owners[p] for p in paths)) if attributable else set()
        row = {
            "id": rid,
            **template,
            "paths": paths,
            "claims": sorted(
                k
                for k, c in claims.items()
                if not attributable or c["rule"] in affected
            ),
            "claimScope": "direct-rule-attribution"
            if attributable
            else "whole-enrolled-contour",
        }
        if rid == "qualification.full":
            row["levels"] = levels
        row["digest"] = fingerprint(
            {
                "guardianCoverage": fingerprint(POLICY),
                "parent": parent,
                "candidate": candidate,
                "delta": diff_digest,
                "obligation": row,
                "semanticChanges": remarks,
            }
        )
        requirements[rid] = row
    return {
        "format": "ocs.safe-push.change-scope/1",
        "changes": changes,
        "requirements": requirements,
        "policyChange": policy_change,
        "semanticChanges": remarks,
        "wholeTreeSha256": fingerprint(new),
        "priorTreeSha256": fingerprint(old),
    }
