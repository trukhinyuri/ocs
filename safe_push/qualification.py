"""Authenticate a full OCS qualification and recover its enrolled comparison cells offline."""

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
GIT_ID = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
SHA256 = re.compile(r"[a-f0-9]{64}")
FILE_LIMIT = 64 * 1024 * 1024
TOTAL_LIMIT = 256 * 1024 * 1024


class QualificationError(ValueError):
    """The submitted material does not establish a current full qualification."""


def require(ok, reason):
    if not ok:
        raise QualificationError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key " + key)
        value[key] = item
    return value


def decode(raw, *, exact=False):
    def finite(value):
        raise QualificationError("nonfinite JSON number " + value)

    return json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=finite,
        parse_float=Decimal if exact else float,
    )


def stamp(text):
    value = datetime.fromisoformat(text)
    require(value.utcoffset() is not None, "receipt time has no timezone")
    return value.astimezone(UTC)


def check_name(name):
    parts = name.split("/")
    require(
        bool(name)
        and all(p not in ("", ".", "..") for p in parts)
        and "\\" not in name
        and "\0" not in name,
        "unsafe receipt or repository path",
    )
    return name


def bytes_at(name, dir_fd=None, limit=FILE_LIMIT):
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(name, flags, dir_fd=dir_fd), "rb") as f:
        s = os.fstat(f.fileno())
        require(
            stat.S_ISREG(s.st_mode) and 0 < s.st_size <= limit,
            "invalid file " + str(name),
        )
        raw = f.read(s.st_size + 1)
        require(len(raw) == s.st_size, "file changed during snapshot " + str(name))
        return raw


def snapshot_dossier(source, dest):
    """Open relative to directory descriptors so a renamed link cannot escape the input."""
    names, total = set(), 0
    dest.mkdir()
    fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:

        def on_error(exc):
            raise exc

        for folder, dirs, files, current in os.fwalk(".", dir_fd=fd, onerror=on_error):
            require(
                len(names) + len(files) <= 4096, "receipt exceeds snapshot file limit"
            )
            for name in dirs:
                require(
                    stat.S_ISDIR(
                        os.stat(name, dir_fd=current, follow_symlinks=False).st_mode
                    ),
                    "linked or irregular receipt directory",
                )
            for name in files:
                path = check_name(str(PurePosixPath(folder) / name))
                raw = bytes_at(name, current)
                total += len(raw)
                require(total <= TOTAL_LIMIT, "receipt exceeds snapshot byte limit")
                require(path not in names, "duplicate receipt path")
                names.add(path)
                target = dest / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
    finally:
        os.close(fd)
    return names


def git(repo, *argv, data=None):
    p = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "-c",
            "safe.directory=" + str(repo.resolve()),
            "-C",
            str(repo),
            *argv,
        ],
        check=False,
        input=data,
        capture_output=True,
        timeout=60,
    )
    require(
        p.returncode == 0,
        "object unavailable from independently selected Git authority",
    )
    return p.stdout


DATA_NAMES = {
    "version.json",
    "assurance/obligations.json",
    "assurance/scope.json",
    "assurance/evidence-index.json",
    "assurance/tooling.json",
    "conformance/scenarios.json",
    "conformance/cases/core.json",
    "stand/kubernetes/policy.json",
}
CHECKER_NAMES = {
    "assurance/trust.py",
    "assurance/structure.py",
    "assurance/verify_receipt.py",
}


def export_commit(repo, rev, destination, *, checker=False):
    """Hash the tracked clean Git bytes. Export only normative data or independently pinned code."""
    require(
        isinstance(rev, str)
        and GIT_ID.fullmatch(rev)
        and git(repo, "cat-file", "-t", rev).strip() == b"commit",
        "expected a full commit object",
    )
    listing = git(repo, "ls-tree", "-r", "-l", "-z", rev).split(b"\0")[:-1]
    entries = []
    for entry in listing:
        header, name = entry.split(b"\t", 1)
        mode, kind, oid, size = header.split()
        require(
            mode in (b"100644", b"100755") and kind == b"blob",
            "clean file-content subject profile requires regular Git blobs",
        )
        entries.append((check_name(name.decode()), oid, int(size)))
    require(
        len(entries) <= 65536 and sum(n for _, _, n in entries) <= TOTAL_LIMIT,
        "Git subject exceeds comparison profile bounds",
    )
    want = DATA_NAMES | (CHECKER_NAMES if checker else set())
    selected = [
        (name, oid, n)
        for name, oid, n in entries
        if not checker
        or name in want
        or name.startswith(("spec/", "schemas/", "assurance/"))
    ]
    objects = io.BytesIO(
        git(
            repo,
            "cat-file",
            "--batch",
            data=b"".join(oid + b"\n" for _, oid, _ in selected),
        )
    )
    hashes = {}
    for name, oid, size in selected:
        require(
            objects.readline().split() == [oid, b"blob", str(size).encode()],
            "unrecognized Git object stream",
        )
        raw = objects.read(size)
        require(
            len(raw) == size and objects.read(1) == b"\n", "truncated Git object stream"
        )
        hashes[name] = sha(raw)
        if name in want or name.startswith(("spec/", "schemas/")):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    require(
        objects.read(1) == b"" and want <= hashes.keys(),
        "required edition data missing",
    )
    (destination / "git-file-digests.json").write_bytes(canonical(hashes))
    edition = decode((destination / "version.json").read_bytes())
    for name in edition["normative"]:
        require(
            check_name(name) in hashes
            and name.startswith(("spec/", "schemas/"))
            and name.endswith((".md", ".json")),
            "unsupported normative locator",
        )
    return {
        "revision": rev,
        "dirty": False,
        "treeSha256": sha(canonical(hashes)),
        "fileCount": len(hashes),
    }


def artifact_inventory(directory, names, inventory):
    require(
        isinstance(inventory, dict)
        and inventory
        and {p for p in names if p.startswith("evidence/")} == set(inventory),
        "detached evidence file inventory differs from signed aggregate",
    )
    for name, expected in inventory.items():
        raw = (directory / check_name(name)).read_bytes()
        require(
            type(expected.get("bytes")) is int
            and expected == {"sha256": sha(raw), "bytes": len(raw)},
            "detached bytes or size changed: " + name,
        )


def verify_reference(
    directory, pinned, evidence, baseline, extra_cases, platform, interval
):
    """Corroborate the historical diagnostics against the enrolled cases and signed suite counts."""
    core = next(
        r["observed"] for r in evidence["checks"] if r["id"] == "core.qualify-edition"
    )
    paths = {
        f"reference/baseline/{baseline}/{s}.json": v
        for s, v in core["mixedVersions"].items()
    }
    paths["reference/conformance.json"] = {
        "checks": core["wireCases"],
        "digest": sha((pinned / "conformance/cases/core.json").read_bytes()),
    }
    require(
        set(paths)
        == {
            "reference/conformance.json",
            f"reference/baseline/{baseline}/hosts-and-go.json",
            f"reference/baseline/{baseline}/python-executor.json",
        },
        "unrecognized historical reference contour",
    )
    corpus = {
        r["id"]: r["rule"]
        for r in decode((pinned / "conformance/cases/core.json").read_bytes())
    }
    full_cases = {
        **corpus,
        **{"go-executor-" + k: v for k, v in corpus.items()},
        **extra_cases,
    }
    exemplar = decode(
        (directory / "evidence/wire-evidence/published-python.json").read_bytes()
    )
    for path, fixture in paths.items():
        data = decode((directory / path).read_bytes())
        subset = path.endswith("python-executor.json")
        expected = corpus if subset else full_cases
        seen = {
            r["id"]: r["rule"]
            for r in data["checks"]
            if r
            == {
                "id": r["id"],
                "rule": r["rule"],
                "status": "pass",
                "detail": "Observed expected behavior.",
            }
        }
        repeated = (
            "edition",
            "suite",
            "suiteDigest",
            "packageVersion",
            "platform",
            "target",
            "features",
            "contracts",
            "limitations",
        )
        require(
            set(data) == set(exemplar)
            and all(data[k] == exemplar[k] for k in repeated)
            and data["platform"] == platform
            and data["suiteDigest"] == fixture["digest"]
            and seen == expected
            and len(data["checks"]) == len(seen) == fixture["checks"]
            and data["edition"] == core["edition"]
            and data["contracts"] == core["contracts"]
            and data["role"] == ("executor" if subset else "mixed")
            and data["binding"] == ("stdio" if subset else "stdio+loopback-http")
            and data["implementations"]
            == (exemplar["implementations"] if subset else core["implementations"])
            and data["scope"]
            == (
                exemplar["scope"]
                if subset
                else "Synthetic status read, explicit grants and published executor cases."
            )
            and interval[0] <= stamp(data["observedAt"]) <= interval[1],
            "historical public reference case evidence mismatch in " + path,
        )
    return set(paths)


def crosscheck_artifacts(directory, oracle, source, report, families):
    table = report["artifactInventory"]
    contents = decode((source / "git-file-digests.json").read_bytes())
    checker = decode((oracle / "git-file-digests.json").read_bytes())
    controls = {row["id"]: row for row in report["independentControls"]}

    def claimed_hashes(values, actual, prefix=""):
        for name, digest in values.items():
            require(
                digest == actual[prefix + check_name(name)],
                "substituted Git or artifact input: " + name,
            )

    wire = families["wire"][0]
    claimed_hashes(wire["sources"], contents)
    claimed_hashes(wire["oracle"], checker, "assurance/wire/")
    files = {k: v["sha256"] for k, v in table.items()}
    claimed_hashes(wire["artifacts"], files, "evidence/wire-evidence/")
    require(
        wire["formal"]["certificateSha256"] == wire["artifacts"]["wire.ndjson"]
        and wire["formal"]["extractedSourceSha256"]
        == wire["artifacts"]["Extracted.lean"]
        and wire["build"]["goBinarySha256"] == wire["artifacts"]["status-go"],
        "wire proof or executable differs",
    )
    provider = families["provider"][0]
    claimed_hashes(provider["targetDigests"], contents)
    proof = provider["proof"]
    claimed_hashes(proof["sourceSha256"], contents)
    require(
        proof["contractSha256"] == checker["assurance/provider/Contract.lean"]
        and proof["candidateContractSha256"]
        == contents["assurance/provider/Contract.lean"]
        and proof["proofSha256"] == contents["assurance/provider/Provider.lean"]
        and proof["generatedCertificateSha256"]
        == files["evidence/" + check_name(proof["generatedCertificate"])],
        "provider proof, source or certificate commitment differs",
    )
    core = families["core"][0]
    require(
        core["formal"]["certificateSha256"] == files["evidence/core.ndjson"],
        "core certificate differs",
    )
    for row in core["checks"]:
        if row["level"] == "model":
            detail = row["observed"]
            require(
                detail["certificate"] == core["formal"]["certificateSha256"]
                and detail["model"] == contents["assurance/core/Contract.lean"]
                and detail["proof"] == contents["assurance/core/Proofs.lean"]
                and detail["statementFile"] == checker["assurance/core/Expected.lean"],
                "core model, proof or statement differs: " + row["id"],
            )
    for family in ("interaction", "platform"):
        filename = "evidence/" + family + ".ndjson"
        binding = next(
            r["observed"]
            for r in families["profile-artifacts"][0]["checks"]
            if r["id"] == "profiles.detached." + family
        )
        require(
            binding["domain"] == family
            and binding["reportSha256"] == files["evidence/" + family + ".json"]
            and binding["submittedCertificateSha256"]
            == binding["independentRebuildSha256"]
            == files[filename]
            and binding["certificateBytes"] == table[filename]["bytes"],
            "foreign " + family + " artifact",
        )
        accepted = set()
        for row in families[family][0]["checks"]:
            for item in row.get("targets", []):
                require(
                    contents[check_name(item["path"])] == item["sha256"],
                    "wrong " + family + " source target",
                )
            if row["level"] in ("model", "source-refinement"):
                detail = row["observed"]
                cert = detail["certificate"]
                require(
                    "evidence/" + check_name(cert["file"]) == filename
                    and cert["sha256"] == files[filename]
                    and cert["declarations"] == binding["kernelDeclarations"]
                    and detail["checkerSha256"] == binding["checkerSha256"],
                    "model proof input differs",
                )
                accepted.add(detail["acceptedDeclaration"])
        require(
            accepted == set(binding["acceptedDeclarations"]),
            "detached model declaration roster differs",
        )
    browser = decode((directory / "evidence/stand-browser.json").read_bytes())
    stand_rows = {r["id"]: r for r in families["stand"][0]["checks"]}
    require(
        {r["id"] for r in browser["checks"]}
        == {"stand.accessibility", "stand.text-and-keyboard"}
        and len(browser["checks"]) == 2
        and all(
            canonical(r) == canonical(stand_rows[r["id"]]) for r in browser["checks"]
        ),
        "detached browser checks disagree with the witnessed stand",
    )
    for item in decode((directory / "evidence/provider-controls.json").read_bytes())[
        "controls"
    ]:
        require(
            type(item["expectedVerification"]) is bool
            and item["expectedVerification"] is item["actuallyVerified"]
            and controls[item["case"]]
            == {
                "id": item["case"],
                "result": item["result"],
                "claims": [item["obligation"]],
            },
            "detached provider challenge differs",
        )
    for item in decode((directory / "evidence/interaction-controls.json").read_bytes())[
        "checks"
    ]:
        require(
            controls[item["id"]] == {"id": item["id"], "result": item["status"]},
            "detached interaction challenge differs",
        )


def authenticate_aggregate(dossier, enrollment, public, vr, trust):
    key = vr.public_pem(public)
    require(
        vr.digest(key) == enrollment["operatorKey"]
        and (dossier / "report.sig").stat().st_size == 64,
        "wrong observer or aggregate signature type",
    )
    trust.verify_signature(dossier / "report.json", public, dossier / "report.sig")


def pinned_replay(tmp, repo, rev, now):
    """Run only in the isolated receiver interpreter, using the operator-selected checker commit."""
    oracle, source, dossier = tmp / "oracle", tmp / "source", tmp / "dossier"
    sys.path.insert(0, str(oracle / "assurance"))
    import structure
    import trust
    import verify_receipt as vr

    report = trust.load(dossier / "report.json")
    enrollment = trust.load(tmp / "enrollment.json")
    subject = trust.load(tmp / "subject.json")
    require(
        enrollment["acceptedVerifier"] == rev and report["acceptedVerifier"] == rev,
        "wrong independently chosen checker revision",
    )
    authenticate_aggregate(dossier, enrollment, tmp / "observer.pem", vr, trust)
    stand_receipt = vr.verify_dossier(
        dossier, enrollment, tmp / "observer.pem", repo, now=now
    )
    require(
        report["format"] == "ocs.qualification/1"
        and report["kind"] == "full"
        and report["eligibility"] == "independent pinned edition replay"
        and report["subject"] == subject
        and report["status"] == "pass"
        and report["failures"] == []
        and report["openRequired"] == [],
        "aggregate does not qualify the enrolled clean subject",
    )
    require(
        stand_receipt["subjectRevision"] == subject["revision"]
        and stand_receipt["subjectTreeSha256"] == subject["treeSha256"]
        and trust.load(dossier / "attestation.json")["subject"] == subject,
        "aggregate and deployment target subject disagree",
    )
    names = {str(p.relative_to(dossier)) for p in dossier.rglob("*") if p.is_file()}
    artifact_inventory(dossier, names, report["artifactInventory"])
    old_scope, new_scope = [
        trust.load(d / "assurance/scope.json") for d in (oracle, source)
    ]
    old_cat, new_cat = [
        trust.load(d / "assurance/obligations.json") for d in (oracle, source)
    ]
    old_scen, new_scen = [
        trust.load(d / "conformance/scenarios.json") for d in (oracle, source)
    ]
    old, new = [
        trust.obligations(cat, scen)
        for cat, scen in ((old_cat, old_scen), (new_cat, new_scen))
    ]
    require(
        not trust.compare_policy(old, new, old_scope, new_scope)
        and report["scope"] == old_scope,
        "protected obligations, scenario linkage or qualification scope changed",
    )
    for name, scenario in old_scen["scenarios"].items():
        require(
            set(scenario["checks"]) <= set(new_scen["scenarios"][name]["checks"]),
            "lost protected public scenario behavior: " + name,
        )
    require(
        all(s["checks"] for s in new_scen["scenarios"].values()),
        "empty public scenario",
    )
    policy = trust.load(oracle / "stand/kubernetes/policy.json")
    require(
        policy == trust.load(source / "stand/kubernetes/policy.json")
        and report["tools"]["inventory"]
        == trust.sha(oracle / "assurance/tooling.json"),
        "stand conditions or pinned tooling inventory changed",
    )
    old_decs, new_decs = [
        structure.inventory(d, cat) for d, cat in ((oracle, old_cat), (source, new_cat))
    ]
    require(
        not structure.compare(old_decs, new_decs)
        and trust.load(dossier / "declarations.json")
        == {
            "accepted": rev,
            "source": subject,
            "evidenceLevel": "source declaration identity",
            "items": new_decs,
        },
        "protected normative declarations changed or detached inventory differs from Git",
    )
    roster = trust.load(oracle / "assurance/evidence-index.json")
    require(
        roster == trust.load(source / "assurance/evidence-index.json"),
        "candidate replaced the enrolled evidence/checker roster",
    )
    controls = report["independentControls"]
    ids = [r["id"] for r in controls]
    require(
        set(ids)
        == set(roster["controlIds"]["local"] + roster["controlIds"]["deployment"])
        and len(set(ids)) == len(ids)
        and trust.load(dossier / "controls.json") == controls
        and all(
            r["result"] == "pass"
            and (
                "expectedAcceptance" not in r
                or type(r["expectedAcceptance"]) is bool
                and r["expectedAcceptance"] is r.get("observedAcceptance")
            )
            and (
                r["id"] not in roster["controlIds"]["deployment"]
                or r.get("observedAcceptance") is False
            )
            for r in controls
        ),
        "independent control roster or results disagree",
    )
    families = {}
    for row in report["evidence"]:
        family = row["id"].split("/", 1)[0]
        require(
            row["report"] == "evidence/" + family + ".json",
            "misattributed evidence report",
        )
        if family not in families:
            path = dossier / row["report"]
            families[family] = (trust.load(path), path, row["replay"])
        require(
            row["replay"] == families[family][2],
            "inconsistent witness replay declaration",
        )
    admitted = trust.admit_reports(new, families, subject, True, roster["checks"])
    for field, value in admitted.items():
        require(
            canonical(value) == canonical(report[field]),
            "signed aggregate diverges from protected replay: " + field,
        )
    crosscheck_artifacts(dossier, oracle, source, report, families)
    profiles = trust.load(source / "spec/profiles/index.json")["profiles"]
    accounting = {
        "numberedRules": sum(len(v) for v in new_scen["requirements"].values()),
        "scenarios": len(new_scen["scenarios"]),
        "profiles": len(profiles),
        "additionalProseGroups": len(new_cat["extraLocators"]),
        "atomicPromises": len(new),
        "declarations": dict(Counter(v["kind"] for v in new_decs.values())),
        "declarationCount": len(new_decs),
    }
    require(
        report["accounting"] == accounting
        and "acceptedEvidenceSlots" in report
        and report["acceptedEvidenceSlots"]
        == report["applicableEvidenceSlots"]
        == sum(len(a["levels"]) for a in new.values())
        and report["requiredLocalSlots"]
        == sum(l != "deployment" for a in new.values() for l in a["levels"]),
        "incorrect promise, scenario, profile or level denominator",
    )
    matrix = trust.load(dossier / "operations.json")
    registered = {
        r["method"]: r
        for r in trust.load(source / "spec/profiles/operations.json")["operations"]
    }
    bindings = families["interfaces"][0]["checks"][0]["observed"]
    require(
        bindings["matrixDigest"] == trust.sha(dossier / "operations.json")
        and set(matrix) == set(registered)
        and len(matrix) == bindings["methodCount"]
        and set(bindings["consumers"]) == {p["id"] for p in profiles},
        "registered operation or profile consumer matrix mismatch",
    )
    for method, item in matrix.items():
        require(
            item["profile"] == registered[method]["profile"]
            and item["publishedCallerCurrentTarget"]
            and all(w["accepted"] >= 1 for w in item["publishedCallerCurrentTarget"]),
            "published operation has no admitted public witness: " + method,
        )
    profile = decode((HERE / "metrics.json").read_bytes())
    ref_files = verify_reference(
        dossier,
        oracle,
        families["core"][0],
        old_scope["compatibilityRevision"],
        profile["extraHostCases"],
        families["wire"][0]["build"]["platform"].replace("/", " "),
        [stamp(report[k]) for k in ("startedAt", "finishedAt")],
    )
    require(
        names
        == {
            "report.json",
            "report.sig",
            "attestation.json",
            "attestation.sig",
            "controls.json",
            "declarations.json",
            "operations.json",
        }
        | set(report["artifactInventory"])
        | ref_files,
        "unknown file outside the signed qualification contour",
    )
    lifetime = policy["workload"]["maximumReceiptAgeSeconds"]
    times = [
        report["startedAt"],
        report["finishedAt"],
        *stand_receipt["observationInterval"],
    ]
    times.extend(
        data["observedAt"] for data, _, _ in families.values() if "observedAt" in data
    )
    times.extend(r["observedAt"] for r in families["stand"][0]["checks"])
    require(
        stamp(report["startedAt"]) <= stamp(report["finishedAt"]),
        "invalid qualification interval",
    )
    for value in times:
        trust.validate_time(value, now, lifetime)
    expires = min(map(stamp, times)) + timedelta(seconds=lifetime)
    witnesses = {r["id"]: r for r in report["evidence"]}
    claims = {}
    for row in report["obligations"]:
        meaning = {
            k: row[k]
            for k in ("source", "property", "subjectRole", "profile", "scenarios")
        }
        for level, result in row["levels"].items():
            require(
                result["status"] == "accepted" and result["evidence"],
                "unclosed assurance cell",
            )
            binds = [
                {k: witnesses[w][k] for k in ("id", "scope", "assumptions", "theorem")}
                for w in sorted(result["evidence"])
            ]
            claims[row["id"] + "@" + level] = structure.fingerprint(
                {
                    "meaning": meaning,
                    "scope": old_scope,
                    "level": level,
                    "witnesses": binds,
                }
            )
    return {
        "claims": claims,
        "reportSha256": trust.sha(dossier / "report.json"),
        "expiresAt": expires.isoformat().replace("+00:00", "Z"),
        "scope": old_scope["edition"],
        "acceptedVerifier": rev,
        "subject": subject,
        "accounting": accounting,
        "controls": len(controls),
        "witnesses": len(witnesses),
        "standReceiptSha256": stand_receipt["receiptSha256"],
    }


def _inspect(dossier, enrollment, observer, checker_repo, verifier, subject, now):
    require(
        isinstance(subject, dict)
        and set(subject) == {"revision", "treeSha256", "fileCount", "dirty"}
        and subject["dirty"] is False
        and type(subject["fileCount"]) is int
        and subject["fileCount"] > 0
        and isinstance(subject["treeSha256"], str)
        and SHA256.fullmatch(subject["treeSha256"]),
        "malformed clean subject identity",
    )
    root = Path(dossier).resolve(strict=True)
    repo = Path(checker_repo).resolve(strict=True)
    require(
        not Path(enrollment).resolve().is_relative_to(root)
        and not Path(observer).resolve().is_relative_to(root),
        "enrollment and observer key must be independently provisioned outside the dossier",
    )
    with tempfile.TemporaryDirectory(prefix="ocs-safe-snapshot-") as name:
        tmp = Path(name)
        snapshot_dossier(root, tmp / "dossier")
        (tmp / "observer.pem").write_bytes(bytes_at(observer, limit=32768))
        (tmp / "enrollment.json").write_bytes(bytes_at(enrollment, limit=1024 * 1024))
        (tmp / "subject.json").write_bytes(canonical(subject))
        require(
            decode((tmp / "enrollment.json").read_bytes())["acceptedVerifier"]
            == verifier,
            "enrollment does not name the independently selected checker",
        )
        export_commit(repo, verifier, tmp / "oracle", checker=True)
        require(
            export_commit(repo, subject["revision"], tmp / "source") == subject,
            "subject identity does not match tracked Git content",
        )
        env = {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(repo),
        }
        # The pre-receive hook may supply objects in its Git quarantine.
        env.update(
            {
                k: os.environ[k]
                for k in ("GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")
                if k in os.environ
            }
        )
        p = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).resolve()),
                "--pinned-replay",
                name,
                str(repo),
                verifier,
                str(now),
            ],
            check=False,
            env=env,
            cwd=tmp,
            capture_output=True,
            timeout=120,
        )
        require(
            p.returncode == 0,
            "independent qualification replay refused: "
            + p.stderr.decode(errors="replace").strip()[-540:],
        )
        result = decode(p.stdout)
        metrics, gaps, limits, fingerprint, target_condition = extract_metrics(
            tmp / "dossier"
        )
        result.update(
            metrics=metrics,
            metricGaps=gaps,
            coverageLimits=limits,
            metricProfileSha256=fingerprint,
            targetConditionSha256=target_condition,
        )
        return result


def inspect_dossier(
    dossier: Path,
    enrollment: Path,
    observer: Path,
    checker_repo: Path,
    verifier: str,
    subject: dict,
) -> dict:
    """Inspect a current sealed execution for the exact independently selected Git subject and stand."""
    try:
        return _inspect(
            dossier, enrollment, observer, checker_repo, verifier, subject, time.time()
        )
    except (
        KeyError,
        TypeError,
        AttributeError,
        StopIteration,
        OSError,
        ValueError,
        subprocess.SubprocessError,
        InvalidOperation,
    ) as exc:
        raise QualificationError(str(exc)) from exc


def at(value, path):
    for part in path.split("."):
        value = value[part]
    return value


def number(value, kind="number"):
    if kind == "boolean":
        require(type(value) is bool, "expected measured boolean outcome")
        return Decimal(int(value))
    if kind == "decimal-text":
        require(
            isinstance(value, str)
            and re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value),
            "expected exact nonnegative decimal amount",
        )
    else:
        require(type(value) in (int, Decimal), "expected exact numeric measurement")
    out = Decimal(value)
    require(
        out.is_finite()
        and out >= 0
        and len(out.as_tuple().digits) <= 96
        and abs(out.as_tuple().exponent) <= 128,
        "nonfinite or out-of-range metric",
    )
    return out


def text_decimal(value):
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text if text and text != "-0" else "0"


def condition_values(data, names):
    def typed(value):
        if isinstance(value, Decimal):
            return {"$exactDecimal": text_decimal(value)}
        if isinstance(value, list):
            return [typed(v) for v in value]
        if isinstance(value, dict):
            return {k: typed(v) for k, v in value.items()}
        return value

    return {p: typed(at(data, p)) for p in names}


def member_values(base, spec):
    if not spec:
        return {"": base}
    method, keys = spec["by"], spec["keys"]
    if method == "fields":
        return {key: base[key] for key in keys}
    source = at(base, spec["path"])
    if method == "map":
        require(
            isinstance(source, dict) and set(source) == set(keys),
            "changed measurement population",
        )
        return source
    require(
        isinstance(source, list) and len(source) == len(keys),
        "changed trial member count",
    )
    members = {str(item[method]): item for item in source}
    require(
        len(members) == len(source) and set(members) == set(keys),
        "ambiguous trial identities",
    )
    return members


def group_metrics(group, row, env):
    base = row[group.get("body", "observed")]
    common = condition_values(base, group["conditions"])
    result = {}
    for key, member in member_values(base, group.get("members")).items():
        prefix = "/".join(v for v in (group["id"], key) if v)
        settings = condition_values(member, group.get("memberConditions", []))
        condition = {
            "instrument": group["source"],
            "method": group.get("body", "observed"),
            "environment": env,
            "design": common,
            "member": key,
            "memberConditions": settings,
        }

        def emit(
            field,
            measured,
            direction,
            unit,
            *,
            kind="number",
            protocol="single observation",
            prefix=prefix,
            condition=condition,
        ):
            name = prefix + "/" + field
            require(
                name not in result and direction in ("min", "max"),
                "ambiguous enrolled metric ID",
            )
            signature = sha(
                canonical(
                    {
                        **condition,
                        "id": name,
                        "unit": unit,
                        "direction": direction,
                        "valueEncoding": kind,
                        "protocol": protocol,
                    }
                )
            )
            result[name] = {
                "condition": signature,
                "direction": direction,
                "value": text_decimal(measured),
            }

        for fields in group["fields"]:
            kind = fields.get("kind", "number")
            for direction in ("min", "max"):
                for field in fields.get(direction, []):
                    emit(
                        field,
                        number(at(member, field), kind),
                        direction,
                        fields["unit"],
                        kind=kind,
                    )
        for field in group.get("arrays", []):
            raw = at(member, field["field"])
            require(
                isinstance(raw, list) and len(raw) == field["size"],
                "incomplete raw trial population",
            )
            vector = [number(x) for x in raw]
            if field["order"] == "rank":
                vector.sort()
            else:
                require(field["order"] == "ordinal", "unregistered trial order")
            for i, measured in enumerate(vector):
                name = f"{field['field']}/{field['order']}-{i + 1:02d}"
                emit(
                    name,
                    measured,
                    field["direction"],
                    field["unit"],
                    protocol={"order": field["order"], "observations": field["size"]},
                )
        for diff in group.get("differences", []):
            kind = diff.get("kind", "number")
            with localcontext() as precise:
                precise.prec = 512
                value = number(at(member, diff["field"]), kind) - number(
                    at(member, diff["prior"]), kind
                )
            if diff.get("clampZero"):
                value = max(value, Decimal(0))
            require(value >= 0, "negative measured charge or unsigned difference")
            emit(
                diff["id"],
                value,
                diff["direction"],
                diff["unit"],
                kind=kind,
                protocol=diff,
            )
    return result


def numeric_observation_shape(doc):
    """Index quantitative leaf locations independently of their values and of array order."""
    paths = set()

    def visit(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                # All registered exchanges already have a named contract and a discriminated transcript.
                # They describe which inputs were tried, including dynamically keyed request IDs.
                if key != "registeredExchanges":
                    visit(value, path + "/" + key.replace("~", "~0").replace("/", "~1"))
        elif isinstance(node, list):
            for item in node:
                visit(item, path + "/*")
        elif (
            type(node) in (int, Decimal, float, bool)
            or isinstance(node, str)
            and path.rsplit("/", 1)[-1]
            in ("amount", "distinctOrganizationPriceTotal", "limitsAfterWork")
        ):
            paths.add(path)

    for row in doc["checks"]:
        if row["level"] in (
            "reference",
            "runtime-observation",
            "artifact-observation",
            "deployment",
            "measurement",
        ):
            key = row["id"] + "@" + row["level"]
            for k in ("observed", "details"):
                if k in row:
                    visit(row[k], key + "/" + k)
    return sorted(paths)


def extract_metrics(directory):
    raw_profile = (HERE / "metrics.json").read_bytes()
    profile = decode(raw_profile)
    report = decode((directory / "report.json").read_bytes(), exact=True)
    domains = set(profile["observableShapes"])
    docs = {
        name: decode(
            (directory / "evidence" / (name + ".json")).read_bytes(), exact=True
        )
        for name in domains
    }
    rows = {
        name + "/" + row["id"] + "@" + row["level"]: row
        for name, doc in docs.items()
        for row in doc["checks"]
    }
    target = docs["stand"]["target"]
    resource = rows["stand/stand.resource@deployment"]["observed"]
    local = {
        "enrolledChecker": report["acceptedVerifier"],
        "tools": report["tools"],
        "platform": docs["platform"]["callerRuntime"],
        "observingRuntime": docs["interaction"]["callerRuntime"],
    }
    stand = {
        "enrolledChecker": report["acceptedVerifier"],
        "clientTools": report["tools"],
        "target": condition_values(target, ["clusterUID", "apiVersion", "namespace"]),
        "runtime": condition_values(
            resource,
            [
                "node",
                "placement",
                "storageClass",
                "provisionedCapacity",
                "resourceLimits",
                "accessModes",
                "standRegion",
                "terms.organization",
                "terms.owner",
                "terms.plan",
                "terms.currency",
                "terms.period",
            ],
        ),
    }
    cells, gaps = {}, []
    for name, expectation in profile["observableShapes"].items():
        shape = numeric_observation_shape(docs[name])
        if (
            sha(canonical(shape)) != expectation["sha256"]
            or len(shape) != expectation["locations"]
        ):
            gaps.append(
                name
                + ": observational field inventory changed; independently enroll its measurement meaning"
            )
    for group in profile["groups"]:
        family = group["source"].split("/", 1)[0]
        env = dict(stand if family == "stand" else local)
        if family == "provider":
            env["productRuntime"] = docs[family]["environment"]
        if family == "wire":
            env["wireBuild"] = condition_values(
                docs[family]["build"],
                [
                    "goBuild",
                    "goVersion",
                    "platform",
                    "pythonInterpreterSha256",
                    "pythonVersion",
                ],
            )
        try:
            metrics = group_metrics(group, rows[group["source"]], env)
            for alias in group.get("aliases", []):
                require(
                    metrics == group_metrics(group, rows[alias], env),
                    "duplicate reported measurement disagrees: " + alias,
                )
            require(not cells.keys() & metrics.keys(), "duplicate enrolled metric")
            cells.update(metrics)
        except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
            gaps.append(group["id"] + ": " + str(exc))
    # Recover duration from authenticated microsecond timestamps, with no binary floating point.
    duration = stamp(report["finishedAt"]) - stamp(report["startedAt"])
    micros = (
        duration.days * 86400 + duration.seconds
    ) * 1000000 + duration.microseconds
    require(micros >= 0, "negative aggregate qualification duration")
    key = "qualification/full-wall-seconds"
    cells[key] = {
        "direction": "min",
        "value": text_decimal(Decimal(micros) / 1000000),
        "condition": sha(
            canonical(
                {
                    "metric": key,
                    "unit": "seconds",
                    "enrollment": report["acceptedVerifier"],
                    "local": local,
                    "stand": stand,
                    "levels": report["byLevel"],
                    "accounting": report["accounting"],
                    "controls": len(report["independentControls"]),
                    "witnesses": len(report["evidence"]),
                }
            )
        ),
    }
    for path in profile["artifactBytes"]:
        try:
            raw = number(report["artifactInventory"][path]["bytes"])
            name = "qualification/bytes/" + path.removeprefix("evidence/")
            cells[name] = {
                "direction": "min",
                "value": text_decimal(raw),
                "condition": sha(
                    canonical(
                        {
                            "metric": name,
                            "unit": "bytes",
                            "env": local,
                            "roster": report["byLevel"],
                            "scope": report["scope"]["edition"],
                        }
                    )
                ),
            }
        except (KeyError, TypeError, ValueError) as exc:
            gaps.append(path + ": " + str(exc))
    return (
        cells,
        gaps,
        profile["coverageLimits"],
        sha(raw_profile),
        sha(canonical(stand)),
    )


if __name__ == "__main__":
    if len(sys.argv) != 6 or sys.argv[1] != "--pinned-replay":
        raise SystemExit("use inspect_dossier from the receiver")
    try:
        result = pinned_replay(
            Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], float(sys.argv[5])
        )
        sys.stdout.buffer.write(canonical(result))
    except (
        KeyError,
        TypeError,
        AttributeError,
        StopIteration,
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(str(error)) from error
