"""Receiver-owned finite admission proof. All submitted values enter Lean as data literals."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import zlib
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEMANTICS_SHA256 = "8a7ade87bb7103f706b47e45931b7e4254c4ce9cca1350f8207315f4bbc1a6fd"
TOOLCHAIN_SHA256 = "984bbb9506fa273c4240de94649938d17a1ba1c72bb30e8a0edcca1c203ec61e"
FACT_ORDER = (
    "singleParent",
    "inventory",
    "qualification",
    "domainReview",
    "independentReview",
    "fresh",
    "noCounterexample",
    "policyContinuity",
    "priorEvidence",
)
REQUIRED_FACTS = frozenset(FACT_ORDER)
THEOREMS = tuple(
    "SafePush." + name
    for name in (
        "facts_exact",
        "metric_exact",
        "gate_exact",
        "decision_sound",
        "exact_commit",
        "stale_competing_parent",
        "revoke_blocks",
        "quarantine_current",
        "unpublished_restart",
        "published_restart",
        "restart_idempotent",
        "foreign_ref_refuses",
        "recovered_with_later_holds",
        "arbitrary_history",
        "history_journal",
        "nonvacuity",
    )
)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")

# Costs exceeding the enrolled receiver budget hold admission instead of weakening it.
MAX_ROWS = 16384
MAX_KEY_BYTES = 512
MAX_DECIMAL_DIGITS = 1024
MAX_PACKET_BYTES = 16 * 1024 * 1024
STAGE_SECONDS = 120


class AdmissionError(ValueError):
    def __init__(self, criterion, reason, outcome="undetermined", certificate=None):
        self.criterion = criterion
        self.outcome = outcome
        self.certificate = certificate
        super().__init__(f"{outcome} [{criterion}] {reason}")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _canonical(data) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _key(name):
    if type(name) is not str or not name:
        raise AdmissionError(
            "evidence.encoding", "row ID must be a nonempty UTF-8 string"
        )
    try:
        data = name.encode("utf-8")
    except UnicodeError as error:
        raise AdmissionError("evidence.encoding", "unencodable row ID") from error
    if len(data) > MAX_KEY_BYTES:
        raise AdmissionError("verification.cost", "row ID exceeds enrolled byte limit")
    return data


def _sha(value, criterion):
    if type(value) is not str or not SHA256.fullmatch(value):
        raise AdmissionError(criterion, "expected a lower-case SHA-256 digest")
    return value


def _rat(value):
    if (
        type(value) is not str
        or len(value) > MAX_DECIMAL_DIGITS
        or not DECIMAL.fullmatch(value)
    ):
        raise AdmissionError(
            "performance.encoding", "expected a bounded exact finite decimal string"
        )
    # Inspect the exponent before constructing enormous powers of ten.
    exp = re.search(r"[eE]([+-]?[0-9]+)", value)
    if exp and abs(int(exp[1])) > MAX_DECIMAL_DIGITS:
        raise AdmissionError(
            "verification.cost", "decimal exponent exceeds enrolled limit"
        )
    number = Decimal(value)
    if (
        max(abs(number.adjusted()), abs(number.as_tuple().exponent))
        > MAX_DECIMAL_DIGITS
    ):
        raise AdmissionError(
            "verification.cost", "decimal magnitude exceeds enrolled limit"
        )
    return Fraction(*number.as_integer_ratio())


def _table(raw, metrics):
    if type(raw) is not dict or len(raw) > MAX_ROWS:
        raise AdmissionError("evidence.encoding", "expected bounded keyed rows")
    result = {}
    for key, data in raw.items():
        _key(key)
        if metrics:
            if (
                type(data) is not dict
                or set(data) != {"direction", "condition", "value"}
                or type(data["direction"]) is not str
                or data["direction"] not in ("min", "max")
            ):
                raise AdmissionError(
                    "performance.encoding", "invalid metric definition for " + repr(key)
                )
            result[key] = (
                data["direction"],
                _sha(data["condition"], "performance.encoding"),
                _rat(data["value"]),
            )
        else:
            result[key] = _sha(data, "coverage.meaning")
    return result


def _git(values):
    if (
        any(
            type(v) is not str or not GIT_ID.fullmatch(v) or not int(v, 16)
            for v in values
        )
        or len({len(v) for v in values}) != 1
    ):
        raise AdmissionError(
            "reference.update", "expected full nonzero Git object IDs in one format"
        )
    return tuple(values)


def _facts(raw):
    if type(raw) is not dict:
        raise AdmissionError("evidence.facts", "required receipt facts missing")
    missing = [name for name in FACT_ORDER if name not in raw]
    if missing:
        raise AdmissionError("fact:" + missing[0], "required receiver fact is missing")
    if set(raw) != REQUIRED_FACTS:
        raise AdmissionError("evidence.facts", "undeclared fact in input")
    if any(type(raw[name]) is not bool for name in FACT_ORDER):
        raise AdmissionError("evidence.facts", "fact values require a checked Boolean")
    return {name: raw[name] for name in FACT_ORDER}


def _counterexample(git, facts, old_claims, new_claims, old_metrics, new_metrics):
    parent, observed, candidate, _ = git
    if observed != parent or candidate == parent:
        return AdmissionError(
            "reference.update",
            "stale expected parent or no advancing candidate",
            "rejected",
        )
    for name in FACT_ORDER:
        if not facts[name]:
            outcome = (
                "rejected"
                if name in ("singleParent", "noCounterexample", "policyContinuity")
                else "undetermined"
            )
            return AdmissionError(
                "fact:" + name, "required receiver fact is false", outcome
            )
    for key, digest in old_claims.items():
        if new_claims.get(key) != digest:
            return AdmissionError(
                "claim:" + key,
                "prior claim disappeared or its accepted meaning changed",
                "rejected",
            )
    for key, old in old_metrics.items():
        cur = new_metrics.get(key)
        if cur is None or old[:2] != cur[:2]:
            return AdmissionError(
                "metric:" + key,
                "protected metric disappeared or its direction/condition changed",
                "rejected",
            )
        if (old[0] == "min" and cur[2] > old[2]) or (
            old[0] == "max" and cur[2] < old[2]
        ):
            return AdmissionError(
                "metric:" + key,
                "protected observation worsened under the same conditions",
                "rejected",
            )
    return None


def _tag(raw: bytes) -> int:
    # Injective even with leading zero bytes and when two Git object formats coexist.
    return int.from_bytes(b"\x01" + raw, "big")


def _untag(n: str) -> bytes:
    value = int(n)
    data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if data[:1] != b"\x01":
        raise AdmissionError("proof.encoding", "round trip lost its byte-string tag")
    return data[1:]


def _hex_literal(text):
    return hex(_tag(bytes.fromhex(text)))


def _metric_literal(value):
    direction, condition, ratio = value
    enum = ".minimize" if direction == "min" else ".maximize"
    numerator = hex(abs(ratio.numerator))
    numerator = "(-" + numerator + ")" if ratio.numerator < 0 else numerator
    rational = "(Rat.ofInt " + numerator + ")"
    if ratio.denominator != 1:
        rational = "(" + rational + " / (Rat.ofInt " + hex(ratio.denominator) + "))"
    return "⟨" + enum + "," + _hex_literal(condition) + "," + rational + "⟩"


def _tree(old, new, literal):
    keys = sorted(set(old) | set(new), key=lambda key: _tag(_key(key)))
    if len(keys) > MAX_ROWS:
        raise AdmissionError(
            "verification.cost", "combined inventory exceeds enrolled row limit"
        )

    def term(start, end):
        if start == end:
            return ".empty"
        mid = (start + end) // 2
        key = keys[mid]
        sides = [
            ("some " + literal(side[key])) if key in side else "none"
            for side in (old, new)
        ]
        return (
            "(.node "
            + term(start, mid)
            + " "
            + hex(_tag(_key(key)))
            + " ⟨"
            + ",".join(sides)
            + "⟩ "
            + term(mid + 1, end)
            + ")"
        )

    return term(0, len(keys))


def _source(git, facts, old_claims, new_claims, old_metrics, new_metrics, accepted):
    decision = "true" if accepted else "false"
    ids = ",".join(_hex_literal(oid) for oid in git)
    flags = ",".join("true" if facts[name] else "false" for name in FACT_ORDER)
    claims = _tree(old_claims, new_claims, _hex_literal)
    metrics = _tree(old_metrics, new_metrics, _metric_literal)
    header = f"""import Admission
set_option maxRecDepth 4096
set_option maxHeartbeats 16000000
namespace SafePushCandidate
open SafePush
def packet : Packet := ⟨{ids},⟨{flags}⟩,{claims},{metrics}⟩
theorem checked : gate packet = {decision} := by decide +kernel
"""
    conclusion = (
        """theorem consequence : packet.expectedParent = packet.observedParent ∧
    packet.candidate ≠ packet.expectedParent ∧ obligations packet.facts ∧ preserves (previous packet) (proposed packet) :=
  decision_sound packet checked
"""
        if accepted
        else """theorem consequence (s : State) : publish s packet = none := by simp [publish, checked]
"""
    )
    return header + conclusion + ROUND_TRIP + "\nend SafePushCandidate\n"


# Read the actual elaborated data in a simple escaped-by-type grammar. IDs/digests
# have only numeric encodings; an independently decoded field must equal its input.
ROUND_TRIP = """
private def claimSide (c : Option Nat) : String := (c.map toString).getD "-"
private def metricSide : Option Metric → String
  | none => "-"
  | some m =>
    let d := match m.direction with | .minimize => "min" | .maximize => "max"
    s!"{d},{m.condition},{m.value.num},{m.value.den}"
#eval do
  let p := packet
  IO.println s!"git|{p.expectedParent}|{p.observedParent}|{p.candidate}|{p.tree}"
  let f := p.facts
  IO.println ("facts|" ++ String.intercalate "," ([f.singleParent, f.inventory, f.qualification,
    f.domainReview, f.independentReview, f.fresh, f.noCounterexample, f.policyContinuity,
    f.priorEvidence].map toString))
  for (k, c) in p.claims.entries do
    IO.println s!"claim|{k}|{claimSide c.before}|{claimSide c.after}"
  for (k, c) in p.metrics.entries do
    IO.println s!"metric|{k}|{metricSide c.before}|{metricSide c.after}"
"""


def _decoded(output):
    git = facts = None
    before_claims, after_claims, before_metrics, after_metrics = {}, {}, {}, {}
    seen = set()
    for line in output.splitlines():
        fields = line.split("|")
        family = fields[0]
        if family == "git" and git is None and len(fields) == 5:
            git = tuple(_untag(v).hex() for v in fields[1:])
        elif family == "facts" and facts is None and len(fields) == 2:
            bits = fields[1].split(",")
            if len(bits) != len(FACT_ORDER) or any(
                b not in ("true", "false") for b in bits
            ):
                raise AdmissionError(
                    "proof.encoding", "serialized packet contains malformed facts"
                )
            facts = dict(zip(FACT_ORDER, (b == "true" for b in bits)))
        elif family in ("claim", "metric") and len(fields) == 4:
            name = _untag(fields[1]).decode("utf-8")
            if (family, name) in seen or fields[2:] == ["-", "-"]:
                raise AdmissionError(
                    "proof.encoding", "duplicate or empty elaborated row"
                )
            seen.add((family, name))
            destinations = (
                (before_claims, after_claims)
                if family == "claim"
                else (before_metrics, after_metrics)
            )
            for raw, destination in zip(fields[2:], destinations):
                if raw == "-":
                    continue
                if family == "claim":
                    destination[name] = _untag(raw).hex()
                else:
                    direction, condition, num, den = raw.split(",")
                    destination[name] = (
                        direction,
                        _untag(condition).hex(),
                        Fraction(int(num), int(den)),
                    )
        else:
            raise AdmissionError(
                "proof.encoding", "unexpected statement in the packet round trip"
            )
    return git, facts, before_claims, after_claims, before_metrics, after_metrics


def _execute(command, work, environment, output=None):
    try:
        result = subprocess.run(
            command,
            cwd=work,
            env=environment,
            stdout=output or subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=STAGE_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AdmissionError(
            "proof.kernel", "proof stage unavailable or exceeded its time budget"
        ) from error
    if result.returncode:
        # Diagnostics can include very large literal terms. Keep the protected log bounded.
        message = ((result.stderr or b"") + (result.stdout or b"")).decode(
            "utf-8", "replace"
        )
        raise AdmissionError(
            "proof.kernel", f"{Path(command[0]).name} failed: {message[:500]}"
        )
    return (result.stdout or b"").decode("utf-8")


def _manifest():
    manifest_path = Path(
        os.environ.get(
            "SAFE_PUSH_TOOLCHAIN_MANIFEST",
            HERE.parent / "assurance/wire/toolchain.json",
        )
    )
    if not manifest_path.is_absolute():
        raise AdmissionError(
            "proof.toolchain", "receiver manifest path must be absolute"
        )
    raw = manifest_path.read_bytes()
    if _digest(raw) != TOOLCHAIN_SHA256:
        raise AdmissionError(
            "proof.toolchain", "independently enrolled toolchain manifest changed"
        )
    return json.loads(raw)


def _toolchain():
    manifest = _manifest()
    target = platform.system() + "/" + platform.machine()
    if target not in manifest["builds"]:
        raise AdmissionError(
            "proof.toolchain", "no enrolled proof toolchain for this verifier platform"
        )
    build = manifest["builds"][target]
    # Only the separately protected receiver's environment may select this installation.
    release_dir = manifest["release"].replace("/", "--").replace(":", "---")
    prefix = Path(
        os.environ.get(
            "SAFE_PUSH_LEAN_HOME", Path.home() / ".elan/toolchains" / release_dir
        )
    )
    if not prefix.is_absolute():
        raise AdmissionError(
            "proof.toolchain", "receiver toolchain path must be absolute"
        )
    for path, expected in build["files"].items():
        if _file_digest(prefix / path) != expected:
            raise AdmissionError("proof.toolchain", "substituted checker file " + path)
    env = {"PATH": str(prefix / "bin") + ":/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
    if (
        _execute([prefix / "bin/lean", "--githash"], prefix, env).strip()
        != manifest["commit"]
    ):
        raise AdmissionError("proof.toolchain", "substituted Lean revision")
    return manifest, build, prefix / "bin", target, env


def _replay(source, expected):
    semantics = (HERE / "Admission.lean").read_bytes()
    if _digest(semantics) != SEMANTICS_SHA256:
        raise AdmissionError(
            "proof.semantics", "independently enrolled admission semantics changed"
        )
    manifest, build, binary, target, env = _toolchain()
    with tempfile.TemporaryDirectory(prefix="safe-push-proof-") as temp:
        work = Path(temp)
        env = {**env, "LEAN_PATH": str(work)}
        (work / "Admission.lean").write_bytes(semantics)
        (work / "Candidate.lean").write_text(source, encoding="utf-8")
        for name in ("Admission", "Candidate"):
            compiled = _execute(
                [
                    binary / "lean",
                    "-DwarningAsError=true",
                    "-o",
                    name + ".olean",
                    name + ".lean",
                ],
                work,
                env,
            )
        if _decoded(compiled) != expected:
            raise AdmissionError(
                "proof.encoding",
                "elaborated packet differs from the receiver's complete input",
            )
        _execute(
            [binary / "leanchecker", "--silent", "Admission", "Candidate"], work, env
        )
        names = [
            *THEOREMS,
            "SafePushCandidate.checked",
            "SafePushCandidate.consequence",
        ]
        proof = work / "proof.ndjson"
        with proof.open("wb") as handle:
            _execute(
                [binary / "leanexport", "Candidate", "--", *names], work, env, handle
            )
        config = {
            "export_file_path": str(proof),
            "permitted_axioms": manifest["axioms"],
            "unpermitted_axiom_hard_error": True,
            "nat_extension": True,
            "string_extension": True,
            "pp_to_stdout": True,
            "pp_declars": names,
            "pp_options": {"proofs": False},
            "print_success_message": True,
        }
        (work / "kernel.json").write_bytes(_canonical(config))
        audit = _execute([binary / "nanoda_bin", work / "kernel.json"], work, env)
        count = re.search(r"Checked (\d+) declarations with no errors", audit)
        if not count or any(
            not re.search(r"(?m)^theorem " + re.escape(name) + r"\b", audit)
            for name in names
        ):
            raise AdmissionError(
                "proof.kernel",
                "independent checker did not validate every named theorem",
            )
        return {
            "semanticsSha256": SEMANTICS_SHA256,
            "toolchainManifestSha256": TOOLCHAIN_SHA256,
            "toolchainArchiveSha256": build["assetSha256"],
            "leanRevision": manifest["commit"],
            "independentKernel": "nanoda",
            "replayedOn": target,
            "axioms": manifest["axioms"],
            "theorems": names,
            "checkedDeclarations": int(count[1]),
            "proofSha256": _file_digest(proof),
            "instanceSha256": _digest(source.encode("utf-8")),
        }


def certify(
    previous_claims: dict[str, str],
    current_claims: dict[str, str],
    previous_metrics: dict[str, dict],
    current_metrics: dict[str, dict],
    parent: str,
    actual_parent: str,
    candidate: str,
    tree: str,
    facts: dict[str, bool],
) -> dict:
    """Replay this exact independently assembled receiver packet, or raise AdmissionError."""
    git = _git((parent, actual_parent, candidate, tree))
    expected = (
        git,
        _facts(facts),
        _table(previous_claims, False),
        _table(current_claims, False),
        _table(previous_metrics, True),
        _table(current_metrics, True),
    )
    diagnosis = _counterexample(*expected)
    packet = {
        "parent": parent,
        "actualParent": actual_parent,
        "candidate": candidate,
        "tree": tree,
        "facts": expected[1],
        "previousClaims": expected[2],
        "currentClaims": expected[3],
    }
    for label, rows in (
        ("previousMetrics", expected[4]),
        ("currentMetrics", expected[5]),
    ):
        packet[label] = {
            key: {
                "direction": d,
                "condition": cond,
                "numerator": str(r.numerator),
                "denominator": str(r.denominator),
            }
            for key, (d, cond, r) in rows.items()
        }
    packet_bytes = _canonical(packet)
    if len(packet_bytes) > MAX_PACKET_BYTES:
        raise AdmissionError(
            "verification.cost",
            "complete normalized packet exceeds the enrolled byte limit",
        )
    source = _source(*expected, accepted=diagnosis is None)
    try:
        kernel = _replay(source, expected)
    except AdmissionError:
        raise
    except (ArithmeticError, OSError, UnicodeError, ValueError) as error:
        raise AdmissionError(
            "proof.kernel", "could not bind and replay complete protected evidence"
        ) from error
    # The finite witness is data, including the entire prior and proposed domains.
    # A recipient can reconstruct each ground theorem under the independently enrolled semantics.
    witness = {
        "format": "ocs.safe-push-packet/1",
        "encoding": "zlib+base64",
        "uncompressedBytes": len(packet_bytes),
        "data": base64.b64encode(zlib.compress(packet_bytes, level=6)).decode("ascii"),
    }
    cert = {
        "format": "ocs.safe-push-proof/1",
        "parent": parent,
        "actualParent": actual_parent,
        "candidate": candidate,
        "tree": tree,
        "inputSha256": _digest(packet_bytes),
        "kernel": kernel,
        "witness": witness,
    }
    if diagnosis is not None:
        diagnosis.certificate = {
            **cert,
            "verdict": diagnosis.outcome,
            "status": "fail",
            "criterion": diagnosis.criterion,
        }
        raise diagnosis
    return {**cert, "verdict": "accepted", "status": "pass"}


def _check_witness(witness, expected):
    n = expected["witness"]["uncompressedBytes"]
    if (
        type(witness) is not dict
        or set(witness) != set(expected["witness"])
        or witness["format"] != "ocs.safe-push-packet/1"
        or witness["encoding"] != "zlib+base64"
        or type(witness["uncompressedBytes"]) is not int
        or witness["uncompressedBytes"] != n
        or type(witness["data"]) is not str
        or len(witness["data"]) > 2 * n + 128
    ):
        raise AdmissionError(
            "proof.receipt", "invalid finite witness framing", "rejected"
        )
    try:
        stream = zlib.decompressobj()
        raw = stream.decompress(
            base64.b64decode(witness["data"].encode("ascii"), validate=True), n + 1
        )
        if (
            not stream.eof
            or stream.unused_data
            or stream.unconsumed_tail
            or len(raw) != n
            or _digest(raw) != expected["inputSha256"]
        ):
            raise AdmissionError(
                "proof.receipt",
                "witness does not reconstruct the enrolled input",
                "rejected",
            )
    except (binascii.Error, zlib.error, UnicodeError) as error:
        raise AdmissionError(
            "proof.receipt", "invalid finite witness encoding", "rejected"
        ) from error


def replay_certificate(
    submitted: dict, *, expected_origin: str | None = None, **enrolled_inputs
) -> dict:
    """Recreate a positive or negative proof from independent inputs; never execute submitted text."""
    if type(submitted) is not dict or type(submitted.get("kernel")) is not dict:
        raise AdmissionError("proof.receipt", "invalid receipt", "rejected")
    try:
        rebuilt = certify(**enrolled_inputs)
    except AdmissionError as refusal:
        if refusal.certificate is None:
            raise
        rebuilt = refusal.certificate
    # Every field is bound, including the independently replayed export. Host labels and
    # archive pins legitimately differ on another enrolled architecture of the same release.
    observed = {**submitted, "kernel": dict(submitted["kernel"])}
    expected = {**rebuilt, "kernel": dict(rebuilt["kernel"])}
    _check_witness(observed.get("witness"), expected)
    # Equal data may have a different compressed representation on another verifier.
    observed["witness"] = expected["witness"]
    manifest = _manifest()
    origin = observed["kernel"].get("replayedOn")
    if (
        origin
        != (
            expected["kernel"]["replayedOn"]
            if expected_origin is None
            else expected_origin
        )
        or type(origin) is not str
        or origin not in manifest["builds"]
        or observed["kernel"].get("toolchainArchiveSha256")
        != manifest["builds"][origin]["assetSha256"]
    ):
        raise AdmissionError(
            "proof.receipt", "unrecognized originating verifier platform", "rejected"
        )
    for record in (observed, expected):
        for field in ("replayedOn", "toolchainArchiveSha256"):
            record["kernel"].pop(field)
    try:
        match = _canonical(observed) == _canonical(expected)
    except (ValueError, TypeError, RecursionError) as error:
        raise AdmissionError(
            "proof.receipt", "invalid canonical receipt data", "rejected"
        ) from error
    if not match:
        raise AdmissionError(
            "proof.receipt",
            "receipt differs from the rooted proof and enrolled input",
            "rejected",
        )
    return rebuilt
