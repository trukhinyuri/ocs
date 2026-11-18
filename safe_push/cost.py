"""Measure the registered pre-publication verification boundary in its own process."""

import argparse
import hashlib
import json
import math
import os
import platform
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import resource
except ImportError:
    resource = None


FORMAT = "ocs.safe-push.verifier-cost/1"
POLICY_FORMAT = "ocs.safe-push.verifier-cost-policy/1"
BOUNDARY = "independent-prepare-entry-to-verified-receipt-before-sign-and-ref-cas/1"
EXPERIMENT = {"profile": "receiver-experiment/1", "mode": "observation-only"}
UNITS = {
    "wallNs": "nanoseconds",
    "selfCpuNs": "nanoseconds",
    "waitedChildCpuUs": "microseconds",
    "selfPeakRssBytes": "bytes",
    "largestWaitedChildPeakRssBytes": "bytes",
    "inputBlocks": "kernel block-input operations",
    "outputBlocks": "kernel block-output operations",
}
PEAKS = {"selfPeakRssBytes", "largestWaitedChildPeakRssBytes"}
SHA = re.compile("[0-9a-f]{64}")


class CostError(ValueError):
    def __init__(self, outcome, criterion, message, observation):
        super().__init__(message)
        self.outcome = outcome
        self.criterion = criterion
        self.observation = {
            **observation,
            "status": outcome,
            "criterion": criterion,
            "reason": message,
        }


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode()


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def is_sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def linux_controls():
    # Ancestor limits affect the process even when its own subgroup says "max".
    location = next(
        line[3:]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    parts = Path(location).parts
    if not parts or parts[0] != "/" or ".." in parts:
        raise ValueError("unrecognized cgroup hierarchy")
    root = Path("/sys/fs/cgroup")
    chain = [root]
    for name in parts[1:]:
        chain.append(chain[-1] / name)
    if (
        not all(p.is_dir() for p in chain)
        or not (root / "cgroup.controllers").is_file()
    ):
        raise ValueError("unobserved cgroup hierarchy")
    controllers = (
        "cpu.max",
        "cpu.weight",
        "cpuset.cpus.effective",
        "cpuset.mems.effective",
        "memory.max",
        "memory.high",
        "pids.max",
        "io.max",
        "io.weight",
    )
    cgroups = [
        {k: (p / k).read_text().strip() for k in controllers if (p / k).is_file()}
        for p in chain
    ]
    governors = {}
    for p in sorted(Path("/sys/devices/system/cpu/cpufreq").glob("policy*")):
        governors[p.name] = {
            k: (p / k).read_text().strip()
            for k in (
                "related_cpus",
                "scaling_governor",
                "scaling_driver",
                "scaling_min_freq",
                "scaling_max_freq",
                "energy_performance_preference",
            )
            if (p / k).is_file()
        }
    return {
        "cgroupVersion": 2,
        "ancestorControllerSha256": fingerprint(cgroups),
        "frequencyPolicySha256": fingerprint(governors),
        "visibleFrequencyPolicies": len(governors),
    }


def platform_conditions():
    """Portable clocks and the implemented Linux resource-counter population."""
    clock = {}
    for name in ("monotonic", "process_time"):
        info = time.get_clock_info(name)
        clock[name] = {
            "implementation": info.implementation,
            "resolutionSeconds": info.resolution.hex(),
            "monotonic": info.monotonic,
            "adjustable": info.adjustable,
        }
    known = {
        "os": sys.platform,
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "runtime": sys.implementation.name,
        "runtimeVersion": list(sys.version_info[:3]),
        "clocks": clock,
        "collectorSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "boundary": BOUNDARY,
    }
    if sys.platform == "linux":
        try:
            fields = {
                "vendor_id",
                "cpu family",
                "model",
                "model name",
                "stepping",
                "microcode",
                "flags",
                "CPU implementer",
                "CPU architecture",
                "CPU variant",
                "CPU part",
                "CPU revision",
                "Features",
            }
            models = set()
            for block in Path("/proc/cpuinfo").read_text().split("\n\n"):
                pairs = [
                    (k.strip(), v.strip())
                    for line in block.splitlines()
                    if ":" in line
                    for k, _, v in [line.partition(":")]
                    if k.strip() in fields
                ]
                if pairs:
                    models.add(fingerprint(sorted(pairs)))
            mem = next(
                s
                for s in Path("/proc/meminfo").read_text().splitlines()
                if s.startswith("MemTotal:")
            )
            known["host"] = {
                "machineIdentitySha256": hashlib.sha256(
                    Path("/etc/machine-id").read_bytes()
                ).hexdigest(),
                "cpuModelDigests": sorted(models),
                "onlineCpus": os.cpu_count(),
                "affinity": sorted(os.sched_getaffinity(0)),
                "schedulerPolicy": os.sched_getscheduler(0),
                "nice": os.getpriority(os.PRIO_PROCESS, 0),
                "physicalMemory": mem.strip(),
            }
            known["host"].update(linux_controls())
            if not models:
                known["unavailable"] = "processor model"
        except (OSError, ValueError, StopIteration, AttributeError) as exc:
            known["unavailable"] = type(exc).__name__
    else:
        known["unavailable"] = "full resource observer on this operating system"
    return known


def children_in_flight():
    if sys.platform != "linux":
        return None
    try:
        files = list(Path("/proc/self/task").glob("*/children"))
        if not files:
            return None
        return sum(len(p.read_text().split()) for p in files)
    except OSError:
        return None


def micros(seconds):
    # getrusage on Linux reports struct timeval. Recover its integral microseconds
    # only while this binding's double has sufficient precision to round-trip them.
    if not math.isfinite(seconds) or seconds < 0 or math.ulp(seconds) >= 1e-6:
        raise ValueError("unrepresentable getrusage microseconds")
    a, b = seconds.as_integer_ratio()
    result = (a * 1_000_000 + b // 2) // b
    # CPython gets timeval as seconds + microseconds * 1e-6. Either adjacent
    # floating conversion can represent that integral kernel counter.
    if abs(seconds - result / 1_000_000) > math.ulp(seconds):
        raise ValueError("inexact kernel microsecond")
    return result


def sample():
    low = time.monotonic_ns()
    counters = {"wallNs": low, "selfCpuNs": time.process_time_ns()}
    error = None
    if sys.platform == "linux" and resource is not None:
        try:
            own = resource.getrusage(resource.RUSAGE_SELF)
            child = resource.getrusage(resource.RUSAGE_CHILDREN)
            counters.update(
                waitedChildCpuUs=micros(child.ru_utime) + micros(child.ru_stime),
                selfPeakRssBytes=own.ru_maxrss * 1024,
                largestWaitedChildPeakRssBytes=child.ru_maxrss * 1024,
                inputBlocks=own.ru_inblock + child.ru_inblock,
                outputBlocks=own.ru_oublock + child.ru_oublock,
            )
        except (ValueError, AttributeError, OSError) as exc:
            error = type(exc).__name__
    else:
        error = "Linux resource counters unavailable"
    return {
        "counters": counters,
        "sampleBracketNs": time.monotonic_ns() - low,
        "utcNs": time.time_ns(),
        "pid": os.getpid(),
        "inFlightChildren": children_in_flight(),
        "unavailable": error,
    }


@dataclass(frozen=True)
class CostStart:
    platform: dict
    first: dict


def start_cost():
    conditions = platform_conditions()
    return CostStart(conditions, sample())


def observation(start, workload):
    if not isinstance(start, CostStart):
        raise CostError(
            "undetermined",
            "verification.cost.start",
            "measurement token unavailable",
            {},
        )
    last = sample()
    later = platform_conditions()
    platform_hash = fingerprint(start.platform)
    compared = {}
    for key in UNITS.keys() & start.first["counters"].keys() & last["counters"].keys():
        compared[key] = (
            last["counters"][key]
            if key in PEAKS
            else last["counters"][key] - start.first["counters"][key]
        )
    condition = (
        fingerprint(
            {
                "platformSha256": platform_hash,
                "workloadSha256": workload,
                "boundary": BOUNDARY,
                "units": UNITS,
            }
        )
        if is_sha(workload)
        else None
    )
    record = {
        "format": FORMAT,
        "status": "observed",
        "boundary": BOUNDARY,
        "platformSha256": platform_hash,
        "workloadSha256": workload if is_sha(workload) else None,
        "condition": condition,
        "observed": compared,
        "provenance": {
            "platform": start.platform,
            "finalPlatformSha256": fingerprint(later),
            "units": UNITS,
            "first": start.first,
            "last": last,
        },
    }
    if start.first["pid"] != last["pid"]:
        raise CostError(
            "undetermined",
            "verification.cost.process",
            "collector changed process",
            record,
        )
    if any(type(v) is not int or v < 0 for v in compared.values()):
        raise CostError(
            "undetermined",
            "verification.cost.counter",
            "invalid or nonmonotonic counter",
            record,
        )
    if any(
        last["counters"][key] < start.first["counters"][key]
        for key in PEAKS & compared.keys()
    ):
        raise CostError(
            "undetermined",
            "verification.cost.counter",
            "process high-water mark decreased",
            record,
        )
    if platform_hash != fingerprint(later):
        raise CostError(
            "undetermined",
            "verification.cost.platform",
            "measurement platform changed",
            record,
        )
    return record


def sufficient(record):
    p = record["provenance"]
    if (
        set(record["observed"]) != set(UNITS)
        or "unavailable" in p["platform"]
        or any(
            s.get("unavailable") or s.get("inFlightChildren") != 0
            for s in (p["first"], p["last"])
        )
    ):
        raise CostError(
            "undetermined",
            "verification.cost.population",
            "complete comparable local counters and waited-child cohort are unavailable",
            record,
        )


def baseline_cost(start, workload_sha256):
    """Finish an actual independent replay of the enrolled pre-CAS boundary."""
    record = observation(start, workload_sha256)
    if not is_sha(workload_sha256):
        raise CostError(
            "undetermined",
            "verification.cost.workload",
            "missing registered protocol",
            record,
        )
    sufficient(record)
    return {**record, "status": "baseline-observation"}


def validate_profile(profile):
    if profile is None or profile == EXPERIMENT:
        return
    fields = {
        "format",
        "profile",
        "workloadSha256",
        "platformSha256",
        "baselineEvidenceSha256",
        "ceilings",
    }
    if (
        not isinstance(profile, dict)
        or set(profile) != fields
        or profile["format"] != POLICY_FORMAT
        or profile["profile"] not in ("ocs-release/1", "receiver-experiment/1")
    ):
        raise ValueError("unknown verification cost registration")
    if not all(
        is_sha(profile[k])
        for k in ("workloadSha256", "platformSha256", "baselineEvidenceSha256")
    ):
        raise ValueError(
            "missing exact preregistered workload, platform or baseline evidence"
        )
    limits = profile["ceilings"]
    if (
        not isinstance(limits, dict)
        or set(limits) != set(UNITS)
        or any(type(x) is not int or x < 0 for x in limits.values())
    ):
        raise ValueError(
            "each protected counter requires its own enrolled integral ceiling"
        )


def valid_reference(previous, record, registration):
    if (
        not isinstance(previous, dict)
        or previous.get("format") != FORMAT
        or previous.get("status") not in ("accepted", "baseline-observation")
    ):
        return False
    if any(
        previous.get(k) != record[k]
        for k in ("condition", "platformSha256", "workloadSha256", "boundary")
    ):
        return False
    if (
        previous["status"] == "accepted"
        and previous.get("registrationSha256") != registration
    ):
        return False
    if previous["status"] == "baseline-observation":
        binding = previous.get("acquisition")
        if not isinstance(binding, dict) or not is_sha(
            binding.get("verifiedReceiptSha256")
        ):
            return False
        if (
            not all(
                isinstance(binding.get(k), str)
                and re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", binding[k])
                for k in ("parent", "candidate")
            )
            or binding["parent"] == binding["candidate"]
        ):
            return False
    values = previous.get("observed")
    if (
        not isinstance(values, dict)
        or set(values) != set(UNITS)
        or any(type(v) is not int or v < 0 for v in values.values())
    ):
        return False
    provenance = previous.get("provenance")
    if (
        not isinstance(provenance, dict)
        or provenance.get("units") != UNITS
        or not isinstance(provenance.get("platform"), dict)
    ):
        return False
    if (
        fingerprint(provenance["platform"]) != record["platformSha256"]
        or provenance.get("finalPlatformSha256") != record["platformSha256"]
    ):
        return False
    a, b = provenance.get("first"), provenance.get("last")
    if (
        not isinstance(a, dict)
        or not isinstance(b, dict)
        or a.get("pid") != b.get("pid")
    ):
        return False
    try:
        return (
            all(
                s["inFlightChildren"] == 0
                and s["unavailable"] is None
                and set(s["counters"]) == set(UNITS)
                and all(type(v) is int and v >= 0 for v in s["counters"].values())
                for s in (a, b)
            )
            and all(b["counters"][k] >= a["counters"][k] for k in UNITS)
            and all(
                values[k]
                == (
                    b["counters"][k]
                    if k in PEAKS
                    else b["counters"][k] - a["counters"][k]
                )
                for k in UNITS
            )
        )
    except (KeyError, TypeError):
        return False


def finish_cost(start, registered_profile, previous_cost):
    workload = (
        registered_profile.get("workloadSha256")
        if isinstance(registered_profile, dict)
        else None
    )
    record = observation(start, workload)
    try:
        validate_profile(registered_profile)
    except ValueError as exc:
        raise CostError(
            "undetermined", "verification.cost.registration", str(exc), record
        ) from exc
    if registered_profile == EXPERIMENT:
        return {
            **record,
            "status": "observation-only",
            "registrationSha256": fingerprint(EXPERIMENT),
        }
    if registered_profile is None:
        raise CostError(
            "undetermined",
            "verification.cost.registration",
            "canonical cost registration is unavailable",
            record,
        )
    reg = fingerprint(registered_profile)
    record["registrationSha256"] = reg
    if registered_profile["platformSha256"] != record["platformSha256"]:
        raise CostError(
            "undetermined",
            "verification.cost.platform",
            "not the enrolled machine and method",
            record,
        )
    sufficient(record)
    previous_ok = valid_reference(previous_cost, record, reg)
    if previous_ok and previous_cost["status"] == "baseline-observation":
        previous_ok = (
            fingerprint(previous_cost) == registered_profile["baselineEvidenceSha256"]
        )
    rows = {}
    adverse = []
    for key, value in sorted(record["observed"].items()):
        prior = previous_cost["observed"][key] if previous_ok else None
        ceiling = registered_profile["ceilings"][key]
        rows[key] = {
            "direction": "min",
            "unit": UNITS[key],
            "value": value,
            "ceiling": ceiling,
            "previous": prior,
        }
        if value > ceiling or (prior is not None and value > prior):
            adverse.append(key)
    record.update(
        comparison=rows,
        adverse=adverse,
        baselineEvidenceSha256=registered_profile["baselineEvidenceSha256"],
    )
    if adverse:
        raise CostError(
            "rejected",
            "verification.cost.regression/" + adverse[0],
            "a registered ceiling or prior observed value was exceeded: "
            + ", ".join(adverse),
            record,
        )
    if not previous_ok:
        raise CostError(
            "undetermined",
            "verification.cost.baseline",
            "prior enrolled measurement is absent or incomparable",
            record,
        )
    return {**record, "status": "accepted"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    args = parser.add_subparsers(dest="command", required=True)
    args.add_parser("platform")
    baseline = args.add_parser(
        "baseline",
        help="replay the enrollment workload from an isolated receiver snapshot",
    )
    for label in ("config", "output"):
        baseline.add_argument("--" + label, type=Path, required=True)
    for label in ("parent", "candidate", "workload-sha256"):
        baseline.add_argument("--" + label, required=True)
    opts = parser.parse_args()
    if opts.command == "platform":
        info = platform_conditions()
        print(
            canonical(
                {"platform": info, "platformSha256": fingerprint(info), "units": UNITS}
            ).decode()
        )
        return
    if not is_sha(opts.workload_sha256):
        parser.error("expected the previously sealed workload SHA-256")
    if opts.output.exists():
        parser.error("output already exists")
    # Same installed prepare entry, fresh process, exclusive publication workload.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from admission import prepare, state
    from receiver import publication_lock

    _, _, journal, _, _ = state(opts.config)
    with publication_lock(journal):
        first = start_cost()
        receipt = prepare(opts.config, opts.parent, opts.candidate)
        result = baseline_cost(first, opts.workload_sha256)
    result["acquisition"] = {
        "parent": opts.parent,
        "candidate": opts.candidate,
        "verifiedReceiptSha256": fingerprint(receipt),
    }
    raw = canonical(result)
    with opts.output.open("xb") as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    print(hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    main()
