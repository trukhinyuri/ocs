#!/usr/bin/env python3
"""Trusted fixture operator. Give these commands only to the owner of the test store."""

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
from contracts import read_json
from jsonschema import ValidationError
from service import ISSUER, ORIGIN, PLAN, Provider, Refused, canonical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--fixture-clock", type=int)
    commands = parser.add_subparsers(dest="action", required=True)
    approve = commands.add_parser("approve")
    approve.add_argument("operation")
    approve.add_argument("digest")
    mint = commands.add_parser("mint")
    mint.add_argument("flow")
    mint.add_argument("--issuer", default=ISSUER)
    mint.add_argument("--origin", default=ORIGIN)
    mint.add_argument("--lifetime", type=int, default=60)
    term = commands.add_parser("expire")
    term.add_argument("account")
    ingest = commands.add_parser("meter")
    for key in ("account", "meter", "key", "interval"):
        ingest.add_argument(key)
    for key in ("quantity", "unit_minor", "at"):
        ingest.add_argument(key, type=int)
    sync = commands.add_parser("sync")
    sync.add_argument("kind", choices=("catalog", "accounts"))
    sync.add_argument("file", type=Path)
    cached = commands.add_parser("cache")
    cached.add_argument("kind")
    cached.add_argument("context", type=Path)
    terms = commands.add_parser("terms")
    terms.add_argument("account")
    overview = commands.add_parser("overview")
    overview.add_argument("--human", action="store_true")
    overview.add_argument("--model")
    overview.add_argument("--provider")
    overview.add_argument("--status")
    overview.add_argument("--time-zone", default="UTC")
    plan = commands.add_parser("billing-plan")
    plan.add_argument("account")
    plan.add_argument("observation", choices=("ambiguous", "resolved"))
    clone = commands.add_parser("backup")
    clone.add_argument("destination", type=Path)
    confirm = commands.add_parser("reconcile")
    confirm.add_argument("operation")
    confirm.add_argument("digest")
    confirm.add_argument("database", type=Path)
    options = parser.parse_args()
    now = options.fixture_clock if options.fixture_clock is not None else int(time.time())
    service = Provider(options.store)
    owner = options.principal
    try:
        if options.action == "approve":
            service.record_approval(owner, options.operation, options.digest, now)
            result = {"recorded": True}
        elif options.action == "mint":
            result = {
                "connectionHandle": service.mint(
                    owner, options.flow, options.issuer, options.origin, now + options.lifetime
                )
            }
        elif options.action == "expire":
            with service.transaction() as db:
                row = service.connection(db, owner, options.account)
                db.execute(
                    "UPDATE entitlements SET expires=? WHERE owner=? AND org=? AND plan=?",
                    (now, owner, row["org"], PLAN),
                )
            result = {"expired": True}
        elif options.action == "meter":
            added = service.ingest_meter(
                owner,
                options.account,
                options.meter,
                options.key,
                options.interval,
                options.quantity,
                options.unit_minor,
                options.at,
            )
            result = {"added": added}
        elif options.action == "sync":
            d = read_json(options.file.read_bytes())
            result = {"published": service.snapshot(owner, options.kind, d["identity"], d["pages"])}
        elif options.action == "cache":
            key = canonical({"kind": options.kind, **read_json(options.context.read_bytes())})
            with service.transaction() as db:
                r = db.execute(
                    "SELECT value FROM snapshots WHERE owner=? AND context=?", (owner, key)
                ).fetchone()
                ns = db.execute(
                    "SELECT COUNT(*) FROM notices WHERE owner=? AND context=?", (owner, key)
                ).fetchone()[0]
                result = {"snapshot": json.loads(r[0]) if r else None, "notices": ns}
        elif options.action == "terms":
            result = service.terms(owner, options.account, now)
        elif options.action == "billing-plan":
            service.plan_observation(owner, options.account, options.observation == "ambiguous")
            result = {"billingObservation": options.observation}
        elif options.action == "overview":
            query = {
                "timeZone": options.time_zone,
                **{
                    k: getattr(options, k)
                    for k in ("model", "provider", "status")
                    if getattr(options, k) is not None
                },
            }
            result = service.overview(owner, now, query)
            if options.human:
                print(
                    f"Accounts {result['count']} | enabled {result['enabled']} | working {result['working']} | attention {result['attention']}"
                )
                for a in result["accounts"]:
                    w = a["limitingWindow"]
                    print(
                        f"{a['label']} [{a['accountId']}] | {a['state']} | remaining {w.get('remaining', w['state'])} {w['unit']} | resets {a['resetAtLocal']} ({a['timeZone']}, in {a['secondsUntilReset']} seconds) | observed {w['evidence']['observedAt']}"
                    )
                return 0
        elif options.action == "backup":
            result = service.backup(options.destination)
        else:
            receipt = service.readback(owner, options.operation, now)
            with sqlite3.connect(options.database.resolve().as_uri() + "?mode=ro", uri=True) as db:
                n = db.execute(
                    "SELECT COUNT(*) FROM deliveries WHERE op=? AND digest=? AND owner=? AND account=?",
                    (options.operation, options.digest, owner, receipt["scope"]["id"]),
                ).fetchone()[0]
            if n != 1:
                raise Refused("unknown_effect")
            service.confirm_external(owner, options.operation, options.digest, now)
            result = service.readback(owner, options.operation, now)
        print(canonical(result))
        return 0
    except ValidationError as e:
        print("Invalid scoped input at /" + "/".join(map(str, e.absolute_path)), file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as e:
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
