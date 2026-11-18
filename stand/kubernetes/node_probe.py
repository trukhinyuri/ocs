"""Measure the deployed adapter and recover coherent scoped state on fresh files in its pod."""

import argparse
import hashlib
import json
import sqlite3
import statistics
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "reference/provider"), str(ROOT / "reference")]
from contracts import utc_at, validate
from executor import PIN, Session
from service import ISSUER, MODEL, PRODUCT, ROUTE, Provider, Refused


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sample(fn, count):
    times = []
    last = None
    for _ in range(count):
        start = time.monotonic_ns()
        last = fn()
        times.append((time.monotonic_ns() - start) / 1e6)
    return last, times


def meta(**extra):
    return {"deadline": utc_at(time.time() + 5), "protocol": "0.1", "manifestDigest": PIN, **extra}


def call(session, op, args, key=None):
    return session.run(
        "tool.call",
        {
            "operation": op,
            "version": "1.0.0",
            "input": args,
            "meta": meta(**({"idempotencyKey": key} if key else {})),
        },
    )["data"]


def prepare(session, account, key):
    return session.run(
        "effect.prepare",
        {
            "operation": "quota.reset",
            "version": "1.0.0",
            "input": {"accountId": account, "grantId": "trial", "windows": ["weekly"]},
            "meta": meta(idempotencyKey=key),
        },
    )


def commit(session, proposal):
    return session.run(
        "effect.commit",
        {
            "operationId": proposal["operationId"],
            "intentDigest": proposal["intentDigest"],
            "meta": meta(),
        },
    )


def denied(fn):
    try:
        fn()
    except Refused as error:
        require(str(error) == "denied", "wrong refusal for revoked or foreign grant")
        return
    raise ValueError("an operation succeeded outside its resource grant")


def digest_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest_value(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def observed_account(path, owner, account):
    """Read-only snapshot of routing, entitlement and all scoped durable meters."""
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        connection = db.execute(
            """SELECT a.account,a.owner,a.can_write,a.credits,a.remaining,a.revision,c.org,
            c.enabled,c.signed,c.archived,c.last_model,c.last_mode,c.last_reply FROM accounts a JOIN connections c USING(account)
            WHERE a.account=? AND a.owner=?""",
            (account, owner),
        ).fetchone()
        require(connection is not None, "owned source account absent")
        entitlements = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM entitlements WHERE owner=? AND org=? ORDER BY plan",
                (owner, connection["org"]),
            )
        ]
        rows = [
            dict(r)
            for r in db.execute(
                """SELECT * FROM meters WHERE owner=? AND account=?
            ORDER BY meter,interval_id,event_key""",
                (owner, account),
            )
        ]
        replies = [r for r in rows if r["meter"] == "reply" and r["output"] is not None]
        require(
            entitlements and replies,
            "expected a real observed entitlement and a live metered reply",
        )
        last = max(replies, key=lambda r: (r["at"], r["event_key"]))
        reply = json.loads(last["output"])
        validate("profile-wire", reply, "modelOutput")
        require(
            (reply["accountId"], reply["route"], reply["model"]) == (account, ROUTE, MODEL)
            and reply["confirmed"] == reply["sent"],
            "meter retained a substituted response",
        )
        return {
            "connection": dict(connection),
            "entitlementSha256": digest_value(entitlements),
            "count": len(rows),
            "meterSha256": digest_value(rows),
            "receiptSha256": digest_value(reply),
            "eventKey": last["event_key"],
            "meteredAt": last["at"],
            "route": reply["route"],
            "model": reply["model"],
        }


def recover(source, store_path, account, owner):
    before = observed_account(store_path, owner, account)
    require(
        before["connection"]["enabled"] and before["connection"]["can_write"],
        "need an actually granted account",
    )
    with tempfile.TemporaryDirectory(
        dir=store_path.parent, prefix="qualification-restore-"
    ) as directory:
        backup = Path(directory) / "immutable-backup.sqlite"
        sizing = source.backup(backup)
        require(
            sizing["availableBytesBeforeBackup"] >= sizing["requiredBytes"]
            and sizing["bytes"] == backup.stat().st_size,
            "unqualified backup capacity",
        )
        original_sha = digest_file(backup)
        restored_path = Path(directory) / "restored.sqlite"
        # A fresh destination is published atomically by the storage owner.
        restore_size = Provider(backup).backup(restored_path)
        require(
            restore_size["availableBytesBeforeBackup"] >= restore_size["requiredBytes"],
            "unqualified restore capacity",
        )
        restored = Provider(restored_path)
        snap = observed_account(restored_path, owner, account)
        require(
            snap == before, "restored granted identity, terms, native reply, or meter set differs"
        )
        scoped = Session.for_http(restored, owner, "probe")
        foreign = Session.for_http(restored, "other-owner", "probe")
        denied(lambda: call(foreign, "limits.read", {"accountId": account}))

        # First obtain real approval for an effect on the *restored* account, then revoke it.
        pending = prepare(scoped, account, "revocation-after-restore")
        restored.record_approval(
            owner, pending["operationId"], pending["intentDigest"], int(time.time())
        )
        call(scoped, "account.enable", {"accountId": account, "enabled": False})
        denied(lambda: commit(scoped, pending))
        denied(
            lambda: call(
                scoped,
                "model.generate",
                {
                    "accountId": account,
                    "route": ROUTE,
                    "model": MODEL,
                    "input": [{"type": "text", "text": "sky"}],
                    "parameters": {"tier": "standard", "reasoning": "off"},
                },
                "revoked-reply",
            )
        )
        denied_state = scoped.run(
            "effect.readback", {"operationId": pending["operationId"], "meta": meta()}
        )
        require(denied_state["state"] == "not-applied", "revoked effect was applied")
        revoked = observed_account(restored_path, owner, account)
        require(
            not revoked["connection"]["can_write"]
            and revoked["connection"]["credits"] == before["connection"]["credits"]
            and revoked["meterSha256"] == before["meterSha256"],
            "revocation mutated the settled scope",
        )
        # Complete a separate disposable transaction, then physically recover its receipt and replay key.
        spare = call(
            scoped,
            "account.connect",
            {
                "provider": ISSUER,
                "product": PRODUCT,
                "authMethod": "local-none",
                "settings": {
                    "label": "Isolated restoration effect",
                    "organization": "restore-scratch",
                },
            },
        )["account"]["accountId"]
        proposal = prepare(scoped, spare, "restore-authorized-once")
        restored.record_approval(
            owner, proposal["operationId"], proposal["intentDigest"], int(time.time())
        )
        receipt = commit(scoped, proposal)
        require(receipt["state"] == "applied", "disposable authorized effect failed")
        second_path = Path(directory) / "receipt-restore.sqlite"
        second_size = restored.backup(second_path)
        second = Provider(second_path)
        secondary = Session.for_http(second, owner, "probe")
        checkback = secondary.run(
            "effect.readback", {"operationId": proposal["operationId"], "meta": meta()}
        )
        balance_before = second.balance(owner, spare)
        replayed = commit(secondary, proposal)
        require(
            checkback == receipt == replayed
            and second.balance(owner, spare) == balance_before
            and balance_before[0] == 0,
            "restored consequential effect was duplicated or lost",
        )
        # The original account, official entitlement and immutable backup have not been altered by the exercise.
        require(
            observed_account(store_path, owner, account) == before
            and digest_file(backup) == original_sha,
            "isolated restoration changed source or immutable backup",
        )
        return {
            "databaseBackupSha256": original_sha,
            "balance": list(source.balance(owner, account)),
            "verifiedTenantIsolation": True,
            "restoredMeterCount": snap["count"],
            "scopedMeterSha256": snap["meterSha256"],
            "observedReplySha256": snap["receiptSha256"],
            "meteredAt": utc_at(snap["meteredAt"]),
            "entitlementSha256": snap["entitlementSha256"],
            "requiredBackupBytes": sizing["requiredBytes"],
            "availableBeforeBackupBytes": sizing["availableBytesBeforeBackup"],
            "backupBytes": sizing["bytes"],
            "requiredRestoreBytes": restore_size["requiredBytes"],
            "availableBeforeRestoreBytes": restore_size["availableBytesBeforeBackup"],
            "revokedPreviouslyGrantedScope": True,
            "revokedOperationState": denied_state["state"],
            "appliedReceiptScope": receipt["scope"],
            "restoredReceiptSha256": digest_value(receipt),
            "restoredReceiptState": checkback["state"],
            "distinctEffectSpends": 1,
            "secondBackupBytes": second_size["bytes"],
            "sourceStateRetained": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--samples", type=int, default=32)
    parser.add_argument("--store", type=Path, default=Path("/data/provider.sqlite"))
    args = parser.parse_args()
    require(
        args.store.is_file() and args.samples > 0,
        "select an existing store and positive sample count",
    )
    owner = "qualification-account"
    service = Provider(args.store)
    session = Session.for_http(service, owner, "probe")
    native_reply, native = sample(
        lambda: service.windows(owner, args.account, int(time.time())), args.samples
    )
    bound_reply, wrapped = sample(
        lambda: call(session, "limits.read", {"accountId": args.account}), args.samples
    )

    def factual(windows):
        return [
            (w["windowId"], w["scope"], w["unit"], w["state"], w.get("remaining"))
            for w in windows["windows"]
        ]

    require(
        native_reply["accountId"] == bound_reply["accountId"] == args.account
        and factual(native_reply) == factual(bound_reply),
        "scope or observed balance changed between routes",
    )
    print(
        json.dumps(
            {
                "accountId": args.account,
                "nativeMs": native,
                "boundMs": wrapped,
                "samples": args.samples,
                "medianNativeMs": statistics.median(native),
                "medianBoundMs": statistics.median(wrapped),
                **recover(service, args.store, args.account, owner),
            }
        )
    )


if __name__ == "__main__":
    main()
