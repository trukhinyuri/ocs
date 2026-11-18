"""Restricted source-to-Lean translation at the provider's decision and transaction boundaries."""

import ast
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

ORACLE = Path(__file__).resolve().parent
TOOLCHAIN = "leanprover/lean4:v4.36.0-rc2"
APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def boolean_ir(node, args):
    if isinstance(node, ast.Name) and node.id in args:
        return args[node.id]
    if isinstance(node, ast.Constant) and type(node.value) in (bool, str):
        return json.dumps(node.value, ensure_ascii=False)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        op = " && " if isinstance(node.op, ast.And) else " || "
        return "(" + op.join(boolean_ir(v, args) for v in node.values) + ")"
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return "(!" + boolean_ir(node.operand, args) + ")"
    raise ValueError("unsupported or effectful Python decision expression: " + ast.dump(node))


def total_body(body, args):
    if not body:
        raise ValueError("decision can fall through")
    head, *tail = body
    if isinstance(head, ast.Return) and not tail:
        return boolean_ir(head.value, args)
    if isinstance(head, ast.If):
        return (
            "(if "
            + boolean_ir(head.test, args)
            + " then "
            + total_body(
                head.body + tail
                if not head.body or not isinstance(head.body[-1], ast.Return)
                else head.body,
                args,
            )
            + " else "
            + total_body(head.orelse + tail, args)
            + ")"
        )
    raise ValueError("unsupported Python decision statement: " + ast.dump(head))


def translate(path, names):
    statements = ast.parse(path.read_text()).body
    only_defs = [
        n
        for n in statements
        if not (
            isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str)
        )
    ]
    if not all(isinstance(n, ast.FunctionDef) for n in only_defs):
        raise ValueError("decision module must contain only its reviewed total definitions")
    funcs = {n.name: n for n in only_defs}
    if set(funcs) != set(names) or len(funcs) != len(only_defs):
        raise ValueError("unexpected, missing or redefined decision routine")
    result = []
    for name, (arity, typ) in names.items():
        f = funcs[name]
        p = f.args
        if (
            f.decorator_list
            or p.vararg
            or p.kwarg
            or p.posonlyargs
            or p.kwonlyargs
            or p.defaults
            or len(p.args) != arity
        ):
            raise ValueError("unsupported Python signature: " + name)
        args = {a.arg: "b" + str(i) for i, a in enumerate(p.args)}
        result.append(
            "def s_"
            + name
            + " ("
            + " ".join(args.values())
            + " : Bool) : "
            + typ
            + " :=\n  "
            + total_body(f.body, args)
        )
    return "\n\n".join(result)


def normalized_sql(statement):
    return " ".join(statement.strip().lower().split())


def expression(node):
    return ast.dump(node, include_attributes=False)


def expected_expression(source):
    return expression(ast.parse(source, mode="eval").body)


def provider_boundaries(root):
    """Check actual callers, identity operands, denial edges and the guarded mutations."""
    path = root / "reference/provider/service.py"
    module = ast.parse(path.read_text())
    cls = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == "Provider")
    functions = {f.name: f for f in [*module.body, *cls.body] if isinstance(f, ast.FunctionDef)}

    def pick(function, source):
        wanted = expected_expression(source)
        hits = [n for n in ast.walk(functions[function]) if expression(n) == wanted]
        if len(hits) != 1:
            raise ValueError(f"{function} lost its reviewed decision operand: {source}")
        return hits[0]

    def parent(function, node):
        return next(p for p in ast.walk(functions[function]) if node in ast.iter_child_nodes(p))

    def guard_matches(function, source, expected_stmt):
        cond = pick(function, source)
        guard = parent(function, cond)
        if (
            not isinstance(guard, ast.If)
            or len(guard.body) != 1
            or not isinstance(guard.body[0], expected_stmt)
        ):
            raise ValueError("unexpected policy branch in " + function)
        return guard

    def owning_transaction(name):
        block = parent(name, parent(name, pick(name, "self.transaction()")))
        if not isinstance(block, ast.With) or block not in functions[name].body:
            raise ValueError("qualified operation lost outer transaction: " + name)
        return block

    # A subclass lookup is dynamically dispatched by the real Ledger.prepare.
    # Treating that lookup as pure requires checking the installed implementation.
    for name in ("current_grant", "connection"):
        allowed = (
            {"self.connection", "db.execute", "bool", "Refused"}
            if name == "current_grant"
            else {"db.execute", "Refused"}
        )
        for call in (n for n in ast.walk(functions[name]) if isinstance(n, ast.Call)):
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "fetchone"
                and isinstance(call.func.value, ast.Call)
            ):
                continue
            fn = ast.unparse(call.func)
            if fn not in allowed or (
                fn == "db.execute"
                and (
                    not isinstance(call.args[0], ast.Constant)
                    or not normalized_sql(call.args[0].value).startswith("select ")
                )
            ):
                raise ValueError("unrecognized or mutating grant lookup: " + name)

    # Every allow is computed on the selected tenant, account, model and actual native options.
    admission = guard_matches(
        "generate",
        "not grant_generation(bool(r['enabled']),bool(r['signed']),entitled,supported,args['route']==ROUTE,options_ok)",
        ast.Raise,
    )
    for src in (
        "self.connection(db,owner,account)",
        "next((m for m in listed if m['id']==args['model']),{})",
        "all(p['type']=='text' for p in args['input'])",
        "bool(m.get('adapterSupported')) and args['model']==MODEL",
        "bool(m.get('entitled')) and now<e['expires']",
        "set(params)=={'reasoning','tier'} and params['reasoning']=='off' and params['tier'] in ('standard','fast') and params['tier'] in m.get('tiers',[]) and params['reasoning'] in m.get('reasoning',[]) and text_ok and 1<=args.get('maxOutputTokens',1)<=8",
    ):
        if pick("generate", src).lineno >= admission.lineno:
            raise ValueError("authorization input resolved after admission")
    invoke = pick(
        "generate",
        "invoke(r['account'],args['route'],args['model'],prompt,sent,args.get('maxOutputTokens',1))",
    )
    confirmation = guard_matches(
        "generate",
        "(execution['account'],execution['route'],execution['model'],execution['used'])!=(account,args['route'],args['model'],sent)",
        ast.Raise,
    )
    bound = owning_transaction("generate")
    if admission not in bound.body or confirmation not in bound.body:
        raise ValueError("admission/confirmation no longer dominates native generation")
    invocation_parent = parent("generate", parent("generate", invoke))
    if not isinstance(invocation_parent, ast.Try) or invocation_parent not in bound.body:
        raise ValueError("native call moved outside the reviewed linear path")
    if confirmation.lineno <= invoke.lineno:
        raise ValueError("response confirmed before native execution")
    calls = [n for n in ast.walk(functions["generate"]) if isinstance(n, ast.Return)]
    if (
        len(calls) != 1
        or expression(calls[0].value) != expected_expression("returned")
        or invoke.lineno <= admission.end_lineno
    ):
        raise ValueError("generation can return a non-attributed reply")

    # A snapshot has a single replacement edge. All other exits preserve the prior observation.
    accept = guard_matches(
        "complete_snapshot",
        "last and publish_complete(entry['origin']==identity,page['complete'],expected is None)",
        ast.Return,
    )
    for n in ast.walk(functions["complete_snapshot"]):
        if (
            isinstance(n, ast.Return)
            and n is not accept.body[0]
            and expression(n.value) != expected_expression("previous")
        ):
            raise ValueError("snapshot has an unguarded publication edge")
    for e in (
        "entry['token']!=expected or (expected is not None and expected in followed)",
        "entry['origin']!=identity or page['revision']!=revision",
        "not last and (page['complete'] or not expected)",
    ):
        scope_gate = guard_matches("complete_snapshot", e, ast.Return)
        if scope_gate.lineno >= accept.lineno or parent(
            "complete_snapshot", scope_gate
        ) is not parent("complete_snapshot", accept):
            raise ValueError("snapshot cursor/revision validated after publication")
    updated = pick("snapshot", "complete_snapshot(previous,pages,ident,kind)")
    unchanged = guard_matches("snapshot", "updated is previous", ast.Return)
    publication = pick(
        "snapshot",
        "db.execute('INSERT OR REPLACE INTO snapshots VALUES(?,?,?)',(owner,key,canonical(updated)))",
    )
    if not updated.lineno < unchanged.lineno < publication.lineno:
        raise ValueError("changed snapshot transaction ordering")
    block = owning_transaction("snapshot")
    if unchanged not in block.body or parent("snapshot", publication) not in block.body:
        raise ValueError("snapshot write can bypass the no-change guard")

    # Amounts are keyed by the authoritative pool/window and added just once.
    collect = guard_matches(
        "independent_total",
        "accept_amount(comparable,identity in independent_keys,known,identity in seen)",
        ast.Assign,
    )
    if expression(collect.body[0].targets[0]) != expression(
        ast.parse("seen[identity] = 0").body[0].targets[0]
    ):
        raise ValueError("aggregate target does not use the authoritative pool key")
    keyed_writes = [
        n
        for n in ast.walk(functions["independent_total"])
        if isinstance(n, ast.Subscript)
        and isinstance(n.ctx, ast.Store)
        and isinstance(n.value, ast.Name)
        and n.value.id == "seen"
    ]
    if len(keyed_writes) != 1 or keyed_writes[0] is not collect.body[0].targets[0]:
        raise ValueError("a pool amount can be written outside its accepted branch")
    prohibited = [
        n
        for n in ast.walk(functions["independent_total"])
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "seen"
        and n.func.attr != "values"
    ]
    if prohibited:
        raise ValueError("unrecognized amount-map mutation")
    for arg in (
        "(item['scope']['kind'],item['scope']['id'])",
        "item['unit']==unit and item.get('period')==period",
        "item['state']=='known' and 'remaining' in item",
    ):
        if pick("independent_total", arg).lineno >= collect.lineno:
            raise ValueError("amount admitted before scope/period check")
    returns = [n for n in ast.walk(functions["independent_total"]) if isinstance(n, ast.Return)]
    if (
        len(returns) != 1
        or pick("independent_total", "sum(values,Decimal(0))").lineno < collect.lineno
    ):
        raise ValueError("pool summary bypasses accepted members")

    # Duplicate and conflicting meter entries return/raise before INSERT. Callers own an IMMEDIATE transaction.
    cmp = pick(
        "meter", "meter_decision(old is not None,old is not None and old['signature']==signature)"
    )
    inserts = [
        n
        for n in ast.walk(functions["meter"])
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "execute"
    ]
    selects = [
        (normalized_sql(n.args[0].value), n) for n in inserts if isinstance(n.args[0], ast.Constant)
    ]
    if (
        len(selects) != 2
        or not selects[0][0].startswith("select ")
        and not selects[1][0].startswith("select ")
    ):
        raise ValueError("unexpected meter write set")
    read = next(
        n
        for sql, n in selects
        if sql
        == "select * from meters where owner=? and account=? and meter=? and interval_id=? and event_key=?"
    )
    write = next(
        n for sql, n in selects if sql == "insert into meters values(?,?,?,?,?,?,?,?,?,?,?,?)"
    )
    if (
        expression(read.args[1]) != expected_expression("(owner,account,meter,interval,key)")
        or not read.lineno < cmp.lineno
    ):
        raise ValueError("meter lookup lost scoped key")
    for expr, t in [("action=='replay'", ast.Return), ("action=='conflict'", ast.Raise)]:
        branch = guard_matches("meter", expr, t)
        if (
            branch not in functions["meter"].body
            or parent("meter", write) not in functions["meter"].body
            or not cmp.lineno < branch.lineno < write.lineno
        ):
            raise ValueError("meter admission occurs after write")
    returns = [n for n in ast.walk(functions["meter"]) if isinstance(n, ast.Return)]
    if len(returns) != 2 or not isinstance(functions["meter"].body[-1], ast.Return):
        raise ValueError("unexpected early meter outcome")
    for method in ("generate", "ingest_meter"):
        txn = pick(method, "self.transaction()")
        block = parent(method, parent(method, txn))
        calls = [
            n
            for n in ast.walk(functions[method])
            if isinstance(n, ast.Call) and ast.unparse(n.func) == "self.meter"
        ]
        if not isinstance(block, ast.With) or len(calls) != 1 or calls[0] not in ast.walk(block):
            raise ValueError("meter operation outside serialized transaction")
    return {
        "generationGuardLine": admission.lineno,
        "invocationLine": invoke.lineno,
        "catalogPublicationLine": publication.lineno,
        "poolAcceptanceLine": collect.lineno,
        "meterInsertionLine": write.lineno,
        "sourceSha256": sha(path),
    }


def ledger_boundary(root):
    """Translate this sealed Python/SQL dispatch region. Unknown programs fail closed.

    SQL primitive meanings are those of a successful SQLite BEGIN IMMEDIATE transaction.
    A resource write is recognized by its relation, exact update, and bound arguments.
    """
    src = root / "examples/reset/ledger.py"
    tree = ast.parse(src.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Ledger")
    funcs = {n.name: n for n in cls.body if isinstance(n, ast.FunctionDef)}

    def calls(nodes):
        return [c for n in nodes for c in ast.walk(n) if isinstance(c, ast.Call)]

    def sql(nodes):
        rows = []
        for n in calls(nodes):
            if isinstance(n.func, ast.Attribute) and n.func.attr == "execute":
                if not isinstance(n.args[0], ast.Constant) or not isinstance(n.args[0].value, str):
                    raise ValueError("unbounded SQL at effect boundary")
                rows.append((normalized_sql(n.args[0].value), [expression(x) for x in n.args[1:]]))
        return rows

    def mutations(nodes):
        return [(s, a) for s, a in sql(nodes) if not s.startswith("select ")]

    def sqlrow(s, args):
        return (normalized_sql(s), [expected_expression(args)])

    if sql(funcs["transaction"].body) != [("begin immediate", [])]:
        raise ValueError("effect writes lost serialized transaction")
    # Resource preparation may only add proposal metadata in the nested create branch.
    prepare = mutations(funcs["prepare"].body)
    if len(prepare) != 1 or not prepare[0][0].startswith(
        "insert into proposals(id, issuer, owner, account, request_key, intent, digest, expires) values ("
    ):
        raise ValueError("preparation touches resource or unrecognized write set")
    if any(
        isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign))
        and any(isinstance(t, (ast.Attribute, ast.Subscript)) for t in getattr(n, "targets", []))
        for n in ast.walk(funcs["prepare"])
    ):
        raise ValueError("unrecognized preparation mutation")
    trusted_prepare = {
        "self.transaction",
        "self.account",
        "self.current_grant",
        "self.proposal",
        "db.execute",
        "json.loads",
        "json.dumps",
        "proposal_decision",
        "secrets.token_hex",
        "intent_hash",
        "str",
        "timestamp",
        "Refused",
    }
    for call in calls(funcs["prepare"].body):
        name = ast.unparse(call.func)
        if name.endswith(".fetchone") and isinstance(call.func.value, ast.Call):
            continue
        if name not in trusted_prepare:
            raise ValueError("unrecognized preparation primitive: " + name)
    for k in ("account", "proposal", "current_grant"):
        if mutations(funcs[k].body):
            raise ValueError("lookup mutated resource: " + k)

    body = [
        n
        for n in funcs["commit"].body
        if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))
    ]
    txn = body[0]
    if (
        not isinstance(txn, ast.With)
        or len(txn.items) != 1
        or expression(txn.items[0].context_expr) != expected_expression("self.transaction()")
    ):
        raise ValueError("commit lost the linearization boundary")
    ops = txn.body
    if (
        len(ops) != 9
        or not all(isinstance(n, ast.Assign) for n in ops[:4])
        or not all(isinstance(n, ast.If) for n in ops[4:7])
    ):
        raise ValueError("unrecognized commit control flow")
    for node, var, value in zip(
        ops[:4],
        ["row", "state", "intent", "verdict"],
        [
            "self.proposal(db,owner,operation_id)",
            "self.account(db,owner,row['account'])",
            "json.loads(row['intent'])",
            """commit_decision(row['digest']==digest,row['applied_at'] is not None,
                                       row['reserved_at'] is not None,self.current_grant(db,state,now),bool(row['approved']),
                                       now<row['expires'],intent['manifestDigest']==current_pin,state['credits']>0 and str(state['revision'])==intent['preconditions']['revision'])""",
        ],
    ):
        if [expression(x) for x in node.targets] != [
            expression(ast.Name(id=var, ctx=ast.Store()))
        ] or expression(node.value) != expected_expression(value):
            raise ValueError("commit lost identity or eligibility operand: " + var)
    replay, deny, local = ops[4:7]
    if (
        expression(replay.test) != expected_expression("verdict in ('replay','reserved')")
        or replay.orelse
        or len(replay.body) != 1
        or not isinstance(replay.body[0], ast.Return)
        or expression(replay.body[0].value) != expected_expression("self.receipt(row,now)")
    ):
        raise ValueError("terminal/unknown state does not replay")
    if (
        expression(deny.test) != expected_expression("verdict!='apply'")
        or deny.orelse
        or len(deny.body) != 1
        or not isinstance(deny.body[0], ast.Raise)
        or expression(deny.body[0].exc) != expected_expression("Refused(verdict)")
    ):
        raise ValueError("refused commit can reach a write")
    if (
        expression(local.test) != expected_expression("deliver is None")
        or local.orelse
        or len(local.body) != 3
        or not isinstance(local.body[-1], ast.Return)
    ):
        raise ValueError("local/remote commit boundary changed")
    if mutations(local.body) != [
        sqlrow(
            "UPDATE accounts SET credits=credits-1, remaining=100, revision=revision+1 WHERE account=?",
            "(row['account'],)",
        ),
        sqlrow("UPDATE proposals SET applied_at=? WHERE id=?", "(now,operation_id)"),
    ]:
        raise ValueError("local debit/receipt is incorrect")
    if mutations(ops[7:]) != [
        sqlrow("INSERT INTO dispatch_reservations VALUES (?,?)", "(operation_id,now)"),
        sqlrow(
            "UPDATE accounts SET credits=credits-1,revision=revision+1 WHERE account=?",
            "(row['account'],)",
        ),
    ]:
        raise ValueError("downstream effect not preceded by a durable reservation")
    deliveries = [
        c for c in calls(body[1:]) if isinstance(c.func, ast.Name) and c.func.id == "deliver"
    ]
    if len(deliveries) != 1 or expression(deliveries[0]) != expected_expression(
        "deliver(operation_id,digest,owner,row['account'])"
    ):
        raise ValueError("unscoped or repeated dispatch")
    if (
        len(body) != 4
        or not isinstance(body[1], ast.Try)
        or not isinstance(body[2], ast.If)
        or not isinstance(body[3], ast.Return)
    ):
        raise ValueError("unknown post-reservation control path")
    if (
        len(body[1].body) != 1
        or body[1].orelse
        or body[1].finalbody
        or body[2].orelse
        or len(body[2].body) != 1
    ):
        raise ValueError("uncertain dispatch can take an unreviewed branch")
    after = {ast.unparse(c.func) for c in calls(body[1:])}
    if after != {"deliver", "self.confirm_external", "self.readback"}:
        raise ValueError("unknown or unscoped post-commit execution")
    if any(
        isinstance(n, (ast.For, ast.While, ast.comprehension)) for n in ast.walk(funcs["commit"])
    ):
        raise ValueError("unrecognized repeated commit")
    return {
        "transaction": sql(funcs["transaction"].body)[0][0],
        "prepareWrites": [p[0] for p in prepare],
        "localWrites": [s for s, a in mutations(local.body)],
        "externalReservations": [s for s, a in mutations(ops[7:])],
        "afterCommitCalls": len(deliveries),
    }


MODEL_TYPES = {
    "eligible_exact": "EligibleExact",
    "partial_preserves": "RetainPartial",
    "wrong_scope_preserves": "RetainScope",
    "duplicate_meter_no_add": "DuplicateMeter",
    "duplicate_pool_no_add": "DuplicatePool",
    "independent_pools_add": "IndependentPools",
    "changed_meter_conflicts": "ChangedMeter",
    "prepare_inert": "Inert",
    "denial_preserves": "NoAuthority",
    "stale_preserves": "NoEligibility",
    "once_over_trace": "Once",
    "unknown_preserved": "NoRetry",
    "commit_witness": "GoodWitness",
    "denial_witness": "BadWitness",
    "unknown_witness": "UnknownWitness",
    "readback_inert": "∀ s : Effect, step s .readback = s",
    "terminal_readback": "∀ (s : Effect) (a b c : Bool), s.result = .applied → step s (.commit a b c) = s",
    "identical_intent_replays": "∀ i : Intent, propose (some i) i = 1",
    "intent_changes_conflict": "∀ a b : Intent, a ≠ b → propose (some a) b = 2",
    "direct_consequence_denied": "∀ a b c d : Bool, directAllowed a b c d = true ↔ a=false ∧ b=false ∧ c=false ∧ d=false",
    "zero_distinct": "countable (.known 0) = some 0 ∧ countable .unknown = none ∧ countable .unlimited = none ∧ countable (.percent 25) = none ∧ countable (.stale 0) = none ∧ countable .unsupported = none",
    "prices_distinct": "committedPrice (.confirmed 0) = some 0 ∧ committedPrice .contractual = none ∧ committedPrice .unknown = none ∧ committedPrice .unpublished = none",
    "exact_scope": "∀ (s i o : Nat) (ticket : Nat × Nat × Nat) (expired consumed : Bool), authentic s i o ticket expired consumed = true ↔ ticket = (s,i,o) ∧ expired=false ∧ consumed=false",
    "separate_identity": "∀ a b : Identity, a = b ↔ a.issuer=b.issuer ∧ a.subject=b.subject ∧ a.product=b.product ∧ a.account=b.account ∧ a.organization=b.organization ∧ a.route=b.route ∧ a.method=b.method ∧ a.plan=b.plan ∧ a.pool=b.pool",
    "usage_partition": "∀ a p f : Bool, usageClass a p f = 0 ↔ a=true ∧ p=false ∧ f=false",
    "reset_eligible": "∀ (n : Nat) (r t : Bool), offerReset n r t = true ↔ 0<n ∧ r=true ∧ t=true",
    "derived_notice_absent": "∀ (l : List Nat) (n : List (Nat × Nat)) (i : Nat), i ∉ n.map Prod.fst → noticeVisible l n i = false",
}

SOURCE_TYPES = {
    "route_matches_source": (6, "s_grant_generation a b c d e f = eligible a b c d e f"),
    "publish_matches_source": (3, "s_publish_complete a b c = (a && b && c)"),
    "pool_matches_source": (4, "s_accept_amount a b c d = (a && b && c && !d)"),
    "meter_matches_source": (
        2,
        's_meter_decision a b = if !a then "append" else if b then "replay" else "conflict"',
    ),
    "direct_matches_source": (4, "s_permit_invocation a b c d = directAllowed a b c d"),
    "handle_matches_source": (6, "s_authorize_handle a b c d e f = (a && b && c && d && e && f)"),
    "prepare_matches_source": (
        2,
        's_proposal_decision a b = if !a then "create" else if b then "replay" else "conflict"',
    ),
    "commit_matches_source": (
        8,
        's_commit_decision a b c d e f g h = if !a then "conflict" else if b then "replay" else if c then "reserved" else if !d || !e then "denied" else if !f then "deadline" else if !g then "pin" else if !h then "conflict" else "apply"',
    ),
}


def verify(subject, certificate_path=None):
    model = subject / "assurance/provider/Provider.lean"
    if re.search(
        r"(?m)^\s*(?:axiom|unsafe|elab|macro|syntax|initialize|#eval|run_cmd)\b|\bsorry\b|\bnative_decide\b|skipKernelTC|trustCompiler",
        model.read_text(),
    ):
        raise ValueError("unexpected trusted or unfinished declaration in candidate provider proof")
    if re.findall(r"(?m)^import (\S+)\s*$", model.read_text()) != ["Contract"]:
        raise ValueError("provider proof imports outside approved contract")
    srcfiles = [subject / "reference/provider/policy.py", subject / "examples/reset/decision.py"]
    translated = translate(
        srcfiles[0],
        {
            "grant_generation": (6, "Bool"),
            "publish_complete": (3, "Bool"),
            "accept_amount": (4, "Bool"),
            "meter_decision": (2, "String"),
            "permit_invocation": (4, "Bool"),
            "authorize_handle": (6, "Bool"),
        },
    )
    translated += "\n" + translate(
        srcfiles[1], {"commit_decision": (8, "String"), "proposal_decision": (2, "String")}
    )
    boundaries = ledger_boundary(subject)
    provider = provider_boundaries(subject)
    check = "\n".join(
        f"example : {typ} := {name}\n#print axioms OCS.Provider.{name}"
        for name, typ in MODEL_TYPES.items()
    )
    for name, (n, typ) in SOURCE_TYPES.items():
        names = list("abcdefgh"[:n])
        split = " <;> ".join([f"cases {x}" for x in names] + ["decide"])
        check += f"\ntheorem {name} ({' '.join(names)} : Bool) : {typ} := by {split}\n#print axioms OCS.Provider.{name}\n"
    local_debits = sum("credits=credits-1" in sql for sql in boundaries["localWrites"])
    remote_debits = sum("credits=credits-1" in sql for sql in boundaries["externalReservations"])
    prepare_debits = sum("update accounts" in sql for sql in boundaries["prepareWrites"])
    translated += f"\ndef prepareDebits : Nat := {prepare_debits}\ndef localDebits : Nat := {local_debits}\ndef remoteReservations : Nat := {remote_debits}\n"
    check += """
theorem prepare_source_inert (balance : Nat) : balance - prepareDebits = balance := by
  simp [prepareDebits]
#print axioms OCS.Provider.prepare_source_inert
def sourceCommit (s : Effect) (digest grant approved expiry pin pre external : Bool) : Effect :=
  let action := s_commit_decision digest (s.result == .applied) (s.result == .uncertain) grant approved expiry pin pre
  if action == "apply" then
    ⟨if external then .uncertain else .applied, s.dispatches + (if external then remoteReservations else localDebits)⟩
  else s
theorem commit_source_refines (s : Effect) (digest grant approved expiry pin pre external : Bool)
  (reachable : s.result ≠ .rejected) :
  sourceCommit s digest grant approved expiry pin pre external =
     step s (.commit approved (digest && grant && expiry && pin && pre) external) := by
  rcases s with ⟨state, count⟩
  cases state <;> cases digest <;> cases grant <;> cases approved <;> cases expiry <;>
    cases pin <;> cases pre <;> cases external <;>
    simp_all [sourceCommit, s_commit_decision, step, localDebits, remoteReservations]
#print axioms OCS.Provider.commit_source_refines
"""
    derived = ["prepare_source_inert", "commit_source_refines"]
    with tempfile.TemporaryDirectory(prefix="ocs-provider-proof-") as directory:
        out = Path(directory)
        (out / "Contract.lean").write_bytes((ORACLE / "Contract.lean").read_bytes())
        (out / "Provider.lean").write_bytes(model.read_bytes())
        (out / "Check.lean").write_text(
            "import Provider\nnamespace OCS.Provider\n"
            + translated
            + "\n"
            + check
            + "\nend OCS.Provider\n"
        )
        env = {**os.environ, "LEAN_PATH": directory}
        outputs = []
        for n in ("Contract", "Provider", "Check"):
            run = subprocess.run(
                [
                    "elan",
                    "run",
                    TOOLCHAIN,
                    "lean",
                    "-DwarningAsError=true",
                    "-o",
                    n + ".olean",
                    n + ".lean",
                ],
                cwd=out,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=120,
            )
            if run.returncode:
                raise ValueError("Lean rejected " + n + ": " + run.stdout[-1400:])
            outputs.append(run.stdout)
        audit = outputs[-1]
        axiom_sets = {}
        for name in (*MODEL_TYPES, *SOURCE_TYPES, *derived):
            text = re.search(
                r"'OCS\.Provider\."
                + name
                + r"' (?:depends on axioms: \[([^]]*)\]|does not depend on any axioms)",
                audit,
            )
            if not text:
                raise ValueError("missing axiom audit for " + name)
            axioms = {a.strip() for a in (text[1] or "").split(",") if a.strip()}
            if not axioms <= APPROVED_AXIOMS:
                raise ValueError("unapproved axiom for " + name + ": " + str(axioms))
            axiom_sets[name] = sorted(axioms)
        derived_file = out / "Check.lean"
        if certificate_path is not None:
            certificate_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=certificate_path.parent, delete=False) as copy:
                copy.write(derived_file.read_bytes())
                staged = Path(copy.name)
            os.replace(staged, certificate_path)
        toolprefix = subprocess.check_output(
            ["elan", "run", TOOLCHAIN, "lean", "--print-prefix"], text=True
        ).strip()
        kernel = Path(toolprefix) / "bin/leanchecker"
        version = subprocess.check_output(
            ["elan", "run", TOOLCHAIN, "lean", "--githash"], text=True
        ).strip()
        if version != "b35cb10cf2ced51a2fd1880cfdbf75c71ab7a35a":
            raise ValueError("unexpected Lean toolchain commit")
        replay = subprocess.run(
            [str(kernel), "--silent", "Contract", "Provider", "Check"],
            cwd=out,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if replay.returncode:
            raise ValueError(
                "exported provider certificate rejected by leanchecker: " + replay.stderr[-300:]
            )
        return {
            "checker": TOOLCHAIN,
            "kernelExecutableSha256": sha(Path(toolprefix) / "bin/lean"),
            "certificateCheckerSha256": sha(kernel),
            "toolchainCommit": version,
            "contractSha256": sha(ORACLE / "Contract.lean"),
            "proofSha256": sha(model),
            "generatedCertificateSha256": sha(derived_file),
            "generatedCertificate": certificate_path.name if certificate_path else None,
            "axioms": axiom_sets,
            "theorems": list(MODEL_TYPES),
            "sourceTheorems": [*SOURCE_TYPES, *derived],
            "sourceSha256": {
                str(p.relative_to(subject)): sha(p)
                for p in [*srcfiles, subject / "examples/reset/ledger.py"]
            },
            "sqliteAbstraction": boundaries,
            "providerDecisionSites": provider,
        }
