"""Translate the sealed reference dispatchers, preserving branch order and ready writes.

Normalized guard syntax denotes observations of a decoded request. The published
guard dictionary supplies their interpretation. Every other dispatch statement
is interpreted or rejected. Parsing/clock/library contracts belong to the TCB.
"""

import ast
import copy
import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAULTS = {
    (-32602, "params"): "params",
    (-32601, "method"): "method",
    (-33001, "denied"): "denied",
    (-33005, "deadline"): "expired",
    (-33008, "incompatible"): "incompatible",
    (-33009, "input"): "input",
    (-33014, "pin"): "pin",
}


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_hash(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def ast_repr(node):
    return ast.dump(node, include_attributes=False)


def fn(tree, name, kind=ast.FunctionDef):
    choices = [node for node in tree.body if isinstance(node, kind) and node.name == name]
    require(len(choices) == 1, "expected one definition of " + name)
    return choices[0]


def stmt(s):
    return {"kind": "stmt", "expr": s}


def gate(test, verdict):
    return ("branch", test, [("return", verdict)], [])


def clock_gates():
    return [gate("!f.dateSyntax", "params"), gate("!f.future", "expired")]


def translate_sequence(ops, state="s", indent="  "):
    if not ops:
        raise ValueError("source path is missing a terminal reply")
    op, *rest = ops
    if op[0] == "state":
        return translate_sequence(rest, op[1], indent)
    if op[0] == "return":
        return f"({state}, .{op[1]})"
    if op[0] != "branch":
        raise ValueError("unknown control instruction")
    _, test, yes, no = op
    positive = translate_sequence(yes + rest, state, indent + "  ")
    negative = translate_sequence(no + rest, state, indent + "  ")
    return f"if {test.format(state=state)} then\n{indent}  {positive}\n{indent}else\n{indent}  {negative}"


def py_fault(exception):
    require(
        isinstance(exception, ast.Call)
        and ast.unparse(exception.func) == "Fault"
        and not exception.keywords
        and len(exception.args) in (3, 4),
        "unknown raised value",
    )
    code, kind, message, *path = [ast.literal_eval(x) for x in exception.args]
    require(isinstance(message, str) and bool(message), "empty fault message")
    verdict = FAULTS[(code, kind)]
    require(path == (["/resourceId"] if verdict == "input" else []), "incorrect fault scope")
    return verdict


def python_ops(body, guards, context, available):
    ops = []
    local = set(available)
    for n in body:
        for word in ast.walk(n.test if isinstance(n, ast.If) else n):
            if (
                isinstance(word, ast.Name)
                and isinstance(word.ctx, ast.Load)
                and word.id in {"meta", "value"}
            ):
                require(word.id in local, f"unbound Python alias {word.id}")
        if isinstance(n, ast.If):
            test = ast_repr(n.test)
            require(test in guards, "unknown Python predicate: " + ast.unparse(n.test))
            ops.append(
                (
                    "branch",
                    guards[test],
                    python_ops(n.body, guards, context, local),
                    python_ops(n.orelse, guards, context, local),
                )
            )
        elif isinstance(n, ast.Raise):
            ops.append(("return", py_fault(n.exc)))
        elif isinstance(n, ast.Assign):
            s = ast.unparse(n)
            if s in ("self.ready = False", "self.ready = True"):
                ops.append(("state", s.split()[-1].lower()))
            elif s in ("meta = params['meta']", "value = params['input']"):
                local.add(n.targets[0].id)
            else:
                raise ValueError("unknown Python write: " + s)
        elif isinstance(n, ast.Expr):
            s = ast.unparse(n.value)
            if s in ("deadline(meta)", "deadline(params['meta'])"):
                ops.extend(clock_gates())
            else:
                field_checks = {
                    "fields(params, ['protocols', 'requiredFeatures', 'meta'])": (
                        "Describe",
                        "!f.shape",
                    ),
                    "fields(params['meta'], ['deadline'], ['traceId'])": (
                        "Describe",
                        "!f.metadata",
                    ),
                    "fields(params, ['operation', 'version', 'input', 'meta'])": (
                        "Read",
                        "!f.shape",
                    ),
                    "fields(meta, ['deadline', 'protocol', 'manifestDigest'], ['traceId', 'parentCallId', 'idempotencyKey'])": (
                        "Read",
                        "!f.metadata",
                    ),
                }
                role, predicate = field_checks[s]
                require(context == role, "shape check attached to the wrong operation")
                ops.append(gate(predicate, "params"))
        elif isinstance(n, ast.Return):
            s = ast.unparse(n.value)
            returns = {
                "{'data': {'resourceId': 'demo', 'state': 'ready'}}": "delivered",
                "{'protocol': '0.1', 'packageId': DESCRIPTOR['id'], 'packageVersion': DESCRIPTOR['version'], 'manifestDigest': DIGEST, 'features': [], 'maxFrameBytes': LIMIT}": "described",
            }
            ops.append(("return", returns[s]))
        else:
            raise ValueError("unhandled Python statement: " + ast.unparse(n))
    return ops


def py_constants(tree):
    return {
        n.targets[0].id: n.value.value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and isinstance(n.value, ast.Constant)
    }


def lift_python(tree, registry, trust):
    require(
        all(
            isinstance(n, (ast.Assign, ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))
            for n in tree.body[1:-1]
        ),
        "unexpected Python executable module initializer",
    )
    primitives = {
        n.name: digest(ast_repr(n).encode())
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name not in ("serve", "Session")
    }
    primitives["module-data"] = json_hash(
        [ast_repr(n) for n in tree.body if isinstance(n, (ast.Assign, ast.Import, ast.ImportFrom))]
    )
    serve = fn(tree, "serve")
    loop = serve.body[1]
    require(
        isinstance(loop, ast.While) and len(loop.body) == 4 and not loop.orelse,
        "unsupported stdio loop",
    )
    primitives["envelope"] = digest(ast_repr(loop.body[2]).encode())
    require(primitives == trust, "Python decoder, clock, envelope or classifier primitive changed")
    require(
        [ast.unparse(s) for s in serve.body[:1] + serve.body[2:]]
        == ["session = Session()", "return 0"],
        "unexpected Python EOF, initialization or loop exit",
    )
    require(
        ast.unparse(loop.test) == "(raw := sys.stdin.buffer.readline(LIMIT + 2))",
        "unsupported bounded readline",
    )
    oversize, rid, _, flush = loop.body
    require(
        isinstance(oversize, ast.If)
        and ast.unparse(oversize.test) == "not raw.endswith(b'\\n') or len(raw) - 1 > LIMIT"
        and [ast.unparse(n) for n in oversize.body] == ["return 2"]
        and not oversize.orelse,
        "wrong byte boundary, terminator or close",
    )
    require(
        ast.unparse(rid) == "rid = None"
        and ast.unparse(flush)
        == "print(json.dumps({'jsonrpc': '2.0', 'id': rid, **reply}, allow_nan=False), flush=True)",
        "unsupported Python response framing",
    )
    require(
        ast.unparse(tree.body[-1]) == "if __name__ == '__main__':\n    raise SystemExit(serve())",
        "Python entry no longer invokes the admitted stdio loop",
    )
    cls = fn(tree, "Session", ast.ClassDef)
    require(
        [ast.unparse(s) for s in fn(cls, "__init__").body] == ["self.ready = False"],
        "wrong initial phase",
    )
    require(
        not cls.bases and not cls.decorator_list and len(cls.body) == 2,
        "unexpected session members",
    )
    dispatch = fn(cls, "run")
    require(
        not dispatch.decorator_list
        and [a.arg for a in dispatch.args.args] == ["self", "method", "params"]
        and not dispatch.args.defaults
        and not dispatch.args.kwonlyargs,
        "unexpected Python dispatch entry",
    )
    body = dispatch.body
    desc, unknown = body[:2]
    require(
        isinstance(desc, ast.If)
        and isinstance(unknown, ast.If)
        and not desc.orelse
        and not unknown.orelse
        and ast.unparse(desc.test) == "method == 'ocs.describe'"
        and ast.unparse(unknown.test) == "method != 'tool.call'",
        "unknown Python method selection",
    )
    guards = {
        ast_repr(ast.parse(s, mode="eval").body): predicate for s, predicate in registry.items()
    }
    outputs = {
        k: translate_sequence(python_ops(statements, guards, k, set()))
        for k, statements in [("Describe", desc.body), ("Other", unknown.body), ("Read", body[2:])]
    }
    outputs["frameLimit"] = py_constants(tree)["LIMIT"]
    return outputs


def go_fault(raw):
    match = re.fullmatch(r'return fault\((-?\d+), ("(?:\\.|[^"\\])*"), ("(?:\\.|[^"\\])*")\)', raw)
    if match:
        code, kind, message = match.groups()
        require(json.loads(message), "empty Go error message")
        return FAULTS[(int(code), json.loads(kind))]
    error = re.fullmatch(
        r'return object\{"error": object\{"code": -33009, "message": ("(?:\\.|[^"\\])*"), '
        r'"data": object\{"kind": "input", "path": "/resourceId"\}\}\}',
        raw,
    )
    if error and json.loads(error.group(1)):
        return "input"
    raise ValueError("unknown Go fault shape: " + raw)


def go_ops(body, guards, context):
    ops = []
    aliases = {
        "Describe": {
            'protocols, valid := stringSet(p["protocols"], nil)',
            'features, validFeatures := stringSet(p["requiredFeatures"], featureName)',
        },
        "Read": {
            'pin, _ := meta["manifestDigest"].(string)',
            'op, _ := p["operation"].(string)',
            'version, _ := p["version"].(string)',
            'in, _ := p["input"].(object)',
            'id, ok := in["resourceId"].(string)',
        },
        "Other": set(),
    }
    for n in body:
        tag, val, init = n["kind"], n.get("expr", ""), n.get("init", "")
        if tag == "if":
            if init == "f := deadline(meta)" and val == "f != nil":
                require(
                    n["body"] == [stmt("return f")] and not n.get("else"),
                    "wrong Go deadline branch",
                )
                ops.extend(clock_gates())
            else:
                guard = (init + "; " if init else "") + val
                require(guard in guards, "unknown Go guard: " + guard)
                ops.append(
                    (
                        "branch",
                        guards[guard],
                        go_ops(n["body"], guards, context),
                        go_ops(n.get("else", []), guards, context),
                    )
                )
        elif tag == "range":
            require(
                context == "Read"
                and init == "_,k"
                and val == '[]string{"traceId", "parentCallId", "idempotencyKey"}'
                and len(n["body"]) == 1,
                "unknown Go metadata loop",
            )
            inner = n["body"][0]
            require(
                inner["kind"] == "if"
                and inner.get("init") == "v, ok := meta[k]"
                and inner["expr"] == "ok && !nonempty(v)"
                and not inner.get("else"),
                "invalid metadata contract",
            )
            ops.append(("branch", "!f.correlations", go_ops(inner["body"], guards, context), []))
        elif tag == "stmt":
            if val in aliases[context]:
                continue
            if val in ("s.ready = false", "s.ready = true"):
                ops.append(("state", val.split()[-1]))
            elif (
                val
                == 'return object{"result": object{"protocol": "0.1", "packageId": "org.example.status-go", "packageVersion": "0.1.0", "manifestDigest": executorPin, "features": []string{}, "maxFrameBytes": frameLimit}}'
            ):
                ops.append(("return", "described"))
            elif (
                val
                == 'return object{"result": object{"data": object{"resourceId": id, "state": "ready"}}}'
            ):
                ops.append(("return", "delivered"))
            else:
                ops.append(("return", go_fault(val)))
        else:
            raise ValueError("unknown Go dispatch construct " + tag)
    return ops


def go_frame(functions):
    setup, loop = functions["serve"][:-1], functions["serve"][-1]
    require(
        setup[0] == stmt("raw, err := os.ReadFile(manifest)")
        and setup[1] == {"kind": "if", "expr": "err != nil", "body": [stmt("return err")]}
        and setup[2]
        == {
            "kind": "if",
            "expr": 'fmt.Sprintf("%x", sha256.Sum256(raw)) != executorPin',
            "body": [stmt('return errors.New("unreviewed executor descriptor")')],
        },
        "Go startup descriptor admission changed",
    )
    require(
        setup[3:]
        == [
            stmt("reader := bufio.NewReaderSize(input, frameLimit+1)"),
            stmt("encoder := json.NewEncoder(output)"),
            stmt("s := session{}"),
        ],
        "unknown Go buffering, initialization or output stream",
    )
    require(
        loop["kind"] == "for" and not loop.get("expr") and not loop.get("init"),
        "unexpected stdio loop bound",
    )
    read, eof, failed, output = loop["body"]
    require(
        read == stmt(r"line, err := reader.ReadSlice('\n')"), "Go reader no longer splits at LF"
    )
    require(
        eof
        == {
            "kind": "if",
            "expr": "errors.Is(err, io.EOF) && len(line) == 0",
            "body": [stmt("return nil")],
        }
        and failed == {"kind": "if", "expr": "err != nil", "body": [stmt("return err")]},
        "Go partial-frame or EOF classification changed",
    )
    require(
        output
        == {
            "kind": "if",
            "expr": "reply != nil",
            "init": "reply := s.respond(line[:len(line)-1])",
            "body": [
                {
                    "kind": "if",
                    "expr": "err != nil",
                    "init": "err := encoder.Encode(reply)",
                    "body": [stmt("return err")],
                }
            ],
        },
        "Go response framing changed",
    )
    driver = functions["main"]
    require(
        sum("serve(*manifest, os.Stdin, os.Stdout)" in json.dumps(n) for n in driver) == 1,
        "Go serve flag no longer binds stdin/stdout",
    )
    limits = [n["expr"] for n in functions["#main.go"] if "const frameLimit =" in n["expr"]]
    require(len(limits) == 1, "unknown Go framing limit")
    return int(limits[0].split("=")[1].strip())


def lift_go(functions, guards, trust):
    require(
        all(json_hash(functions[k]) == value for k, value in trust.items()),
        "Go decoder, clock, envelope or validator primitive changed",
    )
    declarations, select = functions["dispatch"]
    require(
        declarations == stmt('meta, _ := p["meta"].(object)')
        and select["kind"] == "switch"
        and select.get("expr") == "method"
        and not select.get("init"),
        "Go method selector changed",
    )
    cases = {row.get("expr", ""): row["body"] for row in select["body"]}
    require(set(cases) == {'"ocs.describe"', '"tool.call"', ""}, "unexpected exported Go method")
    outputs = {
        name: translate_sequence(go_ops(cases[method], guards, name))
        for name, method in [("Describe", '"ocs.describe"'), ("Read", '"tool.call"'), ("Other", "")]
    }
    outputs["frameLimit"] = go_frame(functions)
    return outputs


def python_host_guard(tree, context_hash):
    status = fn(tree, "status")
    calls = [
        s
        for s in ast.walk(status)
        if isinstance(s, ast.Call) and ast.unparse(s.func) == "channel.request"
    ]
    require(
        len(calls) == 2
        and [ast.literal_eval(c.args[0]) for c in calls] == ["ocs.describe", "tool.call"],
        "unexpected host invocation path",
    )
    block = next(
        n
        for n in status.body
        if isinstance(n, ast.Try)
        and any(isinstance(x, ast.Assign) and ast.unparse(x.targets[0]) == "desc" for x in n.body)
    )
    start = next(
        i for i, n in enumerate(block.body) if isinstance(n, ast.Assign) and n.value is calls[0]
    )
    end = next(
        i for i, n in enumerate(block.body) if isinstance(n, ast.Assign) and n.value is calls[1]
    )
    middle = block.body[start + 1 : end]
    require(
        len(middle) == 3 and isinstance(middle[0], ast.Try) and isinstance(middle[1], ast.If),
        "binding does not dominate call in the Python caller",
    )
    require(
        ast.unparse(middle[0].body[0]) == "validate('wire', desc, 'describeResult')"
        and all(isinstance(h.body[0], ast.Raise) for h in middle[0].handlers),
        "Python caller accepts a schema-invalid bootstrap reply",
    )
    guard = middle[1]
    require(
        len(guard.body) == 1
        and isinstance(guard.body[0], ast.Raise)
        and not guard.orelse
        and ast.unparse(middle[2]) == "channel.limit = min(LIMIT, desc['maxFrameBytes'])",
        "identity mismatch did not return refusal before dispatch",
    )
    pred = guard.test
    guard.test = ast.Constant("<binding-test>")
    require(
        digest(ast_repr(status).encode()) == context_hash,
        "unreviewed Python host context around identity guard",
    )
    require(
        isinstance(pred, ast.Compare) and len(pred.ops) == 1 and isinstance(pred.ops[0], ast.NotEq),
        "unsupported host identity relation",
    )
    left, right = pred.left, pred.comparators[0]
    require(
        isinstance(left, ast.Tuple)
        and isinstance(right, ast.Tuple)
        and len(left.elts) == len(right.elts),
        "unpaired host identity",
    )
    pairs = {
        ("desc['packageId']", "descriptor['id']"): "id",
        ("desc['packageVersion']", "descriptor['version']"): "revision",
        ("desc['manifestDigest']", "pin"): "digest",
    }
    names = [
        pairs[ast.unparse(lhs), ast.unparse(rhs)]
        for lhs, rhs in zip(left.elts, right.elts, strict=True)
    ]
    return " && ".join([*names, "others"])


def go_host_guard(functions, context_hash):
    body = copy.deepcopy(functions["status"])
    invocations = [
        (i, n)
        for i, n in enumerate(body)
        if n["kind"] == "stmt" and ":= invoke(send," in n.get("expr", "")
    ]
    require(
        len(invocations) == 2
        and 'invoke(send, "1", "ocs.describe"' in invocations[0][1]["expr"]
        and 'invoke(send, "2", "tool.call"' in invocations[1][1]["expr"]
        and sum("invoke(send," in json.dumps(n) for n in body) == 2,
        "unexpected Go host call path",
    )
    a, b = invocations[0][0], invocations[1][0]
    window = body[a + 1 : b]
    require(
        len(window) >= 2
        and window[0] == {"kind": "if", "expr": "e != nil", "body": [stmt("return nil, e")]},
        "Go host did not return on refused bootstrap",
    )
    guard = window[1]
    require(
        guard["kind"] == "if"
        and not guard.get("else")
        and len(guard["body"]) == 1
        and guard["body"][0]["expr"].startswith("return nil, errors.New("),
        "missing prior host identity guard",
    )
    factors = {
        "len(desc) != 6": "others",
        'desc["protocol"] != "0.1"': "others",
        'desc["packageId"] != "org.example.status"': "id",
        'desc["packageVersion"] != "0.1.0"': "revision",
        'desc["manifestDigest"] != statusPin': "digest",
    }
    names = [factors[x] for x in guard["expr"].split(" || ")]
    guard["expr"] = "<binding-test>"
    require(json_hash(body) == context_hash, "unreviewed Go host context around identity guard")
    return " && ".join(dict.fromkeys([*names, "others"]))


def extract(subject, go_functions):
    registry = json.loads((HERE / "guards.json").read_text())
    primitives = json.loads((HERE / "primitives.json").read_text())
    tree = ast.parse((subject / "examples/status/executor.py").read_bytes())
    py = lift_python(tree, registry["python"], primitives["python"])
    go = lift_go(go_functions, registry["go"], primitives["go"])
    require(
        "init" not in go_functions
        and json_hash(go_functions["main"]) == primitives["outer"]["goMain"],
        "unreviewed Go executor entry point",
    )
    py_host = python_host_guard(
        ast.parse((subject / "reference/host.py").read_bytes()), primitives["outer"]["pythonHost"]
    )
    go_host = go_host_guard(go_functions, primitives["outer"]["goHost"])
    lines = ["import Contract", "", "namespace OCSWire.Extracted", ""]
    for lang, items in [("python", py), ("go", go)]:
        for method in ("Describe", "Read", "Other"):
            expr = items[method]
            state = "s" if re.search(r"\bs\b", expr) else "_s"
            facts = "f" if re.search(r"\bf\.", expr) else "_f"
            lines += [
                f"def {lang}{method} ({state} : Bool) ({facts} : Facts) : Response :=",
                "  " + expr,
                "",
            ]
        limit = items["frameLimit"]
        lines += [
            f"def {lang}Frame : FrameEvent → IOAction",
            "  | .eof => .stop",
            "  | .unfinished => .reject",
            f"  | .message n notify => if n > {limit} then .reject else if notify then .silent else .writeLF",
            "",
        ]
    for lang, predicate in (("python", py_host), ("go", go_host)):
        lines += [
            f"def {lang}HostSends (id revision digest others : Bool) : Bool :=",
            "  " + predicate,
            "",
        ]
    return "\n".join(lines + ["end OCSWire.Extracted", ""])
