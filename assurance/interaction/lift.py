"""Translate the total Boolean/natural decisions called by the Python fixture into Lean."""

import ast

SIGNATURES = {
    "surface_eligible": (("Bool",) * 5, "Bool"),
    "callback_safe": (("Bool",) * 3, "Bool"),
    "admit": (("Bool",) * 5 + ("Nat",) * 2, "Bool"),
    "grant": (("Bool",) * 4, "Bool"),
    "reserve": (("Nat",) * 2, "Nat"),
    "ack_position": (("Nat",) * 3, "Nat"),
    "can_continue": (("Bool",) * 2 + ("Nat",) * 2, "Bool"),
    "page_size": (("Nat",) * 3, "Nat"),
    "stream_step": (("Nat", "Bool") + ("Nat",) * 7, "Nat × Nat × Nat × Nat × Nat"),
}


def name(identifier):
    return "p_" + identifier


def expression(node, variables):
    if isinstance(node, ast.Name) and node.id in variables:
        return name(node.id)
    if isinstance(node, ast.Constant):
        if type(node.value) is bool:
            return "true" if node.value else "false"
        if type(node.value) is int and node.value >= 0:
            return str(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return "(!" + expression(node.operand, variables) + ")"
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        operator = " && " if isinstance(node.op, ast.And) else " || "
        return "(" + operator.join(expression(x, variables) for x in node.values) + ")"
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = expression(node.left, variables), expression(node.comparators[0], variables)
        op = type(node.ops[0])
        if op is ast.Eq:
            return f"({left} == {right})"
        sign = {ast.Lt: "<", ast.Gt: ">", ast.LtE: "≤", ast.GtE: "≥"}.get(op)
        if sign:
            return f"(decide ({left} {sign} {right}))"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return f"({expression(node.left, variables)} + {expression(node.right, variables)})"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and len(node.args) == 2
        and not node.keywords
    ):
        a, b = node.args
        if node.func.id == "min":
            return f"(min {expression(a, variables)} {expression(b, variables)})"
        if (
            node.func.id == "max"
            and isinstance(a, ast.BinOp)
            and isinstance(a.op, ast.Sub)
            and isinstance(b, ast.Constant)
            and type(b.value) is int
            and b.value == 0
        ):
            return f"({expression(a.left, variables)} - {expression(a.right, variables)})"
    if isinstance(node, ast.IfExp):
        return f"(if {expression(node.test, variables)} then {expression(node.body, variables)} else {expression(node.orelse, variables)})"
    if isinstance(node, ast.Tuple) and len(node.elts) == 5:
        return "(" + ", ".join(expression(x, variables) for x in node.elts) + ")"
    raise ValueError(f"unsupported Python decision expression at line {node.lineno}")


def block(stmts, variables):
    if not stmts:
        raise ValueError("missing total return")
    head, *tail = stmts
    if isinstance(head, ast.Return) and not tail:
        return expression(head.value, variables)
    if isinstance(head, ast.If):
        return f"(if {expression(head.test, variables)} then {block(head.body + tail, variables)} else {block(head.orelse + tail, variables)})"
    if isinstance(head, ast.Return):
        # An unconditional return is the terminal of this branch.
        return expression(head.value, variables)
    raise ValueError(f"unsupported statement at line {head.lineno}")


def translate(path, signatures=SIGNATURES):
    module = ast.parse(path.read_text())
    if not all(
        isinstance(n, ast.FunctionDef)
        or (
            isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str)
        )
        for n in module.body
    ):
        raise ValueError("the kernel must have only definitions and its docstring")
    fs = [x for x in module.body if isinstance(x, ast.FunctionDef)]
    if {f.name for f in fs} != set(signatures) or len(fs) != len(signatures):
        raise ValueError("unsupported or missing decision routine")
    lines = ["import Std", "set_option autoImplicit false", "namespace Concrete"]
    for f in fs:
        argtypes, ret = signatures[f.name]
        args = f.args
        if (
            f.decorator_list
            or args.vararg
            or args.kwarg
            or args.kwonlyargs
            or args.defaults
            or args.posonlyargs
            or len(args.args) != len(argtypes)
        ):
            raise ValueError("unexpected decision signature")
        variables = [a.arg for a in args.args]
        if {"max", "min"} & set(variables):
            raise ValueError("shadowed primitive")
        params = " ".join(f"({name(k)} : {t})" for k, t in zip(variables, argtypes, strict=True))
        lines.append(f"def {f.name} {params} : {ret} := {block(f.body, variables)}")
    lines.append("end Concrete")
    return "\n".join(lines) + "\n"
