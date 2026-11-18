"""Shared declaration challenge, semantic definitions and kernel replay diagnostics."""

import re
import subprocess


def declarations(source, namespace="Interaction"):
    """Read only publisher-owned declaration headers. Lean typechecks the resulting challenge."""
    result = {}
    for m in re.finditer(r"(?m)^theorem (\w+)\s*(.*?)(?:\s*:=\s*)", source, re.DOTALL):
        name, head = m.group(1), m.group(2).strip()
        depth = 0
        for i, char in enumerate(head):
            if char in "({[":
                depth += 1
            if char in ")}]":
                depth -= 1
            if char == ":" and depth == 0:
                break
        binders = re.findall(r"[({]\s*([\w' ]+)\s*:", head[:i])
        args = " ".join(" ".join(v.split()) for v in binders)
        if name in result:
            raise ValueError("duplicate theorem " + name)
        result[name] = (
            "example " + head + " := @" + namespace + "." + name + (" " + args if args else "")
        )
    return result


def definitions(source):
    starts = list(
        re.finditer(
            r"(?m)^(?:private )?(def|structure|inductive|abbrev|theorem|end|namespace|import|set_option)\b(?:\s+(\w+))?",
            source,
        )
    )
    defs = {}
    for i, m in enumerate(starts):
        if m.group(1) in ("def", "structure", "inductive", "abbrev"):
            content = source[
                m.start() : starts[i + 1].start() if i + 1 < len(starts) else len(source)
            ]
            defs[m.group(2)] = " ".join(content.split())
    return defs


def checked_run(args, dir, env):
    result = subprocess.run(args, cwd=dir, env=env, text=True, capture_output=True, timeout=110)
    if result.returncode:
        diagnostics = (result.stderr + result.stdout).strip()
        location = re.search(r"(\w+\.lean):(\d+):\d+: error:", diagnostics)
        obligation = ""
        if location and (dir / location.group(1)).is_file():
            prefix = (dir / location.group(1)).read_text().splitlines()[: int(location.group(2))]
            for line in reversed(prefix):
                mark = re.match(r"(?:theorem |-- obligation )(\w+(?:\.\w+)?)", line)
                if mark:
                    obligation = mark.group(1) + ": "
                    break
        raise ValueError(
            obligation
            + (
                diagnostics[-1200:]
                or f"{args[0]} {args[-1]} exited with status {result.returncode}"
            )
        )
    if re.search(r"\bsorry\b|\bsorryAx\b|warning: declaration uses", result.stdout):
        raise ValueError("unfinished proof in kernel output")
    return result.stdout


def consumed_decisions(path, methods, module):
    """Extract each decision in the guard, assignment or return which consumes it."""
    import ast

    parsed = ast.parse(path.read_text())
    result = {}
    for func, allowed in methods.items():
        owner, sep, leaf = func.rpartition(".")
        if sep:
            classes = [n for n in parsed.body if isinstance(n, ast.ClassDef) and n.name == owner]
            blocks = [
                n
                for cls in classes
                for n in cls.body
                if isinstance(n, ast.FunctionDef) and n.name == leaf
            ]
        else:
            blocks = [
                n for n in ast.walk(parsed) if isinstance(n, ast.FunctionDef) and n.name == func
            ]
        if len(blocks) != 1:
            raise ValueError("unresolved decision consumer " + str(path) + "#" + func)
        signatures = []

        def visit(node, parents=()):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == module
                and node.func.attr in allowed
            ):
                statement = next((p for p in reversed(parents) if isinstance(p, ast.stmt)), None)
                if isinstance(statement, ast.If):
                    # The error or taken branch is part of the admission decision.
                    consequence = [ast.dump(q, include_attributes=False) for q in statement.body]
                    sig = ("if", ast.dump(statement.test), tuple(consequence))
                elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Return)):
                    sig = (type(statement).__name__, ast.dump(statement))
                else:
                    raise ValueError(
                        f"decision result discarded in {path.name}#{func}/{node.func.attr}"
                    )
                signatures.append((node.func.attr, sig))
            for child in ast.iter_child_nodes(node):
                visit(child, (*parents, node))

        visit(blocks[0])
        if not set(allowed) <= {k for k, _ in signatures}:
            raise ValueError(f"decision disappeared from {path.name}#{func}")
        # Source qualification uses the entire reviewed consumer control flow.
        # In particular, an otherwise preserved call may be bypassed by an
        # earlier return or have its result overwritten before state publication.
        body = list(blocks[0].body)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        wrapper = ast.Module(body=body, type_ignores=[])
        result[func] = (
            ast.dump(blocks[0].args, include_attributes=False),
            ast.dump(wrapper, include_attributes=False),
            signatures,
        )

    return result


def verify_consumption(published, subject, methods, module):
    mandated = consumed_decisions(published, methods, module)
    actual = consumed_decisions(subject, methods, module)
    for func, forms in mandated.items():
        if forms != actual[func]:
            raise ValueError(
                f"changed decision consumption or complete wrapper control flow in {subject.name}#{func}"
            )


def protected_lean_unit(published, candidate, unit):
    """Only theorem declarations/proof bodies can extend this sealed model language."""

    def plain(source):
        result = []
        level = 0
        index = 0
        while index < len(source):
            ch = source[index]
            pair = source[index : index + 2]
            if pair == "/-":
                level += 1
                result.append(" ")
                index += 2
                continue
            if level:
                if pair == "-/":
                    level -= 1
                    index += 2
                    continue
                if ch == "\n":
                    result.append("\n")
                index += 1
                continue
            if pair == "--":
                end = source.find("\n", index)
                index = len(source) if end < 0 else end
                continue
            if ch in ('"', chr(96)):
                raise ValueError(unit + ": unreviewed string or syntax quotation")
            result.append(ch)
            index += 1
        if level:
            raise ValueError(unit + ": unterminated source comment")
        return "".join(result)

    def skeleton(source):
        code = plain(source)
        forbidden = r"(?<!\.)\b(axiom|axioms|unsafe|partial|noncomputable|native_decide|sorry|sorryAx|run_cmd|run_tac|elab|elab_rules|macro|macro_rules|syntax|syntax_cat|declare_syntax_cat|notation|infix|infixl|infixr|postfix|prefix|attribute|instance|initialize|builtin_initialize|class|opaque|local|section|universe|variable|export|open|include|omit|extern|implemented_by|trustCompiler|skipKernelTC)\b|@\s*\[|#\s*\w+"
        if m := re.search(forbidden, code):
            raise ValueError(unit + ": unapproved Lean syntax or trust operation " + m.group(0))
        declarations = []
        current = None
        leaders = {
            "def",
            "abbrev",
            "structure",
            "inductive",
            "import",
            "set_option",
            "namespace",
            "end",
            "theorem",
            "private",
        }
        for line in code.splitlines():
            if not line.strip():
                continue
            words = line.strip().split()
            leader = words[0]
            if line[0].isspace():
                if leader in leaders:
                    raise ValueError(
                        unit + ": nested declaration outside the approved semantic context"
                    )
                if current is None:
                    raise ValueError(unit + ": unexpected prelude")
                current[1].extend(words)
                continue
            if leader == "deriving":
                if current is None or current[0] not in ("structure", "inductive"):
                    raise ValueError(unit + ": misplaced derivation")
                current[1].extend(words)
                continue
            if leader not in leaders or (leader == "private" and words[1:2] != ["theorem"]):
                raise ValueError(unit + ": unreviewed Lean command " + leader)
            if leader == "set_option" and words != ["set_option", "autoImplicit", "false"]:
                raise ValueError(unit + ": changed kernel or elaboration option")
            current = [leader, list(words)]
            declarations.append(current)
        return [(kind, body) for kind, body in declarations if kind not in ("theorem", "private")]

    if skeleton(published) != skeleton(candidate):
        originals = definitions(published)
        proposed = definitions(candidate)
        changed = sorted(
            n for n in originals.keys() | proposed.keys() if originals.get(n) != proposed.get(n)
        )
        key = ", ".join(changed) or "imports, namespace or semantic declaration ordering"
        raise ValueError(unit + ": changed frozen semantics: " + key)
