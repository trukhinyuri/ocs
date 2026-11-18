"""Pure decisions at the SQLite transaction boundary. Inputs are host-resolved booleans."""


def commit_decision(
    same_digest, applied, remote_reserved, authorized, approved, unexpired, same_pin, current
):
    if not same_digest:
        return "conflict"
    if applied:
        return "replay"
    if remote_reserved:
        return "reserved"
    if not authorized or not approved:
        return "denied"
    if not unexpired:
        return "deadline"
    if not same_pin:
        return "pin"
    if not current:
        return "conflict"
    return "apply"


def proposal_decision(exists, exact_intent):
    if not exists:
        return "create"
    if exact_intent:
        return "replay"
    return "conflict"
