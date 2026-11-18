"""Total decisions used by the local profile endpoint. Integer inputs are validated naturals."""


def admit(
    inspected: bool,
    admitted: bool,
    bound: bool,
    active: bool,
    owner_ok: bool,
    current: int,
    seen: int,
) -> bool:
    return inspected and admitted and bound and active and owner_ok and current == seen


def grant(parent: bool, exported: bool, imported: bool, scoped: bool) -> bool:
    return parent and exported and imported and scoped


def reserve(available: int, share: int) -> int:
    return max(available - share, 0) if share <= available else available


def ack_position(old: int, requested: int, high: int) -> int:
    return requested if old <= requested and requested <= high else old


def can_continue(waiting: bool, owner_ok: bool, revision: int, expected: int) -> bool:
    return waiting and owner_ok and revision == expected


def page_size(size: int, offset: int, budget: int) -> int:
    return min(max(size - offset, 0), budget)


def stream_step(
    action: int,
    owner_ok: bool,
    credit: int,
    sent: int,
    granted: int,
    remaining: int,
    finals: int,
    amount: int,
    capacity: int,
) -> tuple[int, int, int, int, int]:
    if owner_ok and finals == 0:
        if action == 0 and amount > 0 and credit + amount <= capacity:
            return (credit + amount, sent, granted + amount, remaining, finals)
        if action == 1 and credit > 0 and remaining > 0:
            return (max(credit - 1, 0), sent + 1, granted, max(remaining - 1, 0), finals)
        if action == 2:
            return (credit, sent, granted, remaining, 1)
    return (credit, sent, granted, remaining, finals)


def surface_eligible(
    valid: bool, version_ok: bool, declared: bool, action: bool, granted: bool
) -> bool:
    return valid and version_ok and declared and action and granted


def callback_safe(serial: bool, same_channel: bool, has_import: bool) -> bool:
    return has_import and not (serial and same_channel)
