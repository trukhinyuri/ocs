"""Decisions used before a resource write, native operation or work reservation."""


def admit_native(
    target_ok: bool, abi_ok: bool, owner_ok: bool, isolation_ok: bool, hard: bool
) -> bool:
    return target_ok and abi_ok and owner_ok and isolation_ok and not hard


def may_write(
    owner_match: bool, writer_match: bool, current_epoch: int, admitted_epoch: int
) -> bool:
    return owner_match and writer_match and current_epoch == admitted_epoch


def enter_cell(active: int, tenant_active: int, maximum: int, tenant_maximum: int) -> bool:
    return active < maximum and tenant_active < tenant_maximum
