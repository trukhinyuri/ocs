"""Total policy fragments used in the public provider operations and their refinement proof."""


def grant_generation(active, authenticated, entitled, supported, same_route, options_supported):
    return active and authenticated and entitled and supported and same_route and options_supported


def publish_complete(same_scope, complete, no_next_page):
    return same_scope and complete and no_next_page


def accept_amount(compatible, independent, known, seen):
    return compatible and independent and known and not seen


def meter_decision(exists, exact_event):
    if not exists:
        return "append"
    if exact_event:
        return "replay"
    return "conflict"


def permit_invocation(external, monetary, destructive, irreversible):
    return not (external or monetary or destructive or irreversible)


def authorize_handle(same_owner, same_issuer, same_origin, same_flow, unexpired, unused):
    return same_owner and same_issuer and same_origin and same_flow and unexpired and unused
