# Using the optional operation registry

The [operation registry](operations.json) supplies a stable method name, feature, channel, input schema, output schema, support condition and authority rule. All schema identifiers resolve from the distribution's [schemas directory](../../schemas/). A profile consumer can generate typed bindings in its own language or use an ordinary JSON client.

- For `channel: export`, call the operation through Core `tool.call`. The schema in the registry describes `params.input` and `result.data`. A consequential export is invoked through the effects controls instead. Product-specific exports may have additional names. Standard names have their standard meaning.
- For `channel: control`, the name is the JSON-RPC method and the schemas describe the full `params` and `result`. A notification has no response, and its `output` entry is null. Unsupported controls must be refused or, for notifications, left without effect.
- `condition: baseline` applies to the selected profile and implementing role. Conditional features are exposed only when actually supported. Advertise supported optional controls in the descriptor extension `org.ocs.controls` as an array of method names. Absence of a conditional control means it cannot be relied upon. The effects controls are required together. All externally visible writes still traverse ordinary effect checks.
- Reject schema-invalid replies before passing them to the next component. A generic client may ignore additive optional metadata. If it cannot safely interpret a requested write, binding or required representation, reject it.
- An auth flow is scoped to its subject, account intent and service origin. A `connectionHandle` is an opaque host-brokered reference. Only non-secret values may be entered in generic `values` or `settings`. Secret fields go directly into the broker. Expired device grants, rejected origins and OAuth callback mismatches fail closed.

## Intent equality

Before preparing an effect, construct the [effect intent](../../schemas/profile-wire.schema.json#/$defs/effectIntent) from trusted policy and validated input. All fields in that definition are required, including an explicit (possibly empty) preconditions object. Compute `intentDigest = hex(SHA-256(JCS(intent)))`. The scoped lookup key contains issuer, subject, scope and idempotency key. Empty display changes or retry trace IDs do not change the intent. Changes to recipient, operation version, package pin, authorized owner, price, grant or other effect-bearing preconditions must change the intent or invalidate the proposal. Refuse approval of incomplete or ambiguous intent.

## Network streams

For the stream profile over HTTP, open with an authenticated POST carrying `stream.open`, opt in via `Accept: text/event-stream`, and authenticate control POSTs to the same pinned endpoint. Each SSE `event: chunk` data field contains one `ocs.chunk` JSON-RPC notification. An SSE `event: response` carries the single final JSON-RPC response to the open request. Use the open request ID as the stream control ID, scoped to the authenticated connection owner and retained active session. Notify via `ocs.credit` or `ocs.cancel`. Accepted notification POSTs produce HTTP 204. Controls after close cannot restart a stream. A disconnect before final response leaves the result unconfirmed. Resumable replay is a separately agreed feature.

## Catalog pages

When a model catalog has multiple pages, callers pass the server-issued opaque `pageToken` and retain the same provider, route, account and observation scope. A page may return `nextPageToken`. Use the same completeness and revision rule for paged account inventories. A host publishes a complete comparable snapshot only when every page arrived, its scope/revision is consistent, and no next token remains. A missing or repeated continuation yields partial data and a diagnostic. It cannot retire a model.
