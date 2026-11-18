# Core wire protocol and bindings

Wire version `0.1` uses the request/response form of [JSON-RPC 2.0](https://www.jsonrpc.org/specification). See [wire schema](../schemas/wire.schema.json). One small call requires negotiation and invocation. Package discovery and transport authentication precede both. For a remote service, provision its manifest or verified package separately under the owner’s discovery policy. A network caller can resolve its operations from that descriptor before opening a connection.

## Frames

- **W-01 Encoding.** Encode each message as UTF-8 JSON. Reject a byte-order mark, duplicate keys, non-finite numbers, unpaired surrogates and batches. A message is one object. Integers carried as JSON numbers MUST be in the interoperable range −(2^53−1) to 2^53−1. Use decimal strings, byte strings described by a profile, or scoped artifact handles for values needing greater precision. A string ID is opaque and unique among a caller's outstanding requests. Do not infer authority from it.
- **W-02 Correlation.** Requests contain exactly `jsonrpc:"2.0"`, `id`, `method`, `params`. Responses echo `id` and carry exactly one of `result` or `error`. A malformed request with no trustworthy ID uses `id:null` in the error. Notifications omit `id` and receive no response. Only notifications in negotiated profiles are actionable. Core supports sequential calls. Concurrent implementations MUST correlate independently of arrival order.
- **W-03 Limits.** Default maximum frame size is 1,048,576 UTF-8 bytes excluding the stdio newline. Peers MUST enforce the smaller applicable advertised/local limit. Oversized or invalid transport frames may close the connection rather than allocating an unbounded buffer. Bound concurrency and output. Logs use stderr or a separate channel.
- **W-04 Deadlines.** Every request includes `params.meta.deadline`, an absolute UTC timestamp of the form `YYYY-MM-DDTHH:mm:ss.sssZ`. Apply the shorter of the caller deadline and local budget. Check before dispatch. Propagate remaining budget to children. Use a monotonic clock for elapsed local time. If a read returns too late, report a deadline error. If a write might have happened, preserve its operation ID and report an unknown or known effect separately. A timeout is never evidence of rollback.

## Bootstrap and call

**W-05 Negotiate.** First issue `ocs.describe` with `protocols` (ordered, nonempty), `requiredFeatures` and `meta.deadline`. Select the first mutually supported protocol. Reject unsupported required features. The executor returns `protocol`, `packageId`, `packageVersion`, `manifestDigest`, `features` and `maxFrameBytes`. Before calling, the host compares these with its admitted descriptor and checks the effective frame bound. Disagreement is a pin or compatibility error, not an automatic reinstall. Optional features are identified by the profile IDs in [the index](profiles/index.json). Stable RPC methods are protocol, not programming-language symbols.

**W-06 Invoke.** `tool.call` takes `operation`, `version`, `input` and `meta` containing `protocol`, `manifestDigest` and `deadline`. Optional `traceId`, `parentCallId`, `idempotencyKey` are correlation or effect metadata. A caller cannot establish a principal, account grant or region by adding a JSON field. Validate descriptor, grant, effect and input before executing. A successful synchronous call returns `{"data":...}` conforming to the declared output. An existing platform-specific API may be reached through an admitted adapter. Any conversion loss requires explicit negotiation.

This example uses an illustrative digest and deadline.

```json
{"jsonrpc":"2.0","id":"q1","method":"tool.call","params":{"operation":"example.status.read","version":"1.0.0","input":{"resourceId":"demo"},"meta":{"protocol":"0.1","manifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","deadline":"2030-01-01T00:00:00.000Z"}}}
```

**W-07 Errors.** Return a machine-readable integer `code`, a readable `message` and `data.kind`. Optional fields are `path`, `retryable`, `retryAfterMs` and `operationId`. For a field in input/output, `path` is relative to that payload. Paths for envelope/bootstrap errors are relative to the corresponding envelope/parameters. Messages may be localized. Codes and meanings are stable within this edition.

| Code | Kind | Meaning |
|---:|---|---|
| −32700 | parse | Invalid JSON/encoding or ambiguous duplicate keys. |
| −32600 | request | Invalid envelope. |
| −32601 | method | Unknown method or operation under the negotiated interface. |
| −32602 | params | Invalid RPC parameters. |
| −32603 | internal | Unexpected local error. |
| −33001 | denied | Caller, target or effect is not authorized. |
| −33004 | cancelled | Cancellation acknowledged. Write outcome is tracked independently. |
| −33005 | deadline | Deadline elapsed. |
| −33008 | incompatible | No compatible version or missing mandatory feature. |
| −33009 | input | Operation input failed its contract. |
| −33014 | pin | Selected descriptor/revision changed. |
| −32001 | output | Executor returned an invalid or mismatched response. |
| −32002 | conflict | Same effect key, different intent, or unmet precondition. |
| −32003 | busy | Budget or capacity exhausted. A retry may be possible. |
| −32004 | unavailable | Transport or selected executor unavailable. |
| −32005 | unknown_effect | The outcome of an external state change is unknown. |

**W-08 Transport.** Over stdio, send one compact JSON value followed by LF, flush after each frame, reserve stdout for protocol, and close stdin to end the session. An executor MUST require a successful bootstrap before calls on that session. Over HTTP, use POST to the configured endpoint with `application/json`. Return a JSON-RPC result/error for a valid authenticated exchange. Each invocation is independently authenticated and pinned. A describe response may be cached per endpoint, issuer, revision and scope. Reject new or redirected destinations outside the binding. HTTPS with authenticated peers is required across trust boundaries. Plain HTTP is allowable only under explicit isolated loopback development policy. Transport admission failures may return 401/403, capacity failure 429, and transient failure 503 with bounded retry hints. They cannot be interpreted as a successful operation result.

Compatible streams, durable tasks and events have additional rules in [interaction](profiles/interaction.md). The transport is a choice at a particular edge. The application semantics, authority and consequences travel with the operation.
