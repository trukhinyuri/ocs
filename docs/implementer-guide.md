# Build a host or extension

## A small host

1. Read one manifest as data. Verify the source under the deployment policy. Resolve the required imports and pick the exact version and resource grant.
2. Activate the component on its first authorized call. Exchange `ocs.describe`. Compare the reported identity and the digest of the exact manifest bytes with the admitted values.
3. Validate the operation input and dispatch with a deadline. Match the response ID and validate the output. Return a typed result or error to the caller.
4. Drain and close the instance. A new generation gets new ephemeral handles. Persist durable jobs and uncertain effects with their state owner.

A trusted local program can make the binding in code. A public registry, shared database and network orchestrator are optional. The two [reference hosts](../reference/) demonstrate the same scoped operation in different languages.

## A first plugin

Copy the [read example](../examples/status/) into a clean development directory. Give it your own identity and export contract. Implement the two core methods in your preferred language. Reserve stdout for protocol. Test the successful input, denied resource, wrong contract version, lost transport and an invalid result. Isolate the development instance from production accounts.

Use `uv run --locked python tools/package.py DIRECTORY OUTPUT.ocsx` to build it and `uv run --locked python tools/package.py --verify OUTPUT.ocsx` to inspect it. The archive contains an exact checksum inventory and the manifest. Set deployment-specific limits and publisher trust in the receiving host. Integrity and authority are distinct decisions.

These commands run the published status corpus against the second executor.

```sh
go build -o out/ocs-go ./reference/go
uv run --locked python conformance/run.py --manifest reference/go/ocs.json \
  --report out/go-executor.json --target out/ocs-go --serve --manifest reference/go/ocs.json
```

Run `mkdir -p out` first in a fresh checkout. For a different business contract, copy the [case format](../conformance/cases/core.json) and replace the example operation, grants and expected results with your own. The runner supports request IDs, raw invalid frames, exact scalar expectations and partial object matching. Explicit command arguments select the target.

## Choose the boundary

| User needs | Smallest applicable interface | Failure worth testing |
|---|---|---|
| Read a known fact | One synchronous read | Unknown resource or stale revision |
| Bring a second service into an application | One directional grant between two owners | Recipient revoked while the local service remains available |
| Add a GUI or TUI | One owned surface and one admitted action | Retired panel event, missing renderer or keyboard-only operation |
| Show subscriptions and limits | Provider descriptor and per-account observations | Shared quota, unknown balance, partial catalog or alternate route |
| Consume a reset credit | Prepare, exact approval, commit, readback | Concurrent duplicates or a lost acknowledgement |
| Have two agents share a fact | One typed request and correlated reply | Duplicate delivery, missing modality, exhausted turn budget |
| Expose a cloud service | A tenant-scoped operation and authoritative observation | Accepted provisioning followed by degraded or unknown resource state |
| Use a kernel or hardware path | A platform descriptor and qualified native adapter | Wrong ABI, revoked handles or missing worst-case qualification |

Compare a package’s public inputs and guarantees with its [selected profile](../spec/profiles/README.md). One maintainer can replace the implementation and replay the cases without rebuilding unrelated components. Use the [migration guide](compatibility.md) when moving an existing application.
