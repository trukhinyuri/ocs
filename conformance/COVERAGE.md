# Evidence in this edition

The working draft defines Core and eleven optional feature identifiers. Each implementation makes a scoped claim. Use the [edition index](../version.json) for normative documents and the [operation registry](../spec/profiles/operations.json) for wire shapes. Run `make check` from this checkout. `out/conformance.json` records the live black-box observations including roles, versions, platform, date and limitations.

| Area | Evidence delivered here | Additional evidence for a deployment |
|---|---|---|
| Package inspection, schema resolution and pinning | Offline schema/reference checks, actual pinned manifests and bindings, deterministic archive, altered/ambiguous/path-invalid archives rejected | Verified publisher and deployment-specific confinement |
| Core executor over stdio | Same public corpus against independent Python and Go executors, including success, refused calls, malformed input, negotiation and continued use after error | Contracts or vocabularies beyond the sealed read example |
| Core host and peer | Python and Go hosts call the same Python package. Go → HTTP loopback → receiving Python host → local executor. Credential and write denial, local owner surviving peer shutdown | TLS and identity rotation across machines, production latency, partitions and failover |
| Effect delivery | Synthetic reset with exact approval, precondition, grant and pin checks, concurrent duplicate, client restart, balance and durable receipt | Downstream idempotency, actual quota/reset ability, price, unknown-outcome reconciliation at each provider |
| Providers | Typed fixtures for account, reset eligibility, priced plan, known/zero/unknown quota, model parameters, lifecycle notice, partial pages and attributed usage | Live account, real upstream changes, working inference and access to billing for the named scope |
| Agent exchange | Typed message parts, native operation contract and deterministic dialogue cases | Live model behavior, quality, cost, cross-machine delivery and performance on a defined workload |
| Presentation | Slot, representation, isolated web integrity, action scope, generation and lifecycle rules with synthetic records | Keyboard, assistive technology, localization, rendering, focus and event isolation on each real client |
| Jobs, events, streams and artifacts | State, cursor, artifact, credit, cancellation, continuation and error contracts, schema checks and sample observations | Crash recovery, retention, event ordering, slow consumer, reconnection, effect count and backpressure on the selected binding |
| Cloud and platform | Tenant-scoped resource observation, platform qualification shape and rejection of a hard deadline without evidence | IAM boundaries, data residency, native ABI/lifetime, hardware timing, actual throughput and recovery under load |

The black-box runner reports its own checks. The unit suite separately exercises schemas, documents, archive behavior, deterministic profile cases and authoritative fixture state. A valid record proves that a value can be represented. A deployment claim also needs observations from the actual target and a measured failure case. The edition has working-draft status.
