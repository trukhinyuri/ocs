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

## Formal and operational qualification

The [qualification guide](../assurance/README.md) links the independent wire, profile, source and build witnesses to the atomic catalogue. The [stand](../stand/kubernetes/README.md) exercises a live Kubernetes service, real relay, synthetic accounts, actual local model and browser, bounded load, cancellation, persistent recovery and site attestation. Its results refer to that particular target and time. The table above describes the original published corpus that remains independently replayable.

## Find a requirement and its evidence

In the [scenario index](scenarios.json), look up the rule ID under its specification file and follow the listed scenario IDs. Each scenario names its scope, expected behavior and checks. A bare check ID refers to the wire corpus or the integration report. A `path#test_name` points to a fixture assertion. The `qualification` field records outstanding evidence. An empty check list means the behavior is specified and awaits a qualifying implementation.

## Replay the accepted edition

`make check` runs the existing suite, then reads the full `OCS_BASELINE` commit from local Git history. The default is the first working draft on commit `6f6e22842347806f2963ef1984d9ea592fdddaf0`. A checkout used for this command must contain that commit. Release automation can pass its independently selected full SHA with `make check OCS_BASELINE=<full-commit-id>`. A missing commit fails the check. The verifier reads Git objects locally.

The verifier unpacks the published runner, corpus, wire schemas and fixtures in a temporary directory. The published caller exercises the candidate Python and Go executors. The candidate hosts and receiving peer also call the published status package over the admitted stdio and loopback paths. The full historical host suite includes a control run of the original Python package. A separate executor report addresses the actual Python implementation in the working tree. The published effect, dialogue, archive, record and Go fixture assertions also run. Inspect the two JSON reports under `out/baseline/<full-commit-id>/` for the individual results.

Each working-edition rule needs a scenario. Each reported scenario needs an index entry and evidence for the rule it cites. While the baseline is supported, keep its rule and public case IDs. A case can gain steps or stronger assertions. Removing a published exchange or relaxing its expected result under the same ID fails the check. A private fixture can move with an updated evidence link. The verifier names changed locators and still runs the published fixtures. Record a decision and a migration for a changed meaning. Review a baseline change separately from the implementation it qualifies. For overlapping supported editions, run the same command once per accepted SHA.

To check the verifier itself, use a disposable checkout. Make the Python status executor forget the negotiated session on invalid resource input. Remove `recover-after-input-error` from the working corpus and its evidence link from the index. Run `make check`. The published Python-executor report must still name that case as a failure. Restoring the implementation and the scenario must restore the passing result.
