# Optional profiles

A component needs only the features its users exercise. A profile gives names and semantics to capabilities. It is independent of transport, placement and implementation language. [index.json](index.json) lists the negotiated feature IDs and their normative documents. [Operation contracts](interfaces.md) and the [machine-readable registry](operations.json) give each callable method its inputs, outputs and authority. [Profile records](../../schemas/profile-data.schema.json) define reusable data shapes. [Examples](../../examples/records/) are synthetic, informative observations.

| Feature | Required behavior for the implementing role | Optional by negotiation |
|---|---|---|
| [Stream](interaction.md) | Credit, sequence, cancellation and one terminal response | Replay from retained cursor |
| [Events](interaction.md) | Scoped identity, subscription and delivery semantics | Durable acknowledgement and replay |
| [Artifacts](interaction.md) | Scoped, pinned byte ranges with bounded progress and end of data | Compatible native handles or data paths |
| [Effects](effects-and-jobs.md) | Prepare, establish authority, commit and read back one exact intent | Compensation and mediated external management |
| [Jobs](effects-and-jobs.md) | Scoped durable identifier, state, recovery and status | Cancellation, continuation or compensation |
| [Providers](providers.md) | Describe product, routes, sign-in methods, supported operations and evidence | Accounts, quotas, grants, prices, models and usage |
| [Agents](agents.md) | Bound peer, attributable message and correlated reply | Handoff, jobs, artifacts, streaming and additional modalities |
| [Presentation](presentation.md) | Host-owned placement, event admission and instance lifetime | Declarative, web, native, terminal, assistive or agent interaction |
| [Cloud](platforms.md) | Scoped public contract, state owner and resource observation | Placement, capacity, metering, billing, durability and federation |
| [Platform](platforms.md) | Platform descriptor, admission, lifetime and recovery | Privileged modules, accelerated paths and qualified timing |
| [Peers](../composition.md) | Independently admitted directional bindings, same ownership and grants on each hop | Delegation, regional routing, offline policy or durable reconciliation |

**P-01 Selection.** `features` advertises the profiles actually available. A domain operation is callable only if separately exported and granted. Profile controls require the negotiated feature and the authority specified for that control. Named domain operations such as `limits.read` and `model.generate` use `tool.call` with exact operation version. Profile protocol control methods such as `ocs.chunk` or `effect.commit` have the framing defined in their own profile. All examples of domain operations in this edition use version `1.0.0`. That number describes their own contract, not the OCS edition. Existing external protocols may be mapped by adapters with an explicit coverage report.

**P-02 Claims.** Unsupported and not applicable are different. For example, a non-billable cloud product can declare billing not applicable with a reason. A model account with no quota endpoint declares unavailable evidence. Silence never means infinite quota or permission. [Coverage](../../conformance/COVERAGE.md) distinguishes normative profile definition, schema/example validation and running implementations.
