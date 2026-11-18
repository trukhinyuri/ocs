# Adopting OCS in existing software

Start with a public operation whose owner can confirm a result. Record its arguments, result types, latency objective, permissions, error meanings and observable effects. Give the adapter a package identity, an exact contract revision, synthetic examples and at least one forbidden case. Existing persistence, credentials and execution engines stay with their owners.

| Existing interface | Represent on the OCS boundary | Preserve or expose explicitly |
|---|---|---|
| Local command or function | One declared operation and a process or platform binding | Structured input, encoding, exit/error mapping and side effects |
| Tool discovery service | A reviewed subset of tool schemas and a negotiated session | Required semantics, origin, authority, error, cancellation and opaque results |
| Agent messaging service | Message ID and parts, correlated replies, jobs, artifacts or streams as applicable | Provider of identity, context ownership, modality, task states and replay guarantees |
| Cloud product | Tenant-scoped lifecycle operations, jobs and observations | Desired vs. observed state, costs, capacity, retention, recovery and time bounds |
| Native component or existing GUI | Named platform adapter or scoped surface | ABI, threading and ownership, isolation, accessibility, lifetime and recovery |

Write down each mapping as **preserved**, **conditional** with a testable condition, or **unavailable** with a reason. Keep a native endpoint or existing client available for any essential capability that the mapping cannot express. A new optional profile can add a contract when several independent users share that need.

During cutover, compare read results on the same authorized resource. Keep one owner for writes and retain its idempotency keys, pending approvals and receipts. Verify that rollbacks can read the state written by the new revision. Record old caller/new executor and new caller/old executor outcomes, including denials. A similar package name, manifest field or RPC envelope cannot establish compatibility by itself.

## Preserve extensions during a migration

Inventory both the user-facing contribution and its underlying authority. Commands, keyboard shortcuts, composer actions and context menus can bind one existing operation in several host-owned slots. A status indicator or inspector reads observed state. A file viewer or theme contributes admitted data or a surface. A background observer, importer, scheduler, knowledge source or workflow runs only under its own selected scope. Preserve capabilities such as cancellation, order, scope, revisions, artifact permissions and cleanup. A receiving host can leave an unimplemented optional slot unavailable and explain which client supports it.

For a service descriptor also map plan publication, distribution channels and update authority, tenant entitlement, data export, durability, recovery, meter and billing ownership, operator support and the partition policy. Bind each lifecycle action to its real state owner and a measured result. Existing product-specific capabilities can remain namespaced. The [cloud and platform profile](../spec/profiles/platforms.md) names the evidence needed when claiming those guarantees.

## Design precedents

Portable manifests make contributions discoverable before code runs. Namespaced contributions, lazy activation, instance-owned disposal and an isolated development installation keep a one-operation plugin small. A custom surface uses the application’s existing navigation, localization and trust boundary. An instruction-only package can be tried with one manifest and one text file. [Example workflow](../examples/workflow/ocs.json)

Separate version negotiation and capability discovery from normal calls. An adapter for another tool protocol retains that protocol’s handshake and translates only the documented subset. [Model Context Protocol lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)

Agent protocols distinguish messages from longer-lived tasks and support alternative bindings. Map each supported message part and terminal state explicitly. OCS peers use the native agent export and can operate with a one-shot text exchange. [Agent-to-agent protocol specification](https://a2a-protocol.org/latest/specification/)

Device sign-in has explicit polling, expiry and user interaction. Browser sign-in supports a proof-key exchange. The responsible broker checks the issuer, redirect and audience before accepting a credential. [Device authorization](https://datatracker.ietf.org/doc/html/rfc8628), [Proof key](https://www.rfc-editor.org/rfc/rfc7636), [OAuth security practices](https://www.rfc-editor.org/rfc/rfc9700)

An accessible web contribution supports keyboard operation, recognizable focus and understandable status. A host should also exercise the corresponding terminal, native or assistive path used by its audience. [Web Content Accessibility Guidelines 2.2](https://www.w3.org/TR/WCAG22/)
