# Open Composition Standard (OCS)

**A working draft for composing software across language, process and trust boundaries.** A component describes a versioned operation. An application chooses an implementation and authorizes a binding. The same operation can serve an interactive client, another component or a remote host.

**Edition 0.1.0-draft.1** · wire protocol 0.1 · [Apache-2.0](LICENSE).

| I want to… | Start here | First observable result |
|---|---|---|
| Write a plugin | [Quickstart](docs/quickstart.md) | Request the status of a synthetic resource. |
| Build a host in my own language | [Core](spec/core.md), [wire](spec/wire.md) and [test cases](conformance/cases/core.json) | Load a package, negotiate a version, reject a forbidden call and validate a reply. |
| Connect existing software or independent hosts | [Composition](spec/composition.md) | Bind an explicit export while keeping data and authorization under their owners. |
| Maintain provider integrations | [Provider adapter guide](docs/provider-adapter.md) | Map a connection, quota, model and tested capability to one account. |
| Build a specialized integration | [Profiles](spec/profiles/README.md) | Select the guarantees your service actually needs. |
| Change the standard | [Requirement and scenario index](conformance/scenarios.json), [contribution guide](CONTRIBUTING.md) | Find the existing promises and exercise the accepted edition against a change. |

The [edition manifest](version.json) indexes every normative document and schema. The [implementer guide](docs/implementer-guide.md) explains the host, package and test interfaces. The [compatibility guide](docs/compatibility.md) covers adoption and existing protocols. All specification text, schemas, examples, tests and reference code in this repository are licensed under Apache-2.0.

Run the example from the checkout with Python 3 and Go installed.

```sh
make demo
```

The result is a JSON object reporting that resource `demo` is `ready`. The small Go host runs the example Python executor over standard input and output. It uses only their standard libraries. For the full development checks install the prerequisites in [Conformance](spec/conformance.md), then run `make check`.

**Normative reading order**

[core and package model](spec/core.md) → [wire and errors](spec/wire.md) → [bindings and authority](spec/composition.md) → the [selected profiles](spec/profiles/README.md) → [claims and releases](spec/conformance.md). Schemas specify document shape. Numbered requirements specify observable behavior. A reference executable illustrates a contract. Its internal types and implementation choices are private.

The scope includes locally loaded components, separate processes and network services. It also includes components that present their own interfaces or use a platform-specific critical path. Interoperability claims name a role, version, binding and tested features. See [coverage](conformance/COVERAGE.md) for the boundary of the supplied demonstrations.
