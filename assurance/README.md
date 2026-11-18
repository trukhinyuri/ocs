# Assurance for the draft-1 reference

The [scope](scope.json), [atomic catalogue](obligations.json), [scenario index](../conformance/scenarios.json) and [Kubernetes policy](../stand/kubernetes/policy.json) identify the population and acceptance conditions. Numbered rules have separately identified clauses. The structural inventory also records unnumbered normative paragraphs, public registry entries and schema assertions by source location. Its result establishes the identity of those declarations. Behavioral results require evidence at each prescribed level.

## Reproduce qualification

From a clean Git checkout containing both pinned editions, install the project's locked Python packages with `uv sync --locked`. Install the pinned Lean release with `elan toolchain install leanprover/lean4:v4.36.0-rc2` on the verifier. The qualified local platform uses Linux/arm64, Go, Python, Git, OpenSSL, the repository's Lean toolchain manifest, a Chromium browser and a matching WebDriver. The ordinary OCS call path runs without a proof assistant.

- `make demo` exercises the minimal standalone application.
- `make check` runs the existing conformance suites, the preserved first-edition cases and the hermetic proof and reference qualification. Its report explicitly separates stand obligations.
- `make qualify` runs the full acceptance including the independently bound Kubernetes workload, signed observations and adversarial acceptance controls. [Stand setup](../stand/kubernetes/README.md)

The release caller selects the full accepted commit. For a separate release pipeline, take the launcher and its pin from trusted release configuration. Extract the launcher with `git show "$OCS_ASSURANCE_BASELINE:assurance/launch.py"` into private temporary storage and run it with `--accepted "$OCS_ASSURANCE_BASELINE" --subject /path/to/checkout`. Its Git archive disables replace objects and holds the published properties, semantic definitions and checking scripts independently of the submitted tree. Preserve the original conformance baseline as a separate pin. The initial protocol edition predates the new formal evidence.

## Interpret the dossier

Each report binds the atomic property, target scope, checker commit, subject digest, method, verifier output and evidence location. The kernel checks typed statements and transitive axiom dependencies. Executable decision fragments are translated from inspected Python and Go syntax under documented semantics. The accepted shape/wire oracle exercises ordinary entry points including negative cases. A build observation identifies the binary and records the behavior actually seen. Conditional source theorems and measured executable behavior remain distinguishable throughout the dossier.

Trusted components include the accepted mathematical definitions and translator subset, the Lean kernel and permitted logical axioms, the independently replayed proof checker where named, the language runtime, the platform's clock and process semantics, SQLite's documented atomic transaction boundary, and the operator-selected cluster and identity. The supplied kernels prove selected invariants for unbounded finite traces or inputs within their specified premises. Source refinements cover the actual decision functions and reviewed calling paths described in each slice. General interpreter correctness, compiler correctness, hardware worst-case latency, public inference services and arbitrary cloud scale are separate claims.

The running-cluster dossier contains a verified TLS origin, workload and pod identities, actual data and image checks, authenticated observations, declared thresholds and validity times. Its operator signature binds the exact report and subject, with the trusted public key enrolled outside the checkout. The full check reacquires stand evidence. It reports failures for stale or future data, an unrecognized origin, a different build, missing obligations or an invalid signature.

The machine report lists accounting and execution separately. Results are grouped by evidence level and profile. Scenario totals are overlapping views of slots in linked normative rules. Use a row's property, subjects and underlying receipt for its precise scope. An inapplicable reverse execution is identified explicitly when an earlier edition published a contract without that executable. A changed target, assumption, protected statement, checker or expiry reopens affected obligations. Additional code and equivalent proofs flow through the original statements. A changed meaning, newly mandatory feature or stronger premise uses a separately reviewed version or refinement witness.

## Primary sources and toolchain boundary

The [tool inventory](tooling.json) records the selected versions, licenses, primary sources and trusted boundaries. Additional formats, including the [C/Wasm import](external/README.md), use an operator-enrolled checker independent of the candidate.

Lean elaborates proof terms, checks them in its kernel and supports separate kernel rechecking. The trusted logical basis and machine assumptions are documented in the pinned toolchain manifests. Lean 4 is Apache-2.0. [Lean proof validation](https://lean-lang.org/doc/reference/latest/ValidatingProofs/), [Lean axioms](https://lean-lang.org/doc/reference/latest/Axioms/), [toolchain license](https://github.com/leanprover/lean4/blob/b35cb10cf2ced51a2fd1880cfdbf75c71ab7a35a/LICENSE)

The frozen wire and core checker export proof declarations for a second kernel and validate the declared build. The included Python and Go interop fixtures run real processes. SQLite supplies the data-owner transaction boundaries. JSON Schema validates the exact edition vocabulary and is used as a trusted boundary for the stated data scopes. [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html), [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core)

The user selects a compatible checker for another implementation language by supplying an independently reviewable statement, assumptions, proof object and replay route. Evidence format and qualification happen at development or admission time. No global solver, online registry or extra per-invocation round trip is required.
