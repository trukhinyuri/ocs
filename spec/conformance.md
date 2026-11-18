# Conformance and release evidence

**T-01 Claim.** State edition, role (host, executor, peer or profile adapter), package and contract version, binding, enabled features, platform, test suite revision and observation date. Report each check as pass, fail, skipped or not applicable with a reason. A skipped required case gives no passing claim. An unrelated passing profile cannot compensate for a failure. Report shape is specified by [report.schema.json](../schemas/report.schema.json).

**T-02 Test oracle.** The public wire and numbered requirements determine expected results. Test a released target as a black box using separately maintained data. Include working and forbidden inputs, terminal result or error kind, effect count where applicable, failure after possible execution, and behavior after restart. Record limitations. Comparing two copies of one client is not evidence of independent hosts.

**T-03 Compatibility.** For each claimed feature check old caller/new executor and new caller/old executor. Unknown required features fail before an effect. Unknown optional features can be omitted if the negotiated operation remains correct. Test API change, catalog data change and permission change independently. Report the covered dimension, including process and network bindings.

**T-04 Release.** Publish an immutable edition with its normative documents, schemas, test data and compatible runner. Keep a machine-readable version record, release notes, migration and digest. Pin normative artifacts by release or digest. A release candidate gains stability only for rules with reviewed failure cases and independent implementation evidence. If bytes change, issue a new release. A product release and a protocol edition have separate version histories.

## Run the checks

`make demo` exercises a trusted local reference without network accounts. `make check` runs schema and semantic checks, verifies representative profile records, then the wire/host/peer checks. `make report` writes a black-box JSON report to `out/conformance.json`. Development schema validation uses a maintained Draft 2020-12 validator. The first environment setup needs access to its dependencies or a populated local cache. No remote model keys, cloud accounts or privileged system modules are required.

Use [the coverage matrix](../conformance/COVERAGE.md) when interpreting the result. Developer fixtures are not general claim issuers. An external implementation can run the same executor cases using its stdio command. Reports produced by a target must preserve missing/failed cases. Conformance verifies observed contract behavior, not absolute availability, cryptographic assurance or production capacity.

## Informative references

[JSON-RPC 2.0](https://www.jsonrpc.org/specification), [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/schema), [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901), [Internet timestamps](https://www.rfc-editor.org/rfc/rfc3339), [JSON interoperability](https://www.rfc-editor.org/rfc/rfc7493), [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110), [URI syntax](https://www.rfc-editor.org/rfc/rfc3986), [Trace Context](https://www.w3.org/TR/trace-context/), and [Semantic Versioning](https://semver.org/) provide useful foundations. Only explicitly incorporated provisions are mandatory.
