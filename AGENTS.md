# Working on this repository

Read README.md and look up the numbered rule and its scenarios in conformance/scenarios.json. Include the affected IDs and the result of the pinned-edition replay in a behavior-change review. All authored text is in English and uses vendor-neutral examples. Use synthetic identities, endpoints and data. Never add real credentials or production traces.

Choose one observable behavior. Write or update the black-box case, then change the normative text, schema and reference code as applicable. Run `make check`. A test client may share public schemas but must not import implementation internals to determine the expected outcome. Do not broaden permissions or remove a failing case to make CI pass.

Keep examples independently runnable. Declare the scope of any compatibility claim in the report. Edit optional profiles when the behavior is specific to them. Change core only for common semantics demonstrated by independent consumers or to repair a trust or correctness boundary. Follow GOVERNANCE.md and CONTRIBUTING.md. No publish, external deployment or release is implied by a local change.
