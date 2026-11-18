# Contributing

1. Reproduce an observable problem using synthetic inputs. Name the role, profile and edition.
2. For a design change, start with the [proposal template](proposals/TEMPLATE.md). For a clarification use a small patch.
3. Cite the affected rule and scenario IDs from the [index](conformance/scenarios.json). Specify the input, expected result, forbidden effect and failure behavior. Link each new scenario to its checks or name the evidence still needed. Update the schema when its accepted language changes.
4. Run `make check`. It exercises the working tree and the accepted edition. Keep the previous interaction under its stable ID while that edition is supported. Record a changed promise, correction or retirement with the affected consumers, version, migration and replacement scenario. Keep external access and destructive tests opt-in.
5. Record compatibility, migration, rollback and any unverified case. Generated documentation must be reproducible. An erratum explains the old interpretation and the corrected one.

Use an existing extension point before inventing another mechanism. Each normative change has a consumer. Keep an operation with different authority or costs separately identifiable. A standard change must be understandable without reading either product that motivated it.
