# Contributing

1. Reproduce an observable problem using synthetic inputs. Name the role, profile and edition.
2. For a design change, start with the [proposal template](proposals/TEMPLATE.md). For a clarification use a small patch.
3. Cite a rule ID. Specify the input, allowed result, forbidden effect and behavior under failure. Update the schema only when its accepted language changes.
4. Run `make check`. For interoperability, run the released cases against both the reference and an independent target from a fresh environment. Keep external access and destructive tests opt-in.
5. Record compatibility, migration, rollback and any unverified case. Generated documentation must be reproducible. An erratum explains the old interpretation and the corrected one.

Use an existing extension point before inventing another mechanism. Each normative change has a consumer. Keep an operation with different authority or costs separately identifiable. A standard change must be understandable without reading either product that motivated it.
