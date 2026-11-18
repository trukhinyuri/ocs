# One reset credit, one durable outcome

This test fixture owns a synthetic account with one reset credit and an empty weekly window. The approved reset costs zero currency units, consumes one credit and restores 100 requests. Each balance, authorization record and receipt lives in the same local database. The test can lose a reply, reopen the database, retry from another process connection and inspect the actual balance.

The host supplies the authenticated owner to the service. The test driver calls the trusted approval surface separately. A caller cannot gain approval by adding a property to input. There is no upstream identity or paid service. A remote write for which the downstream outcome cannot be recovered must follow the unknown-outcome rule in [Effects](../../spec/profiles/effects-and-jobs.md).

Run the [executable cases](../../conformance/test_effects.py) with `make check`. They check the public proposal and receipt shapes and count persisted effects. This ledger demonstrates the state boundary behind an effects adapter. Its methods are private example interfaces.
