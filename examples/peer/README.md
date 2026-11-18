# Bind two independent owners

[The assembly](assembly.json) describes a workspace importing one read operation from a service. The [workflow package](../workflow/ocs.json) declares that import. The [service package](../status/ocs.json) supplies it. Each instance has its own trust domain and its manifest is pinned by the digest of its exact bytes. This file is an inspectable assembly example. The development host uses its equivalent sealed binding.

Run `make report` to start a Go caller and a receiving Python host on an ephemeral loopback port. The runner issues a disposable credential and checks a successful read, a different credential, a write outside the grant and local operation after the receiving host stops. Nothing needs to be configured on the machine.

For a deployment across machines, the owner supplies an authenticated HTTPS endpoint, its verified identity, an audience-bound grant, exact revision and a deadline. Define revocation, retry ownership and partition behavior before enabling writes. See [Composition](../../spec/composition.md).
