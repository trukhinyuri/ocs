# Safe Push admission proof

The protected receiver calls `proof.certify` with its committed parent ledger, the complete candidate ledger, the observed Git parent, candidate and tree object IDs, and nine checked facts. A positive receipt names the exact transition. A negative proof shows that this packet cannot be published from any state. Missing or malformed inputs, an unavailable verifier or exhausted verification resources hold publication.

[Admission.lean](Admission.lean) defines the finite decision. `gate_exact` proves both directions. Each previously accepted claim keeps its identifier and meaning digest. Each protected metric keeps its identifier, direction and condition digest. A minimum may decrease, a maximum may increase, and equality passes. Values are compared as exact rationals. New entries are covered by the separately enrolled inventory, target qualification and reviews.

`exact_commit` proves the receipt identifies the successful compare-and-swap transition. `arbitrary_history` and `history_journal` extend preservation and receipt provenance by induction from the enrolled state. A stale second writer fails. Recovery uses the durable ref and authenticated preparation to distinguish an unpublished attempt from the exact published candidate, including repeated restarts. A later hold preserves the historical receipt and blocks current use of a revoked tip.

## Installation and verification

Install the approved Linux verifier distribution from [the pinned manifest](../assurance/wire/toolchain.json). Install `proof.py`, `Admission.lean` and the manifest from the independently enrolled receiver revision outside candidate worktrees. Set `SAFE_PUSH_LEAN_HOME` to the absolute protected toolchain directory. The default resolves the corresponding installed release under the receiver account's home. An absolute `SAFE_PUSH_TOOLCHAIN_MANIFEST` may designate another copy of the identical enrolled manifest. The receiver and its toolchain installation require trusted ownership, including imported libraries. Each invocation checks the pinned executable and shared-library bytes and revision.

The encoder represents Git IDs, SHA-256 digests and UTF-8 row IDs as injective tagged byte sequences. It supplies only literals to the fixed Lean term. The checker decodes the entire elaborated packet and compares it to the receiver input, kernel-checks the concrete decision, exports its transitive proof and replays it with the independent kernel. Its axiom policy permits only `propext`, `Quot.sound` and `Classical.choice`.

Each receipt includes the compressed finite input witness and the digest of the independent proof export. An auditor calls `replay_certificate(receipt, **enrolled_inputs)` with independently obtained parent and candidate ledgers, facts and Git identity. For a different originating verifier platform, supply its independently authenticated `expected_origin`. Replay accepts matching concrete refusals as historical evidence. Only an accepted verdict authorizes a candidate. Run `python -m unittest safe_push.test_proof` from the repository root.

## Scope

The nine factual inputs depend on independent evidence verification, custody and clocks. The model assumes an enrolled genesis, collision-resistant object identities, an exclusive authenticated writer, atomic Git compare-and-swap, durable immutable records and an authentic ref read-back. Publication rechecks freshness and revocation. Packaging, the Python bridge, Git, filesystem durability and host isolation retain explicit implementation and operational trust boundaries. The proof concerns enrolled metric cells and finite declared requirements. Physical workloads outside their observed conditions require independent evidence.
