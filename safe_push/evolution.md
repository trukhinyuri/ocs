# Evolving an enrolled policy

A policy change belongs to its predecessor's authority. Each side's domain, independent and guardian custodians sign the exact proposed transition. The receiver replays the predecessor's admission rule and its registered proof methods before advancing the epoch. Keep all materials in the independently managed authority snapshot so a later auditor can replay the entire history.

## Changes and proof requirements

| Change | Admission requirement |
| --- | --- |
| Add an equivalent predicate alias | Identical executable digest and a subset of an already authorized method's purposes and paths. |
| Add a target | An incumbent proof covers the exact target, its calling convention and conditions. Target adapters receive their names as inputs, including when an existing descriptor is assigned a second name. |
| Add a new executable or extend an existing predicate | Verify its exact bytes and required behavior using a purpose-specific predecessor method. New code is staged as data. |
| Change the assured verifier revision, observer or implementation | Independently prove continuity of the original subject and the proposed subject under the old purpose and scope. A target keeps its original condition digest. |
| Tighten freshness, receiver duration or a cost ceiling | Preserve all registered cells and measurement conditions. An incumbent proof covers usability and preserved domain under the new restriction. |
| Close a mandatory open claim | An incumbent verifier covers that exact claim and independently checks positive and refused evidence. Additional unresolved mandatory claims keep the activation pending. |
| Remove an inherited target, adapter or predicate, relax an existing bound or replace measurement identity | The transition is refused. A new separately proven target can be enrolled alongside the original. |

`evolution_scope(old,new)` returns the exact proof purposes, each scoped to a logical path under `policy/`. Previously enrolled `evolution/add-target`, `evolution/add-adapter` and `evolution/add-predicate` methods may cover unknown future names within their explicit path prefixes. Changing an existing binding or closing an open claim requires its specific purpose. Qualifying an actual release still requires all target observations, independent reviews and ref checks. [Receiver admission](admission.py)

## Materials and signing

Use canonical UTF-8 JSON with sorted keys, compact separators and finite numbers. Each subject, proof or control has an SHA-256 identifier calculated from its exact bytes. A policy subject has `format` equal to `ocs.safe-push.policy-subject/1`, its `policySha256`, `assuranceRevision`, `epoch` and a checker-specific `data` object. An optional `artifacts` map names additional exact opaque inputs by digest. The checker receives them as read-only files under the old or new subject directory.

The evolution object has `format` equal to `ocs.safe-push.evolution/1`, `scopeSha256`, the `old` and `new` digests under `subjects`, the `positive` and `refusal` digests under `controls`, and a `proofs` map from each required purpose to its incumbent `method` and positive `artifact` digest. Each proof envelope supplies `format: ocs.safe-push.evolution-proof/1`, its `purpose`, `scopeSha256`, both `subjects` and a method-specific `body`.

Control format `ocs.safe-push.policy-control/1` binds the scope, `parent`, `actualParent`, `candidate`, `ageSeconds`, `serviceSeconds`, `targetConditions`, `costs`, expected `criterion` and a `refutations` map. The positive case carries a null criterion and an empty refutation map. The adverse case changes one policy input, identifies its reproducible refusal and supplies a distinct negative proof artifact per required purpose. The trusted predecessor method must acknowledge the positive proof and explicitly reject the adverse proof. Its reply binds its exact input context and artifact digest.

Register each expected immutable object using the operator command. Register newly named executable bytes with kind `method` and public observer PEM material with kind `observer`.

```sh
python -I safe_push/operator_cli.py evolution-input /protected/receiver.json subject-or-proof EXPECTED_SHA256 material.json
```

Construct the signature body with `evolution_signature_payload(old,new,evolution)`. It includes both epoch numbers, old and new policy digests, the evolution and scope digests, exact subject digests, control and proof digests. Each signer adds its own `role` and `side`. Pass the resulting envelope with `policy`, `evolution`, `old`, and `new` to the normal `rotate` command. [Operator entry points](operator_cli.py)

## Replaying a complete finite example

Run `python -m unittest safe_push.test_evolution -v`. The original verifier fixes four inputs, two accepted and two refused. It checks both entire subject tables and both proof artifacts under process and filesystem isolation. A stronger timeout passes for the original finite workload. A shorter timeout that excludes one admissible operation fails even though the individual positive example still fits. Another test runs the existing target adapter using its newly registered target name. These are closed finite claims. A general verifier replacement needs incumbent evidence connecting its actual source or binary and admissible domain to the claimed behavior. [Verified examples](test_evolution.py)
