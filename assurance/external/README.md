# Offline third-party evidence

An implementation in any language can submit the [versioned example envelope](example/evidence.json). The owner independently enrolls the exact statement, scope, principal role, transport, assumptions, source, executable artifact and checker. For the [example enrollment](enrollment.json) the claimed property is the intersection of two sets of rights represented by 32-bit masks. The submitted [C source](example/grant.c) was compiled to a 61-byte [Wasm module](example/grant.wasm). The property addresses the actual exported function on every pair of i32 inputs.

## Import the example

Use a verifier checkout independently selected by the operator. In the commands below, `policy` is the full SHA-256 obtained from that enrollment. For this initial repository example it is `8255b6c73271c8fcce13c256da5e41ffcd65878ea0478a2f2a1c486716c56ee9`.

```sh
policy=8255b6c73271c8fcce13c256da5e41ffcd65878ea0478a2f2a1c486716c56ee9
python3 -I assurance/external/check.py \
  --policy assurance/external/enrollment.json --policy-sha256 "$policy" \
  --subject assurance/external/example/grant.c --artifact assurance/external/example/grant.wasm \
  --bundle assurance/external/example/evidence.json --report out/external-receipt.json
```

`ocs.external-evidence/1` contains the scope, statement digest, source digest, artifact digest and inert certificate. The certificate binds the SHA-256 of those scope and digest fields encoded as sorted-key, compact UTF-8 JSON. Scope includes the edition, role, binding, platform, feature set, operation versions, property, assurance level, accepted assumptions and suite. The owner supplies the subject and artifact as separate paths. Only regular files within the enrolled limits are admitted. An envelope with extra status, command or selection fields is refused.

`ocs.external-enrollment/1` pins the statement and checker files by digest. Its command consists of the selected engine, verified program bytes and fixed arguments. The verifier is executed without a shell in a temporary directory. It receives a versioned JSON request on stdin with the exact captured bytes, digest-bound certificate and a fresh nonce. Its response must match the nonce and all bindings. A native checker can use the same protocol as the example Python standard-library driver. Each additional property or alternative verifier requires its own operator enrollment. The protected outer gate supplies independence when it selects this checkout for evaluating a candidate.

The recorded `ocs.external-receipt/1` includes the actual scope, digests, approved checker identity, observed time, theorem and checker result. A refused import returns a nonzero status and a refusal receipt. An operational observation or signature would require its own declared method and provenance.

## What the example checks

The fixed [statement](Grant.lean) describes the byte layout of the admitted module, its function type and exports, Wasm local loads and i32.and stack semantics. It proves that a checked symbolic execution trace refines concrete execution for arbitrary 32-bit arguments. The [checker](wasm_verifier.py) converts only bounded instruction tags, bytes and constructor data to literal terms. The selected Lean kernel checks that the delivered bytes decode to the supplied operations, that every supplied intermediate stack is correct and that the exported result equals the required intersection. The separately pinned `leanchecker` replays the resulting declarations and the permitted transitive axioms are audited. The release and machine hashes come from the [operator toolchain policy](../wire/toolchain.json). Local compiler and OS semantics, the formal description of the supported Wasm subset, the trusted host interpreter and hardware are explicit boundaries. The source fingerprint identifies the associated C source. The artifact property is established directly from the Wasm bytes. [Wasm binary modules](https://webassembly.github.io/spec/core/binary/modules.html) · [Instruction semantics](https://webassembly.github.io/spec/core/exec/instructions.html) · [Lean proof validation](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)

Rebuild the demonstration from source with a compatible C/Wasm compiler or invoke the shipped artifact with an ordinary Wasm runtime. Neither operation is needed by the offline importer.

```sh
clang --target=wasm32-unknown-unknown -nostdlib -O2 -fno-builtin \
  -Wl,--no-entry,--export=ocs_grant,--strip-all \
  -o /tmp/ocs-grant.wasm assurance/external/example/grant.c
node -e 'const m = new WebAssembly.Instance(new WebAssembly.Module(require("fs").readFileSync(process.argv[1]))); console.log(m.exports.ocs_grant(12, 10))' assurance/external/example/grant.wasm
```

## Qualify the importer

`python3 -I assurance/external/check.py --report out/external-import.json` exercises the explicit import CLI and its refusal cases. The positive controls include a separately enrolled artifact with the operand-load order reversed. Its certificate is valid for that artifact. Transplanting it and rebinding its label to the original bytes still fails semantic checking. Other controls exercise a changed statement, weakened binding or stronger premise, altered file, bad stack step, different policy and an applicant-supplied command or success flag. Reports retain only artifact identifiers and scoped evidence. The example uses no network access.
