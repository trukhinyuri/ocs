# Verify a remote stand receipt offline

The live qualification gate signs `attestation.json` with the operator's Ed25519 observer key. The dossier also contains `attestation.sig` and the original byte representation of the observed stand in `evidence/stand.json`. An operator can verify those three files without cluster credentials, a running deployment or the signing key.

## Enroll independently

Establish the approved checker commit, expected source commit, immutable OCI image, kubeconfig context, namespace and observer **public** PEM through your own release configuration. Keep the enrollment and public key outside the submitted dossier. The checker Git database must contain the complete accepted revision, including its stand policy and evidence-index. The subject must be a clean checkout of the explicitly selected source revision.

Use read access to the Kubernetes API, the owned two deployments, services, replica sets, ready pods, PVC, nodes and public certificate projections. Read-only commands through the pods' exec API hash the running source files, executable and mounted public certificates. The enrollment tool checks the actual selected service/controller/pod chain. The request has no qualification dossier input. If a runtime reports a per-platform or config digest, the operator may supply an independently obtained OCI blob map with `--oci-proof`. Otherwise the tool reads the named immutable registry manifest when necessary.

```sh
uv run --locked python -I assurance/enroll_receipt.py \
  --checker-repo "$checker_repo" --checker-commit "$checker_commit" \
  --subject-root "$subject_checkout" --subject-revision "$subject_commit" \
  --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
  --image "$immutable_oci_ref" --public-key "$enrolled_public_pem" \
  --output "$operator_state/enrollment.json"
```

The enrollment binds the subject tree digest, exact cluster and service identities, PVC, ready relay and provider, reported OCI images, the in-container source inventory and Go binary, and public CA and leaf fingerprints. Enrollment immediately before or after the measured recovery may observe either provider pod in the signed old/new recovery pair. The relay and stable identities must agree. Preserve an independently established enrollment for its observation interval when later rollouts change those identities.

## Replay a dossier

Use a trusted verifier installation, an accurate system clock, local Git objects, Python and OpenSSL. Supply the operator's independently provisioned enrollment and exact public PEM. `operatorKey` is SHA-256 over the bytes of that PEM. CA and server/relay certificate hashes in the expected target use their PEM bytes. The browser observation separately uses the public server leaf in DER form.

```sh
python3 -I assurance/verify_receipt.py \
  --checker-repo "$checker_repo" --dossier "$submitted_dossier" \
  --enrollment "$operator_state/enrollment.json" --public-key "$enrolled_public_pem" \
  --report "$operator_state/offline-verdict.json"
```

The verifier authenticates the exact signed bytes, checks the detached report's digest and contents, binds both targets to the enrollment and loads the protected observer predicate, expected check IDs, claim assignments and thresholds by full Git commit ID. It checks every required row's outcome, scope and observation interval, the quality and load measurements, exposed account data and the durable recovery witnesses. Exit code zero records acceptance for the named target and time window. A successful offline verdict authenticates and re-adjudicates the observer's historical evidence. A newly deployed or newly measured target receives its own live observation.
