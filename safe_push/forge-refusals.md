# Reporting an independently measured refusal

`forge_refusals.py` opens both existing signed full OCS dossiers and recomputes the evidence for a staged, direct child of an enrolled historical genesis. A reported failure states that at least one preregistered measurement worsened under comparable conditions. This path supports a factual refusal while unrelated positive release approvals remain outstanding. Every proposal uses `OCS Safe Push` with `status=completed` and `conclusion=failure`. It leaves both refs alone. [Measured refusal verifier](forge_refusals.py) · [Dossier verification](qualification.md)

## Independent inputs

Keep the refusal enrollment and its expected canonical SHA-256 outside the staged commit and its dossiers. Select the original release policy and genesis receipt using anchored receiver records. The enrollment has the following fields.

| Field | Independently selected input |
| --- | --- |
| `format` | `ocs.safe-push.hosted-refusal-enrollment/1` for the original staged branch or `ocs.safe-push.hosted-refusal-enrollment/2` for a separately staged review. |
| `repository`, `repositoryId`, `ownerId`, `ownerType`, `expectedVisibility` | Exact hosted repository, numeric identity and owner. Owner type is `user` or `organization`. |
| `project`, `measurementProject` | Hosted project and the release-policy project that made the measurements. The latter remains visible in the published summary. |
| `target`, `stagingRef`, `parent`, `candidate` | Enrolled release target, noncanonical staged ref, original genesis and proposed direct child. Use full Git object IDs. |
| `bootstrapRef`, `bootstrapCommit` (version 2) | Original bootstrap branch and its pinned tip from the independently installed hosting policy. The hosted default must be that branch or `main`. Each preflight reads both this tip and the candidate's review ref. |
| `releasePolicySha256`, `previousReceiptSha256` | SHA-256 of canonical JSON for the previously installed policy and genesis receipt. |
| `metricProfileSha256` | SHA-256 of the original metric profile file bytes. This profile supplies the metric definitions and directions. |
| `baseEnrollmentSha256`, `candidateEnrollmentSha256` | SHA-256 of each independently provided stand enrollment's exact file bytes. The release policy pins the verifying public key and target conditions. |

The verifier reads the actual clean Git trees for both commits. It reopens both aggregate signatures, stand attestations, artifacts, public observations and claim-level witnesses with the enrolled verifier. It checks the prior observations against the target-prefixed cells inside the rooted genesis receipt. Every inherited evidence level and every registered comparison cell must be present and comparable. Missing, incomparable, invalid, expired or substituted evidence holds the proposal. Equal and improved cells still count in the denominator. The public certificate contains counts and hashes of evidence. The original datasets, file paths, private artifacts and tokens stay with their custodians. [Claim and metric scope](qualification.md)

## Commands

The following arguments are shared across the commands. Supply paths belonging to the independent enrollment and acquisition. The source repository must contain the pinned checker, both historical Git objects and their trees.

```sh
python -I safe_push/forge_refusals.py verify \
  --trust refusal-enrollment.json --trust-sha256 "$ENROLLMENT_SHA" \
  --repo "$OBJECT_REPOSITORY" --old-policy "$ORIGINAL_POLICY" --old-genesis "$GENESIS_RECEIPT" \
  --base-dossier "$ORIGINAL_DOSSIER" --base-enrollment "$ORIGINAL_STAND_ENROLLMENT" \
  --candidate-dossier "$CANDIDATE_DOSSIER" --candidate-enrollment "$CANDIDATE_STAND_ENROLLMENT" \
  --observer "$ENROLLED_OBSERVER_PUBLIC_KEY"
```

Use `preview` with the same arguments plus `--reporter PUBLIC_INSTALLATION.json --reporter-sha256 EXPECTED_SHA` to generate the exact offline body. Use the independently registered public `ocs.safe-push.app-installation/1` receipt for the checking App and the canonical digest selected by its custodian. Preview identifies the need for live checks.

Use `proposal` with the same inputs and add `--reporter-jwt-file PROTECTED_APP_ASSERTION` and either `--gh-read` or `--token-file PROTECTED_READ_TOKEN`. The tool makes GET requests to verify the registered account, repository, branch, tree, direct parent and current checking App installation. It verifies the selected repository grant, exact reporter permissions and suspension status. It also checks existing reserved-name check runs and legacy statuses. It prints the exact proposal. A matching already completed failure returns its run ID. A missing expected run in `readback`, a different issuer or conclusion, or conflicting runs leave confirmation open. The ordinary admission verifier accepts only its own separately evidenced completed success and receipt format. A refusal carries an external ID beginning with `refused:`. [Checking App enrollment](forge-apps.md) · [Hosted check validation](forge.py)

An independently authorized App custodian serializes submission for the repository, SHA and reserved check name, repeats live preflight immediately before acting, and reads back both the created run and the protected ref. GitHub supplies no atomic create-if-absent operation for arbitrary check external IDs. A lost response requires readback before any retry. `readback` verifies the exact failure issuer, result, external ID and public summary. All four commands are read-only with respect to GitHub.

Run `python -m unittest safe_push.test_forge_refusals` for the local controls. To include both independently filed original dossiers, set `OCS_HOSTED_REFUSAL_HISTORY` to the operator's artifact repository. The historical control honors expiration on the real clock. [Acceptance controls](test_forge_refusals.py)

The separate [checking-App sender](forge_delivery.py) replays the original inputs, validates its installation and scopes its short-lived credential to one repository. Run `preview` from the checking identity against the independently selected input bundle. The operator reviews the exact public JSON and its canonical SHA-256. `post-refusal` requires that fingerprint, records a durable intent and can send only a completed failure for that exact staged commit. The sender verifies the run's actual App and result and reads the canonical ref again. `readback` resolves a previously uncertain response without posting. [Delivery controls](test_forge_delivery.py)
