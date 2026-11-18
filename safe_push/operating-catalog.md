# Preparing the permanent OCS operating catalogue

The catalogue preserves the original, witnessed OCS assurance basis while the sole owner prepares a permanent operating authority for project `ocs`. Its output is a read-only local archive, a summary and a draft of policy inputs. A Git publication, a policy election, a human review decision and a valid first production-cost observation each have their own evidence.

## Select the independent public sources

Run on the administrative machine. The custody directory must contain the owner’s selection, matching published proposal and registry, the possession challenge, and the public key and raw Ed25519 signature for each of the four technical roles. Both App registrations and the three ruleset IDs come from the independently operated hosted enrollment. The source object database must contain the enrolled old checker, the original genesis and all historically rejected commits. The tool reads only the selected Git object closures and writes an object pack without creating any Git ref.

The known sole-owner registry digest is `fafffc46707d86dc9e763a1abd705696e7185ab49b247afdceb5b76af7fb763f`. The historical receipt directory contains the original root, seed, refusals and readbacks. The old receiver authority supplies its public observer, full signed baseline and trial dossiers, outside enrollments, acquisitions and content-tree counterexamples. The source paths are recorded to explain initial custody. Offline replay subsequently needs only the resulting archive and the independently retained selection digest.

```sh
python3 -I -B safe_push/operating_catalog.py select \
  --custody /var/lib/ocs-operating/ocs/public \
  --custody-sha256 fafffc46707d86dc9e763a1abd705696e7185ab49b247afdceb5b76af7fb763f \
  --app-pins /var/lib/ocs-forge/enrollment/app-pins.json \
  --forge-policy /var/lib/ocs-forge/enrollment/forge-policy-v2.json \
  --hosted-observations "$PUBLIC_HOST_READBACKS" \
  --release-receipts "$ORIGINAL_ACCEPTANCE/release-receipts" \
  --evidence-authority "$ORIGINAL_RELEASE_STATE/authority" \
  --git-objects "$ORIGINAL_RELEASE_STATE/repository.git/objects" \
  > "$ADMIN_DIR/selected-inputs.json"
sha256sum "$ADMIN_DIR/selected-inputs.json"
```

For this historical acceptance, `ORIGINAL_ACCEPTANCE` ends in `out/safe-push/2f722bc4`, the release state ends in `release-2f722b/state`, and the hosted readback directory ends in `out/safe-push/public-27569472`. Check the selected file and its public asset and adverse-inventory digests against independent records. Retain its SHA-256 separately from the archive. Keep the selection root-owned and available read-only to its consumer.

For an independently reviewed first-cost method candidate, add the exact `--first-cost-revision`, `--first-cost-sha256` and `--first-cost-tests-sha256` to `select`. The last two identify the committed bytes of `safe_push/cost_acquisition.py` and `safe_push/test_cost_acquisition.py`. Add that revision to the independently selected object database if the old evidence receiver only contains the original release history. The catalogue verifies the source and test bytes as inert data. A missing selection produces an explicit pending method enrollment.

## Prepare and replay the archive

Use a new directory beneath an administrator-owned parent outside the input trees. `prepare` checks the local role names and numerical UIDs, authenticates all four possession signatures, captures public records, and independently replays the original baseline and each adverse trial at its signed historical observation time. It verifies the new archive a second time before publishing the directory atomically. An existing directory is reused only after it passes verification for the same independent input selection.

```sh
python3 -I -B safe_push/operating_catalog.py prepare \
  --inputs "$ADMIN_DIR/selected-inputs.json" --inputs-sha256 "$SELECTED_SHA256" \
  --output "$NEW_CATALOGUE_DIRECTORY"

python3 -I -B safe_push/operating_catalog.py verify \
  --bundle "$NEW_CATALOGUE_DIRECTORY" --inputs-sha256 "$SELECTED_SHA256"
```

For a later preparation add `--previous-bundle DIR --previous-inputs-sha256 DIGEST`. The verifier checks the old archive independently, then checks that the original owner selection, comparison basis, hosted guard facts, adverse tree receipts and unresolved criteria survived. It also checks the source pack contains exactly the Git closures named by the selection.

| Material | Verified meaning |
| --- | --- |
| `archive/custody/` and `archive/host/` | One named human owner. Four distinct native role UIDs and public keys, two separate GitHub App UIDs and installation IDs, and the recorded active main-branch hold and two permanent guards. |
| `archive/history/genesis.json` | The original exact per-claim identities, numerical values, directions, conditions, target reports and ten recorded coverage limitations. |
| `archive/bootstrap/`, `archive/evidence/`, `archive/observers/` and `archive/source.pack` | Independently replayable signed executions, original public enrollments and their exact source objects. Current deployment eligibility requires fresh observations. |
| `archive/history/adverse/`, `acquisitions/`, `refusals/` and `readbacks/` | The original content-addressed vetoes and complete worsened cells. The two genuine historical tree refusals preserve 165 and 210 worsened cells respectively out of 364. Both rejected pushes retained the former tip. |
| `catalog.json` and `operating-policy-inputs.json` | Verified preparation facts, the old project’s provenance, selected future permanent parameters, and explicit outstanding conditions. The draft retains every old mandatory open requirement. |

The original historical OCS denominator is 394 claim levels and 364 measurements. A check-run ID in the archive identifies the recorded genuine hosted refusal. The verifier recomputes the worse-cell totals and binds them to the recorded App, repository, candidate, tree, preview and readback. A hosted rule or check may change later. Safe Push requires live readback for a new publication.

## Before irreversible initial policy enrollment

1. The owner has selected public role keys and proved possession. Validate the installed private custody boundaries, the public GitHub registrations, the scoped operating installation and the exact policy under consideration. The native independent role supplies machine-verifiable evidence. An independent human judgement needs its own genuinely available source.
2. Independently pin the candidate checker, its complete incumbent source and its falsification controls **before** the irreversible initial permanent policy. The first-cost grant has exactly the purpose `evolution/receiver-cost` and path `policy/receiverCost`. Preserve each inherited open requirement and its potential old-authority purpose in `prospectiveOpenDispositions`. To close an eligible old hold later, its exact narrow, independently tested purpose must already be available to the predecessor authority.
3. Retain the original comparator snapshot, coverage limits and every adverse tree marker under the effective authority’s veto lookup before enabling a future publication route. The documents continue to name their original measurement project. Read back every marker by tree and digest under the new operational contour. Reprepare against the prior catalogue if input rosters change.
4. Acquire a real first successful full pre-publication workload through the separately approved incumbent method, actual protected native publisher and original controls. Capture the native `executionContextSha256`, publisher UID, capability and network restrictions, separate platform/workload digests, and all seven measured counters. A failed branch experiment, passing calibration, synthetic shell timing or key-possession signature supplies a different observation.
5. Apply the genuine role-specific reviews, current full assurance, prior-purpose proofs, both authenticated election quorums and separate administrative authorization required for any actual transition. Critical-use and broad empirical guarantees retain the original open disposition until the specific scope can be established.

`python -m unittest safe_push.test_operating_catalog -v` runs integrity and monotonicity controls on disposable fixtures. Set `OCS_OPERATING_CATALOG_INPUTS` to an independently selected real administrative input file to run the full three-dossier control. It removes a genuine adverse record from a disposable copy and rewrites the copy’s inventory. The verifier still detects the loss using the original independent selection.
