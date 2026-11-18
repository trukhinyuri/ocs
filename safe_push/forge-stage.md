# Staging a public OCS review branch

`forge_stage.py` transfers one explicitly selected single-parent commit to `refs/heads/review/<slug>` in an enrolled public GitHub mirror. The slug consists of lower-case letters, digits and hyphens and begins with a letter. The original bootstrap staging branch, the current default branch and canonical main are excluded from the destination. A git check result, a release and a production admission have separate evidence. An archived full assurance result identifies the old parent and its historical observation time.

## Establish the public inputs

Prepare a self-contained, administrator-owned bare repository snapshot containing the exact parent, candidate, protected qualification verifier and their Git objects. Every directory and file must be read-only to the publishing UID. The tool reads the object database through a fresh private bare view. It supplies its own Git configuration and hooks policy. Preserve the original signed full dossier, its independent enrollment and its observer public key outside the candidate checkout.

Produce the bounded historical parent receipt. Independently select the comparison checker, original signed-report digest and observer-key digest. This command verifies the proof and observation inventory against the signed original time window.

```sh
python3 -I -B safe_push/forge_stage.py parent-proof \
  --source "$PUBLIC_OBJECTS" --parent "$HISTORICAL_PARENT" --verifier "$HISTORICAL_VERIFIER" \
  --dossier "$SIGNED_DOSSIER" --baseline-enrollment "$INDEPENDENT_ENROLLMENT" \
  --observer-key "$OBSERVER_PUBLIC_KEY" --signed-report-sha256 "$ORIGINAL_REPORT_SHA256" \
  --observer-sha256 "$INDEPENDENT_KEY_SHA256" > "$ADMIN_REVIEW_DIR/parent-proof.json"
```

For the original witnessed parent `3facf571910e0799539a77a1a5112e6609a9a5ca`, the observed signed report was `9b48d20fa66c191837d364ddaca13d861372df764f86b028150b4624094bb232`. It covered 394 requirement levels. Inspect the exported parent identity, tree hashes and source scope before placing this public receipt under administrative ownership. This review operation preserves a historical baseline across later expiry of its deployment observations. Current availability and canonical eligibility each require their distinct current checks.

## Read the canonical guards as the administrator

Use the independently selected administrator’s GET-only GitHub CLI route. Its keyring remains under that account. The two reads verify the public repository and owner IDs, the immutable staging branch, current canonical ref, the active hold and both permanent guards, their exact literal main-branch conditions, bypass actors and effective rules. The default validity interval is ten minutes.

```sh
python3 -I -B safe_push/forge_stage.py guard \
  --enrollment "$FORGE_V2" --ref refs/heads/review/hosted-public \
  --gh-read --gh-executable /usr/bin/gh > "$ADMIN_REVIEW_DIR/guard.json"
```

Install the verified public parent and guard JSON files and the selected forge enrollment beneath an administrator-owned directory, readable by the publisher and protected from modification by that UID. The publisher independently verifies the public effective rules, the visible fields of their three enrolled rule details and current refs. A refresh of the administrative receipt with identical facts can extend its observation window. A change to the enrolled facts changes the action digest or holds the transfer.

## Approve and verify the exact review action

As the publisher App’s genuine, non-root custodian, run the preparation command.

```sh
python3 -I -B safe_push/forge_stage.py prepare \
  --enrollment "$FORGE_V2" --pins "$APP_PINS" --custody "$PUBLISHER_DIR" \
  --source "$PUBLIC_OBJECTS" --parent-proof "$PARENT_PROOF" --guard "$GUARD" \
  --ref refs/heads/review/hosted-public --parent "$HISTORICAL_PARENT" --candidate "$REVIEW_COMMIT"
```

Preparation freshly authenticates the publisher App, verifies its one-repository installation and obtains a short-lived, scoped credential. The approval material contains the repository, ref, absent-ref condition, exact candidate and parent, Git tree, independent whole-source and baseline hashes, guard facts and publisher identity. Show the complete action and `actionSha256` to the owner. After approval, run the same command with `publish` in place of `prepare` and add `--approved-sha256 "$APPROVED_ACTION_SHA256"`.

The publisher repeats preflight, durably records its intent and issues one HTTPS Git push with `--force-with-lease=<review-ref>:`. The empty expected value requires the branch to be absent. Git reads the URL-scoped Basic header from an anonymous sealed memory descriptor. The role session revokes its installation token on exit, including an interrupted operation handled by the process. The bearer stays out of files, arguments, environment variables and printed output. Redirects, personal credential helpers, recursive submodule pushes, tag following and client-side hooks are disabled. [Exact Git force-with-lease](https://git-scm.com/docs/git-push) · [GitHub App installation authentication over HTTPS](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)

`confirm` uses the same operands, authenticates the issuer again and reads the actual branch SHA, candidate tree and direct parent, old parent tree and unchanged canonical ref. `newCreationByEnrolledTransport` is true only after Git acknowledged a new branch for the exact enrolled transfer and the independent API readback agrees. An already matching preexisting branch and an ambiguous acknowledgement have distinct receipt values. An unresolved intent blocks a second network attempt for this branch name. An operator can use `confirm` to reconcile an interrupted send.

Run `PYTHONPATH=safe_push python3 -m unittest safe_push.test_forge_stage -v` for the archived signed baseline, active-guard and actor substitutions, real disposable Git compare-and-swap, protected existing-ref behavior, and a local smart HTTPS receiver with authenticated GET and POST. The real GitHub repository has its own approval and authenticated transfer/readback receipt.
