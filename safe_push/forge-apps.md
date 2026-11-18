# Two GitHub Apps for a hosted OCS mirror

The reporting App can read the source and publish a check. The separate publishing App can read checks and publish Git content. Both are owner-only GitHub App registrations with access to one selected repository. OCS pins the numerical owner, repository, Apps and installations as well as the two public-key fingerprints. A single human repository owner can operate both registrations and retains GitHub administrative authority over both. The two App identities and their separate operating-system custodians establish technical role separation. Any required expert review or authorization has its own evidence and signature. [GitHub App registration and ownership](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)

| Custodian | Repository permissions | Runtime credential |
| --- | --- | --- |
| Reporter | Checks write, Contents read, Metadata read | Reporter installation token |
| Publisher | Contents write, Checks read, Metadata read | Publisher installation token |

The public mirror’s administrative ruleset readback uses its separately selected administrative reader. The App grants contain no repository Administration, Workflows or account permissions. A protected operation needing another permission requires a separate reviewed grant. [GitHub App permission model](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)

## Prepare the local custodians

An administrator selects two distinct, dedicated non-root Unix accounts and provisions a separate mode-`0700` directory owned by each. Install the reviewed `forge_apps.py` as a root-owned, publicly readable executable under an administratively protected absolute path, for example `/usr/local/libexec/ocs-forge/forge_apps.py`. Keep the directories, private keys and tokens outside the Git worktree. Use the machine account corresponding to the role throughout its flow.

Set `APP_TOOL` to the installed script and record the repository’s numerical IDs from an independently chosen read path. The response to `GET /repos/OWNER/REPO` supplies the repository’s `id` and its `owner.id`. A personally authenticated CLI can make this administrative read. The role-specific registration and publishing flow uses its own App credentials. [Get a repository](https://docs.github.com/en/rest/repos/repos#get-a-repository)

## Register and install each role

Run the two registration listeners in separate terminals, substituting the selected private directories, account names and numerical IDs.

```sh
sudo -u "$REPORTER_USER" /usr/bin/python3 -I -B "$APP_TOOL" register \
  --role reporter --custody "$REPORTER_DIR" --repository "$REPOSITORY" \
  --repository-id "$REPOSITORY_ID" --owner-id "$OWNER_ID" --owner-type user --ttl 3600

sudo -u "$PUBLISHER_USER" /usr/bin/python3 -I -B "$APP_TOOL" register \
  --role publisher --custody "$PUBLISHER_DIR" --repository "$REPOSITORY" \
  --repository-id "$REPOSITORY_ID" --owner-id "$OWNER_ID" --owner-type user --ttl 3600
```

Use `--owner-type organization` when the selected owner is an organization. Each listener prints a single `loopbackApprovalUrl`. Open each URL in the owner’s browser on the same machine. The page shows the target and exact role permissions and has one button to review the registration on GitHub. The owner signs into GitHub and chooses **Create GitHub App**. The code returns to the loopback listener with the one-use state and its browser-bound cookie. The host validates its literal loopback origin, the challenge and its expiry, then exchanges the code with GitHub. The protected registration contains the role’s PEM and its public identity. This mirror uses no user OAuth token or webhook secret. A listener on a remote administrative host can be reached through a locally bound SSH forward with the same numerical port on both ends and an explicitly selected `--port`. [Manifest handshake and code exchange](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)

After registration, follow the GitHub `installationApprovalUrl` for that role. Under the enrolled owner select **Only select repositories**, select the exact repository and approve installation. Repeat for the other role. An installation link can be displayed again with `install-link --role ROLE --custody DIR`. [GitHub installation URLs](https://docs.github.com/en/apps/sharing-github-apps/sharing-your-github-app)

If the owner registered the App but the loopback handshake was interrupted, the owner can generate a replacement RSA PEM in that App’s settings. Place the selected PEM directly in the proper custodian’s private directory with mode `0600`. Run `adopt` using the same target arguments as `register`, plus `--app-id`, `--client-id` and `--pem-file`. Public App identity, owner and role permissions are authenticated against GitHub before custody is recorded. [Managing App private keys](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)

## Authenticate the two grants and pin the issuers

```sh
sudo -u "$REPORTER_USER" /usr/bin/python3 -I -B "$APP_TOOL" bind --role reporter --custody "$REPORTER_DIR"
sudo -u "$PUBLISHER_USER" /usr/bin/python3 -I -B "$APP_TOOL" bind --role publisher --custody "$PUBLISHER_DIR"

sudo /usr/bin/python3 -I -B "$APP_TOOL" enrollment \
  --reporter-custody "$REPORTER_DIR" --reporter-uid "$(id -u "$REPORTER_USER")" \
  --publisher-custody "$PUBLISHER_DIR" --publisher-uid "$(id -u "$PUBLISHER_USER")" \
  --project ocs --output-dir "$ISSUER_POLICY_DIR"
```

The parent of `ISSUER_POLICY_DIR` must be owned by the administrator and protected from modification by either role. The administrator re-runs authenticated grant discovery under each actual custodian UID, collecting only the public identity receipt. GitHub’s App-authenticated endpoints identify the installation, account and permissions. A temporary Metadata-only token enumerates the entire installation repository selection. OCS requires exactly the one expected repository, checks its current owner and retires this temporary token. This catches an additional selected repository even if a workload token could be restricted to the intended repository. [App and installation REST APIs](https://docs.github.com/en/rest/apps/apps) · [Installation repository inventory and token revocation](https://docs.github.com/en/rest/apps/installations)

The new directory contains immutable `app-pins.json` for the two actual issuer identities, installations, public-key fingerprints and observed repository visibility. Missing owner approval, a missing or suspended installation, foreign IDs, shared credential custody and changed permissions return `pending/not-qualified`. Hosted ruleset ID and branch enforcement readbacks have a later enrollment step. [Hosted OCS mirror](forge.md)

## Export the public bootstrap policy

Select the full staging ref and its observed Git object ID, the currently qualified local genesis, and the publisher installation ID read back from GitHub. In a repository whose default branch is `review-before-main`, its full staging ref is `refs/heads/review-before-main`. The public mirror command requires an explicit visibility value matching both authenticated App receipts.

```sh
"$APP_TOOL" policy --pins "$ISSUER_POLICY_DIR/app-pins.json" \
  --expected-visibility public --phase bootstrap-template \
  --staging-ref refs/heads/review-before-main --staging-commit "$STAGING_OID" \
  --genesis "$QUALIFIED_GENESIS" --publisher-installation-id "$PUBLISHER_INSTALLATION_ID" \
  > "$OPERATOR_PLAN_DIR/bootstrap-template.json"
jq '.rulePlanInput' "$OPERATOR_PLAN_DIR/bootstrap-template.json" > "$OPERATOR_PLAN_DIR/rules-input.json"
python3 -I -B safe_push/forge.py bootstrap-rules --enrollment "$OPERATOR_PLAN_DIR/rules-input.json"
```

The template carries the reviewed App IDs without inventing any platform-assigned ruleset IDs. Its unfinished policy is ineligible for publication. The hosted forge adapter’s `bootstrap_rule_plan` also generates the original zero-bypass hold, both permanent rules and the final closure from `rulePlanInput`. The authorized administrator reviews the exact rule bodies and reads back the three actual rule IDs from GitHub. The final export uses those IDs without modifying the immutable issuer pins.

```sh
"$APP_TOOL" policy --pins "$ISSUER_POLICY_DIR/app-pins.json" \
  --expected-visibility public --phase bootstrap \
  --staging-ref refs/heads/review-before-main --staging-commit "$STAGING_OID" \
  --genesis "$QUALIFIED_GENESIS" --publisher-installation-id "$PUBLISHER_INSTALLATION_ID" \
  --hold-ruleset-id "$HOLD_ID" --integrity-ruleset-id "$INTEGRITY_ID" --writer-ruleset-id "$WRITER_ID" \
  > "$OPERATOR_PLAN_DIR/forge.json"
```

For an already initialized, audited canonical branch, `--phase initialized --expected-visibility public` exports version 2 with `bootstrap: null`. The forge adapter verifies the actual default branch and effective rules before accepting that contour. [Bootstrap and ordinary hosted acceptance](forge.md)

## Obtain short-lived credentials

```sh
sudo -u "$REPORTER_USER" /usr/bin/python3 -I -B "$APP_TOOL" token \
  --role reporter --custody "$REPORTER_DIR" --pins "$ISSUER_POLICY_DIR/app-pins.json"

sudo -u "$PUBLISHER_USER" /usr/bin/python3 -I -B "$APP_TOOL" token \
  --role publisher --custody "$PUBLISHER_DIR" --pins "$ISSUER_POLICY_DIR/app-pins.json"
```

Each role signs an RS256 JWT using its own private key and client ID, repeats the grant readback, and requests an installation access token limited to the pinned repository ID and role permissions. It verifies that token’s repository inventory before atomically writing `installation.token` with mode `0600`. Output contains the credential path, issuer IDs and expiration. Supply the protected file directly to the appropriate worker and refresh it before expiration. GitHub installation tokens normally expire after one hour. [JWT authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app) · [Issuing repository-limited installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)

Run `python -m unittest safe_push.test_forge_apps -v` for the local browser handshake, real RSA signature and simulated permission/installation controls. Live GitHub registration and enforcement depend on the owner-approved installations and actual target.

The hosted bootstrap also reads each App’s own installation record. When that step is due, use the explicit `jwt` action under each selected role with the same arguments as `token`. It saves an eight-minute RSA assertion in the role-private `app.jwt` and prints its path and expiry. Supply the two genuine, separate assertions to the forge adapter’s `--check-app-jwt` and `--publisher-app-jwt` inputs during the authorized bootstrap. [GitHub App JWTs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
