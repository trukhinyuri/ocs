# Hosted repository adapter

`forge.py` reads an individually enrolled GitHub repository and the independently administered local receiver. Its network requests use GET. Successful proposal commands print the exact proposed check run or leased Git push as JSON for an independently authorized publisher. Confirmation reads the actual protected ref.

## Enrollment

Keep the enrollment and credentials outside contributor control. Record the numeric repository and owner IDs, its exact full name, the local release project, and the independently operated check App and installation IDs. The example uses synthetic values.

```json
{
  "format": "ocs.safe-push.forge/1",
  "repository": "fixture/project",
  "repositoryId": 42,
  "ownerId": 10,
  "project": "ocs",
  "mode": "mirror",
  "checkAppId": 70,
  "checkInstallationId": 1234,
  "publisherAppId": 80,
  "mergeQueue": false
}
```

For a pull-request installation use `"mode":"pull-request"` and `"publisherAppId":null`. Enable `mergeQueue` only on an enrolled repository with that capability. Run the following command to generate an array of installable ruleset bodies. Each array element corresponds to one repository ruleset. Applying them requires separate administrative authorization.

Version 1 requires a private repository with `main` as its default. For an already initialized public or private repository select `ocs.safe-push.forge/2`, add `expectedVisibility` with the exact value `public` or `private`, and use `"bootstrap":null`. Both the provider's visibility label and its Boolean private flag must agree with the enrollment. Each version retains the exact numeric owner, repository and App checks.

The restricted-update rule lets only enrolled bypass actors update the branch. GitHub can return `{"type":"update"}` after the writer was installed with `update_allows_fetch_and_merge` explicitly set to `false`. The verifier accepts these two encodings. An explicit parameters object must contain exactly that Boolean field with value `false`. [Repository rules REST schema](https://docs.github.com/en/rest/repos/rules?apiVersion=2022-11-28) · [Restrict updates](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#restrict-updates)

```sh
python -I safe_push/forge.py rules --enrollment /protected/forge.json
```

Both modes protect `refs/heads/main` against deletion, creation and non-fast-forward updates, require linear history and demand the check from the enrolled App. The integrity ruleset has no bypass actor. Pull requests require two approvals, stale dismissal, code-owner approval and approval of the last push. Mirror mode adds a separate update restriction with the sole publishing App as its only allowed writer. This App remains subject to the integrity ruleset. Audit reads displayed bypass actors, full effective branch rules, classic protection and inherited repository-wide constraints. A hidden bypass list, unreviewed effective rule or inaccessible private rules API holds admission. [Repository rules API](https://docs.github.com/en/rest/repos/rules?apiVersion=2022-11-28) · [Protected branch availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)

## Readback and proposals

Use the read credential selected by the operator throughout. The rules API must expose effective bypass actors to this identity. Even a successful private repository metadata read leaves enforcement open when the rules endpoint returns HTTP 403. The adapter reports the failed endpoint and stops. [Ruleset visibility](https://docs.github.com/en/rest/repos/rules?apiVersion=2022-11-28)

```sh
python -I safe_push/forge.py audit --enrollment /protected/forge.json --token-file /protected/github-read
python -I safe_push/forge.py check-run --enrollment /protected/forge.json --token-file /protected/github-read --receiver /protected/receiver/config.json
python -I safe_push/forge.py mirror --enrollment /protected/forge.json --token-file /protected/github-read --receiver /protected/receiver/config.json
python -I safe_push/forge.py confirm --enrollment /protected/forge.json --token-file /protected/github-read --receiver /protected/receiver/config.json
```

The mirror workflow needs the candidate on a staging ref so the host can read its immutable commit before publication. `check-run` requires a current signed `ocs-release/1` receiver receipt with a verified local consumer, the exact parent and tree and a protected hosted parent. After the independent checking App reports the proposed completed success, `mirror` requires that same App, SHA and receipt identifier in the hosted readback. Its proposal uses the explicit `--force-with-lease=refs/heads/main:<parent>` and the exact certified direct child. Reacquire the preflight immediately before an authorized publication and run `confirm` afterward. Preserve the authenticated hosted response and the local signed receipt. [Check runs](https://docs.github.com/en/rest/checks/runs?apiVersion=2022-11-28) · [Explicit Git lease](https://git-scm.com/docs/git-push)

In pull-request mode, add `--event pull_request` or `--event merge_group`, `--payload <raw-delivery>`, `--signature-file <received-signature-header>` and `--webhook-secret <protected-secret>` to `check-run`. Preserve the exact delivered bytes. The adapter validates the webhook HMAC, App installation, repository, live PR or queued ref, a single direct parent and the candidate's exact hosted Git tree. A synthetic two-parent integration commit, a changed queue head or a newly constructed squash commit requires independent qualification of the real publishable object. A check proposal certifies its named immutable SHA. Confirmation requires the same SHA at the actual hosted branch. [Webhook HMAC](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries) · [Merge-group events](https://docs.github.com/en/webhooks/webhook-events-and-payloads#merge_group)

The host accepts neutral or skipped outcomes for certain required checks. The independent publisher must issue success only for the exact current release receipt and use its own App credentials. Registering a name or a workflow under contributor control leaves this custody requirement open. The adapter refuses neutral, skipped, cancelled, pending, colliding and foreign-source check results. Repo administration, App key custody, host enforcement and webhook delivery remain operational trust assumptions. Run `python -m unittest safe_push.test_forge` for isolated controls. Claims about a specific hosted installation additionally require its real administrative readback and approved positive and negative ref experiments. [Required-check semantics](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)


## Verify a frozen enrollment

When the default is a review branch and `main` is absent, enroll the following separate read-only scope. All values below are synthetic.

```json
{
  "format": "ocs.safe-push.forge-hold/1",
  "repository": "fixture/project",
  "repositoryId": 42,
  "ownerId": 10,
  "expectedVisibility": "public",
  "stagingRef": "refs/heads/review/proposal",
  "stagingCommit": "5555555555555555555555555555555555555555",
  "holdRulesetId": 103
}
```

```sh
python -I safe_push/forge.py audit-hold --enrollment /protected/hold.json --gh-read
```

The readback verifies the exact default review branch, its immutable commit, a successful reference listing with no exact `refs/heads/main`, and the registered hold's effective rules and visible empty bypass list. The active rule is named `OCS main enrollment hold` and requires creation, update, deletion and non-fast-forward restrictions specifically on `refs/heads/main`. The result is `frozen-no-main`. Operational release acceptance has its own evidence and App custody. [Active rules for a branch](https://docs.github.com/en/rest/repos/rules) · [Matching refs](https://docs.github.com/en/rest/git/refs)

`--gh-read` selects the active `github.com` account from the installed CLI's keyring. Its administrative reads use GET on registered verification routes, with bounds on response size and elapsed time. For a version-managed installation, add `--gh-executable /absolute/installed/path/gh`. The resolved executable and its path must be owned by the operator or system and outside contributor-controlled repositories. A caller may instead select an explicit `--token-file`. Bootstrap still requires the two separate App JWTs for installation readback.

## Initial canonical ref in mirror mode

Version 2 supports a first publication of the independently enrolled, currently qualified local genesis. The normal single-parent transition follows once the canonical branch exists. For initial creation, the `bootstrap` object contains the exact `stagingRef`, `stagingCommit`, `genesis`, `holdRulesetId`, `integrityRulesetId`, `writerRulesetId` and `publisherInstallationId`. Obtain server-assigned rule IDs independently. The checking App, its installation, and the distinct publishing App are registered in the surrounding enrollment.

1. Keep the initial hold active. Use `bootstrap-rules` to generate the two permanent mirror guards. It accepts a v2 mirror enrollment with `"bootstrap":null` before their rule IDs exist. Independently install and read them back. Integrity has no bypass and applies the pinned App check to branch creation. The writer rule restricts both creation and update to the sole publishing App. Capture the real guard IDs in the final enrollment.
2. Run `bootstrap-context` with the final enrollment, current receiver, read credential, and each App's independently sourced JWT. The readback verifies installation owner, identity, suspension and relevant permissions. The receiver must be at its enrolled release genesis with zero subsequent transitions. The adapter rechecks the full target dossiers, original evidence levels, metric populations, enrollment and comparable verifier-cost baseline. Elapsed qualification, outstanding obligations or an experiment-profile seed keep the hold in effect. [App installation API](https://docs.github.com/en/rest/apps/apps#get-a-repository-installation-for-the-authenticated-app)
3. The domain, independent reviewer, guardian and publisher separately sign the exact returned context extended with `issuedAt` and `expiresAt` within its evidence window. A quorum envelope contains that `payload` and a `signatures` map, with each signature over the payload plus its own `role`. Supply it using `--authorization`. `bootstrap-check` produces a check-run proposal on the enrolled genesis for the independently operated App.
4. After the App reports the completed success, acquire `bootstrap-handoff` while the original hold and both permanent guards are active. Sign the resulting context with the same four roles and a current time window. It binds the actual check ID and completion time, the exact genesis authorization and the original versions of all three overlapping constraints.
5. Under separate administrative authorization, disable and retain the initial hold. The two permanent guards continue enforcing their original rules. `bootstrap-create` requires the full current evidence and `--handoff`. It checks the provider's complete version history for the original active hold followed by its disabled state, unchanged permanent guard versions that predate the handoff, both authentic App installations, the same completed check and the continued absence of `main`. A deleted hold, unseen version, reordered change, hidden bypass, missing history or ambiguous clock order keeps creation pending. [Ruleset history API](https://docs.github.com/en/rest/repos/rules#get-repository-ruleset-history)
6. The authorized sole publisher applies the exact returned command. An empty expected ref in `--force-with-lease=refs/heads/main:` enforces absent-to-genesis compare-and-swap. Confirm the actual remote object with `bootstrap-confirm`. Install the final additional zero-bypass `OCS canonical creation closed` rule from `rules` while retaining the two permanent guards, switch the default to `main`, and run `audit`. `bootstrap-confirm` identifies the observed default and whether the final closure was verified. [Explicit empty Git lease](https://git-scm.com/docs/git-push)

The bootstrap commands share `--enrollment`, `--receiver`, `--token-file`, `--check-app-jwt` and `--publisher-app-jwt`. The stage that prints a signable context supplies no private signing operation. The administrative rules change and actual check publication remain with their separately authorized custodians. If the platform cannot provide the required historical or current readbacks, the pending scope identifies the missing prerequisite. The hosted API fixture exercises these states separately from any claim about a live installation.
