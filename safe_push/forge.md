# Hosted repository adapter

`forge.py` reads a private GitHub repository and the independently administered local receiver. Its network requests use GET. Successful proposal commands print the exact proposed check run or leased Git push as JSON for an independently authorized publisher. Only `confirm` reports a verified hosted transition, after observing the exact object at the protected ref.

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
