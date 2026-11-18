# Maintain one provider adapter

A provider package translates an upstream service into scoped contracts. A host owns account selection, secret custody, the operation grant and the user’s current route. The presentation reads the same projections as the CLI or automation. Adding a provider means adding a package and its fixtures. The host can discover it without a provider-specific settings page.

## Start with an account and one answer

1. Implement `provider.describe` for the exact product. Declare supported credential flows, routes and available operations. Give the host a stable label for each choice.
2. Bind a connection explicitly to the intended account. Keep keys and OAuth tokens in the credential broker. Test denial, expiry and renewal using synthetic responses.
3. Declare the operation that actually delivers value. Pin the account, route, model and parameters for any health probe. A working probe on another route belongs to that other route.
4. Add account observations, limits, prices and catalogs independently. Unsupported facts have a visible state. Preserve allowable operation when one observation endpoint fails.

| Question on an account row | Fact to show | What a user can do |
|---|---|---|
| Can I use this account now? | Enabled, sign-in state, entitlement, last verified reply and actual route | Connect, reconnect or change local routing |
| How many usable requests remain? | Limiting window, amount or percent, shared pool, next reset and last observation | Refresh or inspect independent windows |
| Can I reset a window now? | Verified reset right, remaining credits, target, expiry and price | Review and commit a supported reset, or open the verified management link |
| What am I paying for? | Plan, billing basis, region, currency, period, source and checked time | Inspect published or account-specific terms |
| Is this subscription useful? | Successful work, probes, fallback uses, last use and alternative routes for this model | Review the impact on the last route before disabling it |
| Are the models current? | Official catalog, account entitlement, mapped parameters and actual verification for each mode | Examine new unsupported options, an EOL notice or a compatible replacement |

Group accounts by provider and show enabled, usable and attention-needed counts on the overview. Keep the common read path visible before details. Counts over partial inventories need a scope and a completeness indication. A failed refresh preserves the last successful observation with its age.

## Handle upstream changes

Capture representative successful and denied replies as redacted, synthetic records. Replay them through the mapping layer, then check exported operations as a client. A changed response field should break the affected mapping test while unrelated providers still pass. Add a paginated catalog case with an incomplete final page, a shared quota, an expired login, an unknown price, an advertised but unsupported option and a charged reset with uncertain outcome. Live checks state which account and route they actually used and what they cost.

When a provider announces a new model, compare complete snapshots for the same scope, retain explicit user selection and check the adapter’s protocol support. Discovery can reveal the name immediately. A verified reply requires that model and those parameters. Preserve aliases and official notices with observation times. Treat disappearance without an official notice as an observation requiring investigation.

See the [provider rules](../spec/profiles/providers.md), [operation registry](../spec/profiles/operations.json), [reset fixture](../examples/reset/) and [example account records](../examples/records/).
