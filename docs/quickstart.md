# Your first component

The example runs on a POSIX development system with Python 3.11+ and Go 1.22+. Commands below run from the root of the checkout. No account or network service is used by the demo.

```sh
make demo
```

The application asks for the condition of resource `demo`. The host finds the package at [examples/status/ocs.json](../examples/status/ocs.json), starts the reviewed executor, checks its identity and calls `example.status.read`. The response is `{"resourceId":"demo","state":"ready"}`. Inspect the manifest to see the input, output and effect.

To use the second host implementation and run the development tests, install the Python dependencies with `uv sync --locked`. Initial dependency installation may need network access. With the cache populated, `uv sync --locked --offline` works. The following commands exercise both hosts and build the example archive.

```sh
uv run --locked python reference/host.py --manifest examples/status/ocs.json --resource demo
make check
make package
```

Change the fixture's state from `ready` to `degraded` in a disposable copy. The response changes without a host rebuild. Changing it to an undeclared state must fail output validation. Each development host has an explicit policy for this example. A different operation requires its own binding and grant. To debug selection, inspect the manifest ID, contract version, effect and the host's policy. To debug execution, inspect the JSON error kind and pointer.

For a new integration, start with one read operation, then add only the profiles its users need. Keep deployment addresses and secrets out of portable identity. Develop against a fixture with a known input and result. The [composition rules](../spec/composition.md) apply unchanged when an application exports a public operation backed by several components.
