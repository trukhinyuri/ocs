# Isolated POSIX resource cell

The reference service exposes a tenant-scoped resource through OCS. It stores desired bytes, revision, materialization and write ownership in a local SQLite database. Materialization atomically installs a POSIX file. Observation reads the actual contents and compares them with the authoritative revision. An accepted request is pending until the file exists at the expected contents. A missing or changed file produces a degraded observation.

The operator configures a bearer-to-tenant map in `OCS_CELL_IDENTITIES`, a separately protected snapshot trust key, and an explicit peer map. Each logical writer receives its own identity. Negotiation pins both its connection and owner epoch. A write rechecks identity and epoch inside the storage transaction. Cutover advances the epoch, closes its retired handles and preserves the desired state. A resource retirement leaves an explicitly recoverable tombstone. Restore verifies scope, signature, length, digest, expected destination revision and available capacity before switching state.

```sh
uv run --locked python reference/platform/server.py --directory /path/to/cell \
  --trust-key /path/to/local-snapshot-key --peers /path/to/peer-config.json --port 17481
```

The listener accepts numeric loopback connections only. The peer configuration maps each admitted peer name to an endpoint, a dedicated scoped read token and the appropriate tenant. Import and export decisions belong to their respective cells. Peer tokens cannot perform resource writes, issue grants or change another cell's writer. A stopped peer leaves local observation available. Readback of an uncertain remote operation preserves the same operation ID until the owner obtains new evidence.

The native descriptor describes the running POSIX architecture, pointer ABI, owner, confinement and handle lifetime. The host obtains a real read-only file descriptor and exposes a scoped handle for `pread`. A package asking for an incompatible ABI, stronger confinement or a hard timing bound receives a refusal. Resources and handles have finite owner and cell limits. The comparison with a direct native file read uses the same bytes, warm data and tenant distribution.

The workload and reports are described in the [platform acceptance guide](../../assurance/platform/README.md). The service and its public descriptor are deployed from the complete reviewed checkout with the edition's schemas. Use the released snapshot and code identity when making a deployment claim.

For the scoped peer fixture, `--peer-credentials-stdin` obtains its outbound credential once from a private process pipe during startup. The public topology contains only the exact endpoint and tenant. The parent provisions the same permitted peer after a restart. An altered endpoint, an altered tenant or an inline credential override is refused. Previously supplied operator bindings remain supported by the existing startup mode. [Credential and restart controls](../../conformance/test_platform_reference.py)
