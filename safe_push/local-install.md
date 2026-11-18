# Native Linux receiver

A system administrator installs the selected receiver commit, its evidence policy and its independently enrolled proof tools. Git clients reach a private Unix socket. Each Git connection runs as the locked system account `ocs-sp-INSTANCE`. Independently registered methods run behind a second private Unix socket under the separate locked account `ocs-me-INSTANCE`. Installation, activation and acceptance are separate commands.

## Inputs and installation

Select a full implementation commit containing the native installer, a local Git object store, an existing client group and the publisher key matching the enrolled policy. Keep the selected installer in administrative custody. It verifies its own bytes against the selected release before installing the runtime.

Choose one proof-tool source. `--lean-archive` verifies the entire distribution archive against the enrolled platform SHA-256 and then checks each named executable and library. For an existing installation, the tool below produces the whole-tree identity used by `--lean-home`. The administrator independently verifies and enrolls that identity. It includes relative paths, regular-file contents, executable bits and relative link targets for every library, tool and other distribution file.

```sh
python3 -I -B safe_push/local_install.py lean-digest "$LEAN_HOME"
```

Bootstrap a new authority with the previously selected policy and qualification evidence.

```sh
sudo python3 -I -B safe_push/local_install.py install \
  --instance "$INSTANCE" --client-group "$CLIENT_GROUP" \
  --source "$OCS_REPO" --revision "$RECEIVER_COMMIT" \
  --lean-archive "$LEAN_ARCHIVE" \
  --policy "$POLICY" --evidence "$GENESIS_EVIDENCE" \
  --publisher-key "$PUBLISHER_KEY" --observer-key "$OBSERVER_PUB"
```

Repeat `--method FILE` and `--observer-key FILE` for the independently enrolled methods and keys required by the policy. Supply `--cost-baseline FILE` when the enrolled receiver-cost policy names an independent baseline. Bootstrap runs the selected receiver’s operator installer as the dedicated unprivileged service account against private copies of its inputs.

An existing prepared receiver can be imported with its original authority, evidence, journal, Git objects, signing material and monotonic checkpoint. The importing administrator selects the exact configuration checksum. The copy holds the source publication lock. It reconstructs the destination’s protected Git configuration and hooks and verifies the actual ref. The prior installation retains its ref format. If the fresh source has no publication lock yet, the importer creates the coordination inode with the source journal owner.

```sh
sudo python3 -I -B safe_push/local_install.py prepare \
  --instance "$INSTANCE" --client-group "$CLIENT_GROUP" \
  --source "$OCS_REPO" --revision "$RECEIVER_COMMIT" \
  --config "$PREPARED_CONFIG" --config-sha256 "$PREPARED_CONFIG_SHA256" \
  --lean-home "$LEAN_HOME" --lean-tree-sha256 "$ENROLLED_LEAN_SHA256"
```

For both installation modes, the receiver verifies the immutable runtime tree, proof distribution, publishing-key identity, current epoch and signed chain before reporting its local initial readback. The state directory must be new. Installation emits the paths, actual initial tip and hashes of the installed service units. A failed installation removes its newly allocated private files. Previously allocated dedicated accounts can be reused when their identity and group isolation still satisfy the checks. The installation binds both UIDs and the evaluator socket in the administrator-owned `state/authority/broker.json`.

## Activation and readback

Use a non-root member of the enrolled client group for transport acceptance. Activation starts both socket units. The receiver checks that this client cannot access its private state or the private evaluator endpoint. It compares a real Git read with the signed-chain readback, then runs the four-frame status exercise through the evaluator socket. Add `--enable` to start both sockets at boot.

```sh
sudo python3 -I -B safe_push/local_install.py activate --instance "$INSTANCE" --caller "$CALLER"
sudo python3 -I -B safe_push/local_install.py verify --instance "$INSTANCE" --caller "$CALLER"
```

The result includes the standard remote URL in `url`. Configure the remote once in the working repository. The push refspec selects the current local commit for the receiver’s main branch.

```sh
git remote add safe-push "ocs::$INSTANCE"
git config remote.safe-push.push HEAD:refs/heads/main
git ls-remote safe-push refs/heads/main
git push safe-push
```

Git discovers the administrator-installed `git-remote-ocs` on the client’s `PATH`. The helper accepts the enrolled instance name, negotiates `connect` and carries the ordinary upload-pack or receive-pack stream over its private Unix socket. [Git remote helper protocol](https://git-scm.com/docs/gitremote-helpers)

Existing `ext::` integrations can use the `legacyUrl` readback and authorize the transport for their individual command. The new standard URL works with the default Git protocol policy.

The system administrator runs future custody and evidence commands with the installed `release/safe_push/operator_cli.py`, Python `-I -B` and the installed `state/receiver.json`. Active receivers use their installed code and data. Published transitions can be audited with the installed `receiver.py audit` or validated for current use with `receiver.py consume`.

| Path under `/var/lib/ocs-safe-push/INSTANCE` | Custody |
| --- | --- |
| `release/` and `lean/` | Root owns the selected immutable implementation and complete proof distribution. |
| `state/authority/`, `state/witness/`, `state/hooks/`, Git configuration and installed seals | Root administers the policy, epoch floor, evidence and hooks. The receiver can read them. |
| `state/publishing/` | Root owns the key. The dedicated publisher group alone has ordinary read access. |
| `state/repository.git/objects/`, `state/repository.git/reftable/` and `state/journal/` | The publisher can record Git objects, refs, reflogs and publication receipts. Git object alternates remain administratively protected. |

The private socket is `/run/ocs-safe-push/INSTANCE.sock`, owned by root and the client group with mode `0660`. The per-instance client program lives at `/usr/local/libexec/ocs-safe-push/INSTANCE/socket_client.py`. Instances share a root-owned dispatcher at `/usr/local/bin/git-remote-ocs`. The installer reuses an existing dispatcher only when its bytes match the independently selected release and its permissions protect it. A conflicting existing executable stops provisioning. The systemd connection service has a private network, private temporary files, an empty capability set, a read-only host filesystem and explicit writable state directories. Git must support the reftable backend and offline migration. Its references and reflogs fit in a writable subdirectory of a read-only bare root.

The evaluator listens on `/run/ocs-safe-push-method/INSTANCE.sock` with mode `0660` and the publisher’s group. The server authenticates the connecting publisher or administrator through the kernel. The client authenticates the responding evaluator UID and binds the reply to its exact request. Only the systemd evaluator connection has supplementary membership in the publisher group. Its mount namespace exposes the public Git object store read-only. An empty, read-only authority mount receives four explicit bindings for the root policy, broker metadata, installed method programs and signed rotations. Reviews, evidence bundles, acquisition records, adverse observations and future authority directories remain on the publisher side. The evaluator receives only the specific serialized evidence operands for its method call. The signing key directory, journal, epoch checkpoint and hooks are inaccessible inside the evaluator namespace. The complete state is read-only. The evaluator receives its connected socket directly from systemd.

The evaluator has its own process and network namespaces, an empty capability set, no privilege elevation and temporary filesystems with `nosuid,nodev,noexec`. The host runtime socket directory and shared-memory filesystem are also isolated. Each connection has a 1 GiB memory ceiling, up to 128 tasks, 200% CPU quota and a 180-second lifetime. The socket permits eight concurrent connections. Inside the evaluator, the independently selected adapter receives a further isolated namespace with its specific read-only inputs. The four-frame status adapter runs the candidate executor inside another isolated namespace with two public fixture files.

Activation’s `methodEvaluator` result records the actual evaluator UID, scoped status results and measured wire bytes, plus checks of private key, journal, checkpoint and reference-write access. The diagnostic is independently identifiable as `diagnosticOnly`. Ordinary release decisions use their enrolled target and proof receipts. The native tests also submit an ordinary registered method, attempt actual canary reads and a reference-directory write in a disposable service, and exercise the kernel’s rejection of a foreign publisher UID.

System administrators and the independently selected verifier programs form part of the trust boundary. A caller with separate host administrative privileges can exercise those privileges independently of Git client access.

The native installer targets Linux with systemd supporting private PID namespaces and per-connection socket activation, unprivileged nested user namespaces, Bubblewrap, an enrolled Lean platform, Git with reftable, Python, OpenSSL and the local account administration utilities. The `test_local_install.py` suite checks the unit configuration, complete library identity, signed-state migration a real ref update from a separate Unix UID, and ordinary Git push and readback over a temporary Unix socket with the external-command transport disabled. Actual activation and client readback remain specific to the selected machine.
