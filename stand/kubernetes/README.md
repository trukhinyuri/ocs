# Run the qualification workload on Kubernetes

The stand has one persistent provider writer, a separate restricted inference relay, a loopback interaction executor alongside the provider, and an independent in-cluster client Job. A namespaced ClusterIP serves HTTPS. The controller also drives a real browser at narrow width and increased font size. It observes the workload before and after replacement of its owned pod and verifies a separately restored SQLite backup. The workload's published model, account terms and reset right belong to this deployed service. CPU, host, network, storage and outside provider charges belong to their respective operators.

The [workload policy](policy.json) fixes the sample size, concurrency, effective budget, quality threshold, recovery bound and observation lifetime. The model's [held-out task](../../assurance/provider/criteria.json) is distinct from its training examples. Compare direct inference with a separately authenticated relay forwarding full admissible history or only required facts. The observer records actual pod identities and application payload bytes. TLS framing and general network overhead require separate measurement.

## Dedicated local cluster

Use a Linux host with a working container engine, `kubectl`, `openssl` and the repository's locked Python environment. The local installer runs a pinned Kubernetes distribution in a dedicated isolated node. It binds the API to `127.0.0.1:16443`, keeps cluster data in a dedicated named volume and exports a private kubeconfig under the user's state directory. The workstation's normal kubeconfig and context remain available.

```sh
uv sync --locked
python3 stand/kubernetes/local.py --verify-latest --ensure-boot
uv run --locked python stand/kubernetes/deploy.py --local
make qualify
```

`--verify-latest` compares the reviewed local image with the upstream stable Kubernetes release. Update the image pin through review when upstream advances. For boot persistence the host's container engine must be enabled at boot. On this local stand the engine's system service is enabled and the node has restart policy `always`. Verify a real supervised crash on the dedicated node with the following opt-in command. It checks ownership and refuses a control-plane interruption when unrelated pods are present.

```sh
uv run --locked python stand/kubernetes/restart_check.py --local-owned-node \
  --report out/kubernetes/node-recovery.json
```

## Existing local or remote cluster

Build the image for the cluster's Linux architectures using the [pinned build recipe](Dockerfile). Supply an image accessible to the intended nodes by its immutable OCI digest. The same workload and acceptance client apply to a local context or a remotely administered cluster. The operator chooses the registry, permissions and publishing procedure. A remote kubeconfig and context select that cluster explicitly. Use a dedicated namespace and a storage class providing a filesystem-backed ReadWriteOnce PVC with the durability semantics required by SQLite.

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -f stand/kubernetes/Dockerfile -t "$OCS_REGISTRY_TAG" --output type=oci,dest=out/ocs-image.tar .
uv run --locked python stand/kubernetes/deploy.py \
  --kubeconfig "$OCS_KUBECONFIG" --context "$OCS_CONTEXT" \
  --namespace "$OCS_NAMESPACE" --image "$OCS_IMAGE"
make qualify OCS_KUBECONFIG="$OCS_KUBECONFIG" OCS_CONTEXT="$OCS_CONTEXT" \
  OCS_NAMESPACE="$OCS_NAMESPACE" OCS_IMAGE="$OCS_IMAGE"
```

The deployer needs permission to manage the named Services, Deployments, Job, PVC and stand-owned Secret. Preprovision the namespace with label `app.kubernetes.io/part-of=ocs-qualification` or allow the deployer to create it. The observer reads the cluster identity, namespace, Services, replica owner chain, pod/image status, storage and the qualification credentials. It reads the scheduled node architecture to validate the immutable OCI index and obtains its child manifest or configuration digest. It requires logs, exec, port-forward and UID-preconditioned deletion of the owned workload pod. It leaves unrelated workloads alone. External clusters keep their existing control-plane supervision.

The workload runs as an unprivileged account, with bounded resources, a read-only root filesystem and no mounted Kubernetes service account token. Server, relay and client credential projections are separate. On renewal, the deployer preserves scoped bearer identities and restarts the owned endpoints on the new certificate pin. Kubeconfigs, CA private keys, bearer tokens and observer signing keys stay outside Git and public evidence.

The provider and relay each serve at most four concurrent HTTPS requests. When a health check or new request reaches a busy listener, the listener waits for a worker within the original connection deadline. The handshake and response share the time left in that budget.

For an isolated transport diagnosis run `stand/kubernetes/observe.py --help`. The complete acceptance uses the frozen observer and verifies each required observation. The diagnostic option that omits the browser leaves its obligation open.

A registry-isolated operator can supply a trusted bundle of raw OCI manifest bytes with `--oci-proof FILE` during deployment or `OCS_OCI_PROOF=FILE` for full qualification. Each base64-encoded blob is keyed by its SHA-256; the verifier resolves child manifests from the separately selected root digest. Without a bundle the deployer reads the pinned registry digest using the build client.
