# DoofusAI SPM on Kubernetes

Authored by Aniza Inc.

## Deploy to a qualification namespace

1. Select a cluster with at least two schedulable hosts eligible for the same CSI volume. Confirm the CSI driver supports `ReadWriteOncePod`, can fence a failed node, and can reattach the filesystem on another eligible host. Use a block-backed filesystem with POSIX file locking. Set the StatefulSet claim template's storage class in an environment overlay if the cluster default does not meet these requirements.
2. Build from the repository root with `docker build -t "$IMAGE" spm` and push to the authorized registry. Reference the published image by digest in the overlay using Kustomize `images`. Add the namespace and storage settings there. The base image contains Python and OpenSSL. Include the provider CLI or SDK required by each connector that will run in the deployed environment, and configure that connector's approved identity. Run database-backed collectors in the storage-owning pod. Reserve the PVC for the StatefulSet.
3. Configure an HTTPS ingress controller or authenticated reverse proxy for the `doofusai-spm` service on port 8000. Apply the label `doofusai-spm-ingress=allowed` to the dedicated ingress namespace and verify your network plugin enforces NetworkPolicy. Create the optional `doofusai-spm-config` Secret in the application namespace with `issuer.json` for federation and `metrics.token` for authenticated scraping. Distribute tokens through your approved secret manager. The [enterprise operations guide](../../ENTERPRISE-OPERATIONS.md) describes the issuer format and identity mapping.
4. Render and review the environment overlay with `kubectl kustomize "$OVERLAY"`, then apply it to the designated cluster using `kubectl --context "$CONTEXT" apply -k "$OVERLAY"`. Run `kubectl --context "$CONTEXT" -n "$NAMESPACE" rollout status statefulset/doofusai-spm`. Check the pod's node, the bound PVC and the HTTPS health endpoint. Confirm protected endpoints reject unauthenticated requests.

Keep the StatefulSet at one replica. Kubernetes limits the claim to one pod, and the service takes an exclusive writer lock beside the database. Maintain tested off-volume backups for storage loss. Use the [restore procedure](../../ENTERPRISE-OPERATIONS.md) to qualify recovery from those backups separately.

## Measure recovery to another host

1. Record an existing canary assessment ID. With a short-lived project administrator credential, save the `boot_id`, `node` and `stream_id` from `GET /api/v1/instance` on the HTTPS origin. Pass the same credential as `SPM_QUALIFICATION_TOKEN` for the observer. Make sure its lifetime covers the planned exercise.
2. Start the observer at incident onset. Start from the `spm` directory.

   ```sh
   python3 tools/qualify.py observe-reschedule "$SPM_ORIGIN" \
     --previous-boot "$BOOT" --previous-node "$NODE" --stream "$STREAM" \
     --known-scan "$CANARY_SCAN" --rto-seconds "$RTO_SECONDS"
   ```

3. Exercise controlled host evacuation and actual host outage separately in the designated cluster. For an unreachable host, rely on the platform storage fencing procedure and confirm the old process cannot write before intervening with pod or volume attachment state. The observer requires a changed node and boot identity, the same persisted stream, and successful readback of the assessment. Retain the observer result and cluster events for the measured outage window.
4. Exercise cloud connectors and federation with the qualification tool from the [add-on guide](../../ADDONS.md), then run representative load and document achieved throughput, latency, error rates, and recovery times. A successful reschedule demonstrates recovery from a surviving volume. Document recovery from volume loss with a separate timed restore.

[Kubernetes single-pod volume access](https://kubernetes.io/docs/tasks/administer-cluster/change-pv-access-mode-readwriteoncepod/) · [StatefulSet pod deletion and fencing guidance](https://kubernetes.io/docs/tasks/run-application/force-delete-stateful-set-pod/)
