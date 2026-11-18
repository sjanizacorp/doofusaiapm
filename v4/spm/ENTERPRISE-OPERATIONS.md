# DoofusAI SPM enterprise capabilities and operating procedures

Authored by Aniza Inc

## Relationships, risk, and exceptions

Create inventory with an operator or administrator token. An existing assessed asset can link to one graph node. Other nodes may use `asset: null`. Create every node before posting its edges.

| Request | JSON body |
|---|---|
| `POST /api/v1/graph/nodes` | `{"id":"public-endpoint","kind":"endpoint","asset":null,"criticality":"high","public":true}` |
| `POST /api/v1/graph/nodes` | `{"id":"model-a","kind":"model","asset":null,"criticality":"high","public":false}` |
| `POST /api/v1/graph/nodes` | `{"id":"serving-role","kind":"identity","asset":null,"criticality":"medium","public":false}` |
| `POST /api/v1/graph/nodes` | `{"id":"training-data","kind":"data","asset":"training-store","criticality":"critical","public":false}` |
| `POST /api/v1/graph/edges` | `{"origin":"public-endpoint","target":"model-a","relation":"serves"}` |
| `POST /api/v1/graph/edges` | `{"origin":"public-endpoint","target":"serving-role","relation":"uses_identity"}` |
| `POST /api/v1/graph/edges` | `{"origin":"model-a","target":"training-data","relation":"reads_data"}` |
| `POST /api/v1/graph/edges` | `{"origin":"serving-role","target":"training-data","relation":"can_access"}` |

Examples assume that `training-store` already exists. To update a node, send its full record with the same ID and kind. Remove a relationship with `DELETE /api/v1/graph/edges` and the same JSON body. Open **Relationships** to inspect the declared graph.

Risk uses the control's existing policy weight, plus criticality (0, 10, 25, or 40), plus 20 points when a directed graph path leads from a declared public endpoint to the issue's linked node. Scores are capped at 100. A missing graph link yields policy-only prioritization. The score uses declared relationships and should not be treated as a verified exposure measurement.

In **Issues**, open the issue history as an administrator to assign an eligible principal or approve an exception. Give the exception a reason and an expiration within 90 days. An active exception moves the issue below unexcepted issues without changing its risk score or open status. Revoke an active exception from the same screen. Exception approvals and revocations are audited. The issue retains its scan history.

- `GET /api/v1/issues/{id}/exceptions` lists recent exception records.
- `POST /api/v1/issues/{id}/exceptions` approves one using `reason` and a zoned ISO 8601 `expires_at`.
- `DELETE /api/v1/issues/{id}/exceptions` revokes it using `{"id":"EXCEPTION_ID"}`.
- The project issue list returns the first 100 prioritized issues for its selected status.

## Runtime metadata intake and security-event export

A trusted integration using an operator or admin token can send normalized metadata to `POST /api/v1/runtime-findings`. Use the integration's stable source and event ID. Create the target node first.

```json
{
  "source": "ApprovedGateway",
  "event_id": "evt-44271",
  "node": "public-endpoint",
  "category": "guardrail_block",
  "severity": "high",
  "observed_at": "2026-11-16T15:40:00Z"
}
```

Categories are `guardrail_block`, `sensitive_data_detection`, `policy_violation`, and `identity_alert`. Severity is `info`, `low`, `medium`, `high`, or `critical`. Keep raw prompts, responses, secrets, and personal data out of metadata. Expect 201 for a new finding, 200 for an exact repeat, and 409 for the same source and ID with changed event facts. The **Runtime findings** tab displays the latest 100 events. The connector does not inspect or intercept live traffic.

An admin can poll `GET /api/v1/security-events?after=0` for a maximum of 500 events per call. Persist `next_after` only after downstream delivery, and continue while `has_more` is true. Track the returned `stream_id` along with the cursor. After a restore promotion, a new stream ID requires replay from cursor zero and reconciliation at the destination. Signing and export are independent of delivery to a particular SIEM.

To produce a verifiable audit batch on the host, use a dedicated RSA key and restrictive file permissions:

```sh
python3 app.py --db ./data/posture.sqlite export-audit \
  "Model Operations" ./audit-0001.signed /secure/audit-private.pem --after 0
python3 app.py verify-audit ./audit-0001.signed /secure/audit-public.pem
```

Use the returned `next_after` for the next batch. Signature verification detects file tampering. The envelope contains encoded audit data and needs encrypted storage, restricted access, and protected transport. The source database's host administrators retain access to the audit records. Retain signed batches outside that host if independent custody is required.

## Model promotion gate

Use a signing process with a dedicated private key and publish the public key to a protected CI configuration. Sign the exact manifest bytes after the artifact is finalized. A schema 1 manifest specifies exactly `schema`, `artifact_id`, lowercase hex `sha256`, and byte `size`. The deployment job supplies the expected artifact ID and trust key independently of the artifact.

```sh
# Trusted release signing environment
openssl dgst -sha256 -sign /secure/release-private.pem \
  -out model.manifest.sig model.manifest.json

# CI validation before promotion
python3 app.py verify-artifact model.bin model.manifest.json model.manifest.sig \
  /trusted/release-public.pem --artifact-id training-model-1
```

Require a successful exit before promotion. Gate the exact immutable bytes or content digest that will be deployed and preserve the output manifest with the release record. Test failure by changing a byte in a disposable fixture. The verifier reads bytes and checks signature, artifact identity, size, and hash. To require an additional structure check, add `--format-policy safetensors` to the same command in trusted CI configuration. The gate accepts the supported dtypes, validates tensor dimensions and range sizes, and rejects duplicate fields, gaps, overlaps, and trailing data. It reads the header without loading tensors or running inference. The header limit is 16 MiB. Valid files that use unsupported dtypes require a policy review before promotion. The structure result does not assess model behavior or detect backdoors.

## Enterprise identity and short-lived tokens

The API accepts RS256 JWT access tokens that follow the RFC 9068 profile. Configure an approved identity provider or identity platform to issue a token for the dedicated DoofusAI API audience, with the `spm:access` scope and a lifetime no greater than 15 minutes. The native browser login form can accept that access token, as can an Authorization bearer header. For a compatible provider, enable the browser device authorization flow below so users can obtain a token without pasting it.

Create a configuration file readable only by authorized host users. Pin public RSA verification keys to the issuer's key IDs. Relative paths resolve from this file.

```json
{
  "issuer": "https://id.example.com",
  "audience": "https://spm.example.com/api",
  "clients": ["approved-portal"],
  "keys": {"issuer-key-2026": "issuer-key-2026.pem"}
}
```

Map an exact issuer and subject to a DoofusAI project, principal, and role. Provider groups and roles are not accepted as authorization assignments. A mapped subject belongs to one project for that issuer.

```sh
python3 app.py map-identity https://id.example.com opaque-subject \
  "Model Operations" Jules operator
python3 app.py serve --issuer-config /etc/doofusai/issuer.json
python3 app.py unmap-identity https://id.example.com opaque-subject
python3 app.py issue "Model Operations" integration operator --ttl-minutes 15
```

### Browser sign-in using device authorization

Configure the approved public OAuth client for the RFC 8628 device grant. The client must be on the issuer allowlist and its authorization server must issue an RFC 9068 access token for the configured audience and `spm:access` scope. Device-client registration and audience settings differ by provider.

Add a `device` object to the existing issuer configuration:

```json
{
  "client_id": "approved-portal",
  "origin": "https://spm.example.com",
  "device_endpoint": "https://id.example.com/oauth/device",
  "token_endpoint": "https://id.example.com/oauth/token",
  "verification_uri": "https://id.example.com/device"
}
```

1. Publish the loopback service through the approved HTTPS proxy at the exact configured origin. Use the provider's actual endpoint URLs. Keep unauthenticated route rate limits at the proxy.
2. Restart the service with `--issuer-config`. Open the configured origin, select **Sign in with your organization**, then open the provider page. Enter or compare the code shown in DoofusAI before approving access.
3. Return to DoofusAI and verify the project, principal, and role. Test denial, an expired attempt, and a user with no local mapping. Use **Cancel sign-in** if you initiated the wrong session.
4. Keep the provider's access token lifetime at 15 minutes or less. The client holds the access token in memory until sign-out or reload. Start another sign-in after expiration.

The flow requires a provider that supports device authorization and returns the configured verification URL. The application keeps pending attempts in memory and discards them on restart. It follows provider polling intervals and backs off on throttling or transport failure. It does not store refresh tokens or implement authorization-code redirects.

Validate identity with `GET /api/v1/me` and test a rejected user before enabling shared access. For key rotation, install the new pinned key alongside the old one, restart with both configured, complete the issuer rotation, and remove the old key after its tokens expire. For a compromised key, remove it immediately and restart. Unmapping a subject denies new requests even if the access token is still valid.

## Single-node deployment, monitoring, and recovery

The included [systemd service](deploy/doofusai-spm.service) runs under a dedicated Linux account named `doofusai`. Install the application files to `/opt/doofusai/spm`, create that service user/group, and install the unit. The database resides at `/var/lib/doofusai/posture.sqlite`. Review the unit against your Linux distribution before enabling it.

```sh
sudo install -m 0644 deploy/doofusai-spm.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now doofusai-spm
curl -fsS http://127.0.0.1:8000/health
```

For federation, use a systemd override to replace `ExecStart` with the same command plus `--issuer-config /etc/doofusai/issuer.json`. The application binds to loopback. Configure your approved HTTPS reverse proxy and enforce request limits, authentication rate limits, and credential-free access logs. Keep the local listener inaccessible from other hosts. Monitor systemd failures and use `GET /health` for service readiness. Project administrators can poll `GET /api/v1/operations` for record counts, schema version, and latest sync result. The unit and external monitoring setup require a deployment check on the intended Linux host.

Recovery drill:

1. Make a fresh backup with `app.py backup` and copy it to approved restricted storage. Record the backup timestamp and identify a known report and issue.
2. Run `python3 app.py verify-backup /path/to/backup.sqlite` on a restore host with the same release. Copy the verified file to a separate recovery database path. Verify that a test service can read the intended project and records.
3. Before promoting a recovery instance, stop or fence the previous writer and stop any temporary listener on the recovery file. Run `python3 app.py --db /path/to/recovery.sqlite promote-recovery`. This validates the database and gives event consumers a new stream ID.
4. Start the service using the recovery path. Verify health, a known prior report, a new write, and the new stream ID. Switch the approved ingress only after those checks pass. Coordinate consumers to replay or reconcile their last snapshot.
5. Record elapsed downtime and any gaps after the backup timestamp. Review restored credentials and identity mappings since a backup can predate a revocation. Keep the old writer fenced until incident closure.

The automated suite exercises a local cold restore with the primary database unavailable, restores an old report, checks the event stream change, and writes a new assessment on the recovery copy. Automatic multi-host failover, replication and measured availability objectives still need infrastructure and a deployment exercise.

[JWT access token profile](https://www.rfc-editor.org/rfc/rfc9068) · [OpenSSL signing and verification](https://docs.openssl.org/3.5/man1/openssl-dgst/)

[OAuth device authorization](https://www.rfc-editor.org/rfc/rfc8628) · [Safetensors format](https://github.com/safetensors/safetensors#format)
