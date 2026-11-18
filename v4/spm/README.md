# DoofusAI SPM
Authored by Aniza Inc

A local, project-scoped posture assessment service for manually recorded AI configuration and discovered Google Cloud Storage bucket settings. Requires macOS or Linux and Python 3.10+ with SQLite. The server listens on loopback.

```sh
cd spm
python3 app.py issue "Model Operations" jules admin
python3 app.py serve
```

Open http://127.0.0.1:8000 and paste the generated token. Treat it as a password. Add an asset and run an assessment. Use Unknown for facts you cannot verify. Asset IDs are visible in project reports and audit records. Keep sensitive content out of IDs.

```sh
python3 -m unittest discover -s tests -v
python3 app.py backup ./posture-backup.sqlite
python3 app.py revoke "Model Operations" jules
```

Use `--db PATH` before any subcommand to select a separate database. Test a backup by pointing a separate loopback instance at a copy on a different port. Backups contain credentials' hashes and assessment data and require restricted storage.

The browser smoke test and manual screenshot workflow use Playwright and Chromium. Run `node tools/capture.cjs /absolute/output/directory` with Playwright resolvable through Node, and set `SPM_CHROME` to a Chromium executable when using a system browser.

The Python service is a clean implementation. The upstream Node application, policy packs, data and credentials require a separately designed migration before adoption. Refer to the [gap register](../GAP-ASSESSMENT.md) for open enterprise requirements.

## Issue tracking and schema upgrade

Open **Issues** to see problems grouped by asset kind and control. **View issue history** shows when a problem opened, recurred, resolved, or was reassessed without the required fact. Each event links to the saved assessment. A passing observation resolves the issue, a later failure reopens it under the same ID, and an unknown observation preserves the previous status.

- `GET /api/v1/issues?status=open` returns open issues for the credential's project. Use `status=resolved` for resolved issues. Each list returns up to 100 entries.
- `GET /api/v1/issues/{id}` returns the issue and its latest 100 observations. A valid token from a different project receives HTTP 404.
- New scan snapshots can include `evidence.recorded_by` and `evidence.recorded_at` for the operator-provided facts. Older snapshots remain readable without these fields. The recorded timestamp describes entry into DoofusAI, and the source remains operator-declared.

On the first start, schema upgrades run within a single transaction. Databases from the original build have their issue history reconstructed from saved scans. Existing scan snapshots remain unchanged. Before upgrading an existing deployment, take a backup with the running version and verify the upgrade against a copy. Roll back by restoring the pre-upgrade backup to a separate database path and starting the previous release against that path.

Project admins can assign or unassign an issue from **View issue history**. Enter the principal name of an administrator or operator with a valid credential in the project. Clear the field to unassign. The API equivalent is `POST /api/v1/issues/{id}/assignment` with `{"assignee":"Casey"}` or `{"assignee":null}`. Changes appear in the project audit log.

New credentials expire after 720 hours by default. Set `--ttl-hours 24` on the issue command to shorten their lifetime. Older credentials survive the schema upgrade with their original lifetime. Revoke and reissue them to adopt expiration.

## Google Cloud Storage connector

1. Create or select the DoofusAI project by issuing its first credential. Install the Google Cloud CLI on the host and set up Application Default Credentials for a dedicated read-only identity. The connector uses the Cloud Storage JSON bucket-list API, which requires `storage.buckets.list` on the source project. Configure a quota project if required by the credential.
2. Run the connector against the same database used by the web server. Use the same Google Cloud project identifier on each run.

   ```sh
   python3 app.py --db ./data/posture.sqlite sync-gcs "Model Operations" YOUR_GCP_PROJECT
   ```

   The command exits successfully after the inventory, assessments, and issue changes have been committed. Inspect **Cloud syncs** for source, time, count, or failure. The same list is available at `GET /api/v1/sync-runs`. Bucket entries show when they were last observed. On a failed sync the prior inventory and issue state are preserved. Buckets absent from a successful full listing are marked no longer discovered. Their prior issues and assessments remain available.
3. Schedule repeat runs with the host scheduler if desired. Use absolute paths to Python, `app.py`, and the database, and run under the service account whose ADC and Google Cloud CLI are available. Keep and monitor the command's exit result. The connector rejects overlapping runs against the same database.
4. Open **Issues** and select an issue's assessment. The source snapshot includes the bucket name, numeric project ID, metadata revision, collection timestamp, and sync ID. Fix settings through the source system when authorized, then sync again. A pass on the applicable check resolves its existing issue.

The connector reads bucket metadata only. The controls evaluate explicit bucket-level public access prevention, uniform bucket-level access, and whether a customer-managed default encryption key is set. They do not evaluate effective organization-level policies, object-level IAM or ACLs, or the encryption of existing objects. A missing default customer-managed key describes key configuration. It does not imply plaintext storage. A run supports up to 5,000 buckets and 40 API pages.

For inventory clients, `GET /api/v1/assets` returns `next_after` when another page is available. Pass that ID in the URL-encoded `after` parameter. Cloud assets include a `source` object and can only be reassessed through the connector. Manual saves or scans targeting those IDs return HTTP 409.

[Bucket list API](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/list) · [Cloud Storage bucket metadata](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets) · [Google authentication for REST](https://docs.cloud.google.com/docs/authentication/rest)

## Documentation

- [Administration guide](../output/pdf/doofusai-spm-administration.pdf)
- [User guide](../output/pdf/doofusai-spm-user-guide.pdf)
- [API guide](../output/pdf/doofusai-spm-api-guide.pdf)
- [Enterprise capability roadmap](../ENTERPRISE-ROADMAP.md)

## Extended capabilities

The [enterprise operations guide](ENTERPRISE-OPERATIONS.md) covers relationship-based prioritization, issue exceptions, runtime finding intake, security-event export, artifact verification, federation, monitoring, and recovery.

The [cloud, runtime, and qualification add-ons guide](ADDONS.md) covers Google AI discovery, imported sensitivity labels, inline screening, external scanner verdicts, and load and recovery commands.

The [Kubernetes operations guide](deploy/kubernetes/README.md) covers single-writer deployment and node recovery qualification. See the [add-on guide](ADDONS.md) for deployment behavior checks and Google Cloud Storage permission reviews.

See the [Oracle Cloud, IBM Cloud, and Salesforce connector procedures](ADDONS.md#collect-oracle-cloud-ibm-cloud-and-salesforce-inventory) for setup, collection, and staging verification.

The [platform-local agent deployment guide](ADDONS.md#deploy-and-run-platform-local-collection-agents) covers console enrollment, CLI installation, provider prerequisites, and on-demand collection.
