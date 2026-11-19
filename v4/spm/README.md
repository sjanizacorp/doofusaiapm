# DoofusAI SPM
Authored by Aniza Inc

A project-scoped AI security posture service with a browser console, direct platform collection, additional read-only agents, assessments, access evidence, classification, and release/runtime policies. Use Python 3.13 for the tested release environment.

For the complete architecture, platform coverage, enterprise use cases and deployment instructions, see the [product overview](../README.md).

Run the following from this directory to create an account and start the service.

```sh
python3 app.py set-local-user ModelOps alex.smith admin
python3 app.py serve
```

Open http://127.0.0.1:8000 on the service host and sign in with that username and password. Organization sign-in through Entra ID or AD FS requires provider configuration and project mappings.

Use **Connections** to configure platform targets, select a server credential profile, test access and run scans. Use **Agents** to configure additional collectors and recurring collection. Provider tools and read-only permissions are required where collection runs.

Use --db PATH before a subcommand to select the database. Protect backups and verify restoration separately. The shell controls in the parent directory support installation, start, stop, status, and uninstall.

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

- [Administration guide](../manuals/doofusai-spm-v4-administration.pdf)
- [User guide](../manuals/doofusai-spm-v4-user-guide.pdf)
- [Configuration guide](../manuals/doofusai-spm-v4-configuration.pdf)
- [Enterprise capability roadmap](../ENTERPRISE-ROADMAP.md)

## Extended capabilities

The [enterprise operations guide](ENTERPRISE-OPERATIONS.md) covers relationship-based prioritization, issue exceptions, runtime finding intake, security-event export, artifact verification, federation, monitoring, and recovery.

The [cloud, runtime, and qualification add-ons guide](ADDONS.md) covers Google AI discovery, imported sensitivity labels, inline screening, external scanner verdicts, and load and recovery commands.

The [Kubernetes operations guide](deploy/kubernetes/README.md) covers single-writer deployment and node recovery qualification. See the [add-on guide](ADDONS.md) for deployment behavior checks and Google Cloud Storage permission reviews.

See the [Oracle Cloud, IBM Cloud, and Salesforce connector procedures](ADDONS.md#collect-oracle-cloud-ibm-cloud-and-salesforce-inventory) for setup, collection, and staging verification.

The [platform-local agent deployment guide](ADDONS.md#deploy-and-run-platform-local-collection-agents) covers console enrollment, CLI installation, provider prerequisites, and on-demand collection.

## Browser sign-in

Create a local username/password account with `python3 app.py set-local-user ModelOps alex.smith admin`. The CLI asks for the password without echoing it. In the browser, enter that username and password and choose **Sign in**.

Organization sign-in supports an Entra ID tenant or AD FS OIDC provider using `serve --sso-config sso.json`. Install `requirements-sso.txt`, register the HTTPS application root as the redirect URI, and map each authorized subject to a project using `map-identity`. See the distribution's OPERATOR-REFERENCE.md for examples and a live-tenant verification checklist.
