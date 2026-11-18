# Cloud inventory, runtime policy, and deployment qualification

Authored by Aniza Inc

## Discover Google AI assets and classification metadata

The Google AI connector uses read-only Application Default Credentials and lists models, prediction endpoints, and Agent Engine reasoning engines in one region per sync. Configure the Google Cloud CLI and a principal with the corresponding list permissions for the source project. For optional Sensitive Data Protection profiles, also grant access to list existing file store data profiles in the selected location. Set up profiling in Google Cloud ahead of time.

```sh
cd spm
python3 app.py --db ./data/posture.sqlite sync-gcs "Model Operations" MY_PROJECT
python3 app.py --db ./data/posture.sqlite sync-vertex "Model Operations" MY_PROJECT us-central1 \
  --profile-location global
```

Use the same Google project identifier for both connectors so storage issues can link to discovered AI metadata. Add `--quota-project` when required for your Application Default Credentials. Omit `--profile-location` if the deployment has no profiles. Treat HTTP permission failures as missing coverage and fix the connector's authorized setup before retrying.

- Open **Cloud syncs** to confirm the run or inspect failure details. A failed run preserves the last complete inventory.
- Open **Relationships** and select the discovered scope. The component inventory shows endpoints, model deployments, explicit service accounts, agents, and referenced storage. Inspect the same data with `GET /api/v1/cloud-graph?scope=MY_PROJECT%3Aus-central1`. This is an infrastructure-level inventory. A dependency or package bill of materials is outside this collector's scope.
- Open **Issues** to review endpoint networking findings and their sources. DoofusAI evaluates the endpoint's network configuration. A public endpoint can still require authenticated calls, and this check does not prove internet reachability or effective IAM.
- The connector imports sensitivity labels and profile timestamps from existing Cloud Storage profiles. It never reads objects or copies sample findings. A profile up to 30 days old can add 20 points for high sensitivity or 10 for moderate sensitivity. A linked path from a public-network-configured endpoint can add 20 exposure points. These are prioritization signals, not a proof of data access or classification coverage.
- Change an authorized test endpoint's private networking configuration and run the connector again. A passing check resolves the previous issue under the same ID. The prior report remains available. If a resource disappears from a successful listing, DoofusAI marks the endpoint inactive and preserves its history.

[Google AI API](https://docs.cloud.google.com/gemini-enterprise-agent-platform/reference/rest) · [Endpoint types](https://docs.cloud.google.com/gemini-enterprise-agent-platform/machine-learning/predictions/choose-endpoint-type) · [File store profiles](https://docs.cloud.google.com/sensitive-data-protection/docs/reference/rest/v2/projects.locations.fileStoreDataProfiles/list)

## Screen application inputs and outputs inline

Call the authenticated `POST /api/v1/runtime/inspect` endpoint from your application immediately before sending content to a model or returning it to an end user. Issue a short-lived, scoped runtime credential instead of passing a general operator credential to an integration. The body is limited by the service's 8,192-byte JSON request limit and the endpoint's 6,000-character text limit.

```sh
python3 app.py issue-runtime "Model Operations" app-gateway ApprovedGateway \
  --scope inspect --ttl-minutes 15
```

Use `--scope findings` for ingestion only, or `--scope both` if the application needs both. The findings endpoint accepts events only for the source named when the credential was issued. Scoped credentials cannot query inventory, read findings, or mutate other project data. Rotate them through the application operator's secret delivery mechanism. Use the bundled `RuntimeClient.screen` in Python to forward only its returned text. Treat any `ScreeningError` as a hold or reject decision.

To associate a normalized runtime finding with a discovered endpoint, use its node `id` from the cloud graph API. List findings by project to see whether the node came from declared or discovered inventory. Previously received finding records are retained when a later sync no longer contains the node.

```sh
curl -fsS "$BASE/api/v1/runtime/inspect" \
  -H "Authorization: Bearer $SPM_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"text":"Contact person@example.test","action":"redact"}'
```

- **allow** means the configured patterns produced no matches. Use the original text if the application policy permits it.
- **redact** includes the replacement text. Forward only that returned text.
- **block** withholds the content. Do not forward the original. Reject or hold the operation when a required screening call is unavailable, malformed, or times out.
- The service detects selected private key markers, bearer tokens, AWS access key IDs, and email-address patterns. It does not store the inspected message or automatically emit a finding. You can separately send a normalized event without the input or response text to the existing runtime findings endpoint. Heuristic screening is limited to the documented patterns and is not a substitute for full data classification or behavioral threat detection.

## Require an externally signed scanner verdict for model promotion

Have an approved independent scanner or attestation adapter sign the exact JSON verdict using a scanner key distinct from your release key. The schema accepts exactly `schema`, `artifact_id`, `sha256`, `scanner`, `scanned_at`, and `verdict`. Use schema `doofusai.threat-verdict.v1`, a lowercase SHA-256 hex digest, a zoned timestamp, and `allow` only for a successful scanner policy decision.

```sh
python3 app.py verify-artifact model.safetensors manifest.json manifest.sig release-public.pem \
  --artifact-id model-release-42 --format-policy safetensors \
  --threat-report verdict.json --threat-signature verdict.sig \
  --threat-public-key scanner-public.pem --trusted-scanner approved-scanner \
  --threat-max-age-hours 24
```

Require exit 0 before promotion. Missing inputs, a mismatched digest or scanner, an invalid signature, a denied verdict, or expired evidence cause failure. Use pinned public keys and immutable artifact digests. This gate enforces the external verdict; scanner installation and detection quality are external dependencies.

## Qualify an environment and measure recovery

Run load checks against a staging origin you control with representative data. Set `SPM_QUALIFICATION_TOKEN` via your approved secret mechanism before running. The tool makes bounded read-only calls, checks response shapes, and exits nonzero for errors or a missed latency target.

```sh
cd spm
python3 tools/qualify.py load https://spm-staging.example.com \
  --requests 240 --workers 8 --p95-target-ms 250
```

Test a restore against a copy. Record a conservative backup-capture time before taking your backup and record simulated incident time. The command creates and checks an isolated loopback service, promotes the copy, reads and writes a canary record, checks the event stream, and removes temporary files.

```sh
python3 tools/qualify.py recover ./backup.sqlite \
  --captured-at 2026-11-16T14:00:00Z --incident-at 2026-11-16T14:00:05Z \
  --rto-seconds 10 --rpo-seconds 15 --known-scan KNOWN_SCAN_UUID
```

Use a qualification token for the project's known scan. Omitting the scan ID exercises backup validation and a recovery write but skips verification of a prior scan.

For an operator-led multi-host drill, record the old stream ID and a scan ID that predates the verified backup. Start the observer from a separate host with an admin test credential for the project containing the known report. Then fence the old writer, restore and promote the standby database with the [recovery procedure](ENTERPRISE-OPERATIONS.md#single-node-deployment-monitoring-and-recovery), and switch the approved ingress.

```sh
python3 tools/qualify.py observe-failover https://spm-staging.example.com \
  --previous-stream PREVIOUS_STREAM_ID --known-scan KNOWN_SCAN_UUID --rto-seconds 90
```

Start the observer at the beginning of the planned failover. It measures until the same ingress returns health, a new stream ID, and the known scan. The observer does not change ingress, elect a writer, or replicate data. The local rehearsal and its backup-age check do not establish a production recovery objective.

### Local qualification record

The loopback instance held 60 synthetic assets, assessments, and open issues. Three read-load runs exercised 240 requests each at concurrency eight, with no failed requests and p95 response times of 35.73, 35.91, and 36.71 ms. The cold restore reached healthy read/write operation in approximately 0.30 seconds and retrieved the known pre-backup assessment. The backup and simulated incident occurred within the same recorded second. These measurements describe the local fixture and exclude network ingress, TLS, replication, and operator response time.

A separate local switchover drill used two service processes with separate database files behind one loopback relay. The old writer stopped before promotion. The observer detected the restored instance and known assessment in 0.53 seconds, and a new assessment was written to the promoted copy. The same drill verified redaction and blocking through the scoped runtime client over HTTP. Separate physical hosts and automated failover remain outside that drill.

## AWS AI discovery and Access Analyzer findings

Run from a host configured with AWS CLI v2 and a dedicated read-only identity. The connector verifies the active AWS account with STS before collecting inventory. Give it only the list and describe access needed for SageMaker models, endpoints and endpoint configurations, and for Bedrock agents. If you supply an IAM Access Analyzer ARN, its role also needs `access-analyzer:ListFindings` for that analyzer. Run in a region that supports the configured services.

```sh
python3 app.py --db ./data/posture.sqlite sync-aws "Model Operations" 123456789012 us-east-1 \
  --analyzer arn:aws:access-analyzer:us-east-1:123456789012:analyzer/pilot
```

The `aws:123456789012:us-east-1` scope appears in **Relationships**. SageMaker endpoints connect to their production models. Models can link to their execution role and referenced S3 artifact bucket. Agents can link to their explicitly configured service role and foundation model. The connector reads configuration only. It does not enumerate S3 objects or invoke agents, models, or endpoints.

Use an appropriately configured external-access analyzer for assessed roles. An active external-access finding on a collected role creates an issue and contributes to risk. Explicit resolution from the same analyzer can close the issue. A role with no matching active or resolved observation remains unknown. An analyzer is pinned to the scope after the first configured import. This avoids replacing evidence with conclusions from a different analyzer. Analyzer evidence is limited to the selected scope and finding types. Endpoint IAM, service control policies, and full per-principal effective permission analysis require further work.

[Model configuration](https://docs.aws.amazon.com/cli/latest/reference/sagemaker/describe-model.html) · [Endpoint configuration](https://docs.aws.amazon.com/cli/latest/reference/sagemaker/describe-endpoint-config.html) · [Bedrock agent configuration](https://docs.aws.amazon.com/cli/latest/reference/bedrock-agent/get-agent.html) · [Access Analyzer findings](https://docs.aws.amazon.com/cli/latest/reference/accessanalyzer/list-findings-v2.html)

## Dependency inventory from CycloneDX and GitHub

First identify a model, endpoint, or agent node in the project. Use its ID when importing a document. A successful import keeps a snapshot keyed to the workload and exact file digest. Exact reimports return the existing record.

```sh
python3 app.py --db ./data/posture.sqlite import-bom "Model Operations" app-agent release.cdx.json
```

The importer accepts a supported subset of CycloneDX 1.5–1.7 and SPDX 2.2–2.3 JSON, up to 2 MiB. It retains component or package identifiers, names, types, versions and available purls, plus supported dependency relationships. It does not fetch external references or attest to report completeness. The SPDX import counts relationships outside its supported subset. Open **AI bills of materials**, or use `GET /api/v1/boms?workload=app-agent` and `GET /api/v1/boms/{id}` to retrieve the normalized snapshot.

To collect repository dependencies automatically, provide a GitHub credential via the `SPM_GITHUB_TOKEN` environment variable using your secret manager. Use a credential with repository read access and identify the exact approved temporary download hostname for your GitHub report deployment.

```sh
python3 app.py --db ./data/posture.sqlite sync-github-bom "Model Operations" app-agent OWNER/REPO \
  --download-host APPROVED_DOWNLOAD_HOST
```

DoofusAI uses GitHub's asynchronous generation and fetch endpoints. A temporary download URL must match the configured hostname. The GitHub bearer token is never sent with the download request. Only use a report for a repository actually associated with the selected workload. Repository dependencies and deployed package inventory can differ.

[CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) · [GitHub SBOM API](https://docs.github.com/en/rest/dependency-graph/sboms)

## Require safe model-package content

For a signed ZIP containing weights and metadata, add the strict archive and numeric policy to the existing signature verification command:

```sh
python3 app.py verify-artifact model.zip manifest.json manifest.sig release-public.pem \
  --artifact-id model-release-42 --format-policy safe-model-package --numeric-policy finite
```

The native package checker reads members without extracting them or loading a model. It requires at least one Safetensors member and admits only bounded Safetensors, JSON, Markdown and UTF-8 text files. It rejects unsupported archive structure, ambiguous or unsafe names, links, disallowed file types, malformed tensor layout and excessive expansion. The package limit is 512 MiB on disk and 2 GiB expanded. The optional numeric check rejects detected non-finite floating-point weights and invalid Boolean encodings. It is also available for standalone Safetensors files. Add the independent scanner-verdict flags when your release policy requires behavioral scanning. Native allowlist and numeric checks do not establish that a model is free of backdoors.

## Enforce application and agent policy

A project administrator can set `POST /api/v1/runtime-policy` to `{"minimum_action":"block"}`. All project screening requests will block on detected matches, including requests for redaction. `GET /api/v1/runtime-policy` displays the configured minimum. Set it back to `redact` only if project policy permits.

1. Create or discover the agent node in the project's relationship inventory.
2. As a project admin, add an exact rule with `POST /api/v1/agent-tool-rules`, using a documented tool and target alias. The operations are `read`, `write`, and `invoke`. For example:

   ```json
   {"agent":"app-agent","tool":"search","operation":"read","target":"approved-index"}
   ```

3. Issue a credential for this agent only:

   ```sh
   python3 app.py issue-runtime "Model Operations" agent-gateway ApprovedGateway \
     --scope tools --agent app-agent --ttl-minutes 15
   ```

4. Call `POST /api/v1/runtime/authorize-tool` before performing the operation, or use `RuntimeClient.authorize_tool`. Execute only after an explicit allow from the client. Derive the labels from the actual operation and target being dispatched, and never substitute labels supplied by the model. Refuse or hold the call on denial, missing policy, malformed response or transport failure. The authorization endpoint neither runs a tool nor validates tool arguments.
5. Revoke a rule with `DELETE /api/v1/agent-tool-rules` and the same body. Administrative changes are audited. The service does not persist tool call arguments or screening text.

## Monitor and qualify staging

Give the application account read access to a randomly generated, URL-safe monitoring token file. Use a separate credential from project tokens. Append `--metrics-token-file /secure/spm-metrics.token` to the service's start command. The optional `/metrics` endpoint serves Prometheus text with bounded route and status labels. Configure Prometheus to load the credential from a protected file, and keep the collector path inside the approved monitoring network.

```yaml
scrape_configs:
  - job_name: doofusai-spm
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /secure/spm-metrics.token
    static_configs:
      - targets: [spm-monitoring.example.com]
```

Once the authorized staging connectors have run, set `SPM_QUALIFICATION_TOKEN` to a federated staging access token. Verify the intended identity and latest successful connector evidence:

```sh
python3 tools/qualify.py pilot https://spm-staging.example.com \
  --project "Model Operations" --principal Jules \
  --require-sync aws=aws:123456789012:us-east-1 \
  --require-sync vertex=MY_PROJECT:us-central1 --github-workload app-agent
```

This check fails on the wrong principal, missing or stale evidence, or a failed latest sync. Run the load and recovery checks separately against agreed targets. Local acceptance was exercised using fixture cloud responses. The new localhost HTTP smoke verified imported inventory, agent deny/allow, authenticated metrics, and a signed model package. It also completed 240 read requests at concurrency eight with zero errors and 6.05 ms p95 on the small test instance. A verified production deployment needs representative workloads, TLS ingress, actual identity and cloud accounts, and a separately managed replicated data plane and single-writer fencing for automatic multi-host recovery.

## Azure Machine Learning and Microsoft Foundry

Use the Azure CLI with a dedicated identity authorized to read the selected Azure ML workspace, model containers, online endpoints, and deployments. The connector uses the public Azure Resource Manager endpoint and a subscription-scoped CLI token. It does not require deployment or invocation permissions.

```sh
cd spm
python3 app.py --db ./data/posture.sqlite sync-azure "Model Operations" \
  SUBSCRIPTION_UUID resource-group ml-workspace --rbac \
  --foundry-account foundry-account --foundry-project foundry-project
```

- Use `--rbac` only if the Azure identity can list role assignments for the workspace scope. The assessment checks direct assignments to discovered managed identities for the built-in Owner, Contributor, and User Access Administrator roles at the workspace, resource group, or subscription scope. The result is assignment evidence. It does not resolve group membership, PIM, custom roles, managed conditions, deny assignments, or effective permissions.
- Use the two Foundry flags together to inventory agents in the specified project. The Azure identity also needs permission to list those agents. The connector requests a separate token for the Foundry service and retains agent names and supported model references. It does not store agent instructions or invoke agents. Omit both flags to collect the Azure ML workspace alone.
- In **Relationships**, open the scope `azure:SUBSCRIPTION_UUID:resource-group:ml-workspace`. The graph links the workspace to its storage account, model containers and endpoints. It links deployments to recognized workspace models and records explicit managed identity relationships. Azure online endpoint assessments use the reported public-network-access setting. Public network configuration does not establish anonymous access.
- Test changes on an authorized pilot workspace. A report-backed pass can resolve the original issue. Missing evidence remains unknown. A failed collection preserves the last complete graph and does not close issues.
- Import a release BOM against an inventoried model, endpoint, or agent ID. Runtime findings can reference the same discovered ID, and an application can use an agent-scoped tool credential for a discovered Foundry agent.

[Azure ML model containers](https://learn.microsoft.com/en-us/rest/api/azureml/model-containers/list?view=rest-azureml-2025-12-01) · [Azure ML endpoints](https://learn.microsoft.com/en-us/rest/api/azureml/online-endpoints/list?view=rest-azureml-2025-12-01) · [Azure role assignments](https://learn.microsoft.com/rest/api/authorization/role-assignments/list-for-scope) · [Microsoft Foundry REST API](https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/aiproject)

## VMware ESXi and vCenter

Install the optional SDK in the same Python environment used to run the connector. Configure a read-only ESXi or vCenter account with visibility into the intended inventory. Set `SPM_VSPHERE_USER` and `SPM_VSPHERE_PASSWORD` through the host's secret mechanism. For an internal vSphere CA, provide the CA bundle. Certificate verification is always enabled.

```sh
cd spm
python3 -m pip install -r requirements-vsphere.txt
python3 app.py --db ./data/posture.sqlite sync-esxi "Model Operations" esx.example.com \
  --ca-file /secure/vsphere-ca.pem
```

Use `sync-vsphere` with a vCenter DNS name to collect inventory visible through vCenter. The scope is `vsphere:HOST:PORT`; port 443 is the default. In **Relationships**, inspect ESXi hosts, virtual machines, datastores, and networks. The graph shows host placement, datastore references, and VM network attachments when reported. It does not infer network reachability, identify applications installed in guests, access guest files, or read virtual disks.

- **Host lockdown** uses the reported lockdown mode. Standalone hosts or credentials with restricted visibility may return no value, which leaves the control unknown.
- **VM logging** uses the VM configuration flag. **EFI Secure Boot** is evaluated only when EFI firmware and its Secure Boot setting are both reported. BIOS and unreadable settings remain unknown under that check.
- Connect through vCenter consistently for centrally managed hosts. The connector keys records to the management endpoint and managed-object ID. Collecting the same host directly and through vCenter creates separate scopes.
- A VM can be linked to a release BOM and can receive normalized runtime findings from an authorized integration. VM inventory by itself does not identify any model or agent running inside the guest.
- Schedule the command through the host scheduler when repeated collection is needed. Protect credential delivery and capture the exit status. DoofusAI serializes overlapping source collections for the same database.

[VMware SDK](https://github.com/vmware/pyvmomi) · [vSphere PropertyCollector](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vmodl.query.PropertyCollector.html) · [Host lockdown metadata](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.ConfigInfo.html) · [VM logging flag](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.FlagInfo.html)

## Qualify the new sources

After running both connectors against a designated staging deployment, use a federated test credential and require recent successful runs:

```sh
python3 tools/qualify.py pilot https://spm-staging.example.com \
  --project "Model Operations" --principal Jules \
  --require-sync "azure=azure:SUBSCRIPTION_UUID:resource-group:ml-workspace" \
  --require-sync "vsphere=vsphere:esx.example.com:443"
```

In the scope argument, use the actual lowercased subscription UUID, resource group, workspace, and host. This check verifies recorded sync freshness plus the federated identity. It does not contact Azure or vSphere directly. The automated connector suite uses Azure API and vSphere SDK fixtures. A live pilot is required to qualify provider permissions and supported VMware versions.

## Explain risk and verify remediation

Open an issue's history to see the declared or collected configuration path behind its exposure score. The cloud path includes the source scope, contributing asset metadata, observation time, and latest collection status. DoofusAI labels evidence older than 72 hours stale and recently retained evidence degraded if the latest sync failed. A failed collection preserves the previous risk score. The path represents configuration relationships and does not establish actual network connectivity or effective permissions.

To verify a fix on an authorized staging asset:

1. Run its owning connector and record an issue backed by a failed control.
2. Apply the planned fix in the source system and rerun the same connector scope.
3. Open the resolved issue. The issue history links to the baseline and verified reassessment when both observations came from separate, successful syncs and used the same control and policy version.
4. Require the proof in a release or remediation check:

   ```sh
   python3 tools/qualify.py remediation https://spm-staging.example.com \
     --issue ISSUE_UUID --provider azure --max-age-hours 24
   ```

Use a staging project credential in `SPM_QUALIFICATION_TOKEN`. The project-scoped endpoint is `GET /api/v1/issues/{id}/remediation-proof`. It withholds verification when the latest observation is unknown, the source asset is absent, comparable evidence is missing, or the latest sync failed. The command also rejects a mismatched provider or stale evidence. It checks stored assessments without contacting the provider or changing configuration.

## Enforce agent model selection

A project administrator can allow a specific model for an inventoried agent using `POST /api/v1/agent-model-rules` with `{"agent":"app-agent","model":"approved-model"}`. View rules using GET or revoke a specific pair using DELETE and the same JSON fields. Changes are audited. Missing rules or removed inventory targets are denied.

```sh
python3 app.py issue-runtime "Model Operations" model-router ModelGateway \
  --scope models --agent app-agent --ttl-minutes 15
```

Use `POST /api/v1/runtime/authorize-model` or the Python client's `authorize_model` method before invoking a model. The application must send the identifier that maps to the actual provider model it will call. Execute only after an explicit allow. A model-only credential does not authorize tool calls. The optional `--scope agent` supports both checks for the same agent. Existing tool-only credentials retain their current scope. This gate checks application routing policy and does not inspect model behavior.

## Review permissions and compare changes

The **Access reviews** page is available to project administrators. Reviews bind a principal and resource to an inventoried asset, record the exact actions examined, and retain the provider's result and evaluation time. A later inventory refresh flags older reviews for reassessment. Review data is scoped to the project. Access-review creation is audited.

### AWS IAM policy simulation

1. Run the AWS inventory connector and identify the DoofusAI ID for the role to review. Use a host AWS CLI identity in that account with permission for `iam:SimulatePrincipalPolicy` on that role.
2. Select one resource ARN and explicitly list the actions to evaluate. Actions in the request are simulated only. The connector never invokes them.

   ```sh
   python3 app.py review-aws-access "Model Operations" AWS_ROLE_ASSET_ID \
     --resource arn:aws:s3:::approved-artifact-bucket/models/release.safetensors \
     --action s3:GetObject --action s3:PutObject
   ```

   The role must still be present in the project's AWS scope. The command supports same-account resource ARNs and S3 bucket/object ARNs under a bucket inventoried in that scope. It rejects wildcard actions and resources, cross-account scope, and incomplete or mismatched provider results.
3. In **Access reviews**, inspect the decision, missing context keys, and any reported permissions boundary or Organizations result. The product records an indeterminate decision when AWS returns missing context or conflicting constraint evidence. Simulation uses the policies and context AWS evaluated. It does not exercise the target action or prove that a real session would receive the same answer.

[AWS IAM simulator behavior and limits](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html) · [AWS CLI simulate-principal-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/simulate-principal-policy.html)

### vCenter named-user privilege check

Run `sync-vsphere` against vCenter before reviewing an active host or VM. Use the same trusted TLS setup and read-only service credential as for inventory. The vCenter server checks the named user's reported privileges on the selected inventory object, including grants through group membership. This API is available on supported vCenter versions and is not implemented on direct ESXi connections.

```sh
python3 app.py review-vsphere-access "Model Operations" VM_ASSET_ID \
  --principal 'reader@example.com' --privilege System.View \
  --privilege VirtualMachine.Interact.PowerOn --ca-file /secure/vsphere-ca.pem
```

The command returns a review ID. **Access reviews** shows allowed, denied, or indeterminate for each requested privilege. Missing provider decisions remain indeterminate. No VM action is performed.

[vCenter HasUserPrivilegeOnEntities](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.AuthorizationManager.html#hasUserPrivilegeOnEntities)

### Compare before and after a change

1. Save a baseline review. In your approved change workflow, adjust the applicable permission or policy in the source system.
2. Rerun the same review for the same principal, target, and action set. In the newer review, choose the baseline and select **Compare decisions**. A result is inconclusive whenever either review lacks a usable decision.
3. Optionally require the change in staging. Set `SPM_QUALIFICATION_TOKEN` to a project administrator test credential:

   ```sh
   python3 tools/qualify.py access-change https://spm-staging.example.com \
     --review NEW_REVIEW_UUID --baseline BASELINE_REVIEW_UUID --provider aws \
     --require s3:GetObject=access-removed --max-age-hours 24
   ```

The API exposes the same evidence through `GET /api/v1/access-reviews/{id}` and `GET /api/v1/access-reviews/{id}/compare?baseline={baseline_id}`. The staging gate rejects outdated inventory, stale evidence, incompatible reviews, and unexpected changes. Provider responses are verified with test fixtures. Run an authorized staging review to confirm AWS and vCenter permissions and version compatibility.

### Google Cloud Storage current-caller permission check

1. Run `sync-gcs` with your approved Application Default Credentials and copy the bucket's DoofusAI asset ID from the resulting inventory.
2. Use ADC with a verifiable Google UserInfo subject and permission to read bucket metadata. Run this command from the application directory using the same database as the inventory collector.

   ```sh
   python3 app.py --db "$DB" review-gcs-access "$PROJECT" "$ASSET" \
     --permission storage.objects.get --permission storage.objects.list
   ```

3. Open **Access reviews** as a project administrator and match the recorded Google subject to the reviewing identity. Decisions apply to the supplied permissions for this caller at the inventoried bucket. The collector verifies the bucket's project number and metadata version around the check. A provider error or unexpected bucket change interrupts the review. For change qualification, capture a comparable review using the same identity, bucket and permission set after the policy update. Select `--provider gcs` in the access-change procedure above.

[Cloud Storage permission check API](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/testIamPermissions)

## Evaluate model behavior before release

1. Use an approved staging deployment with a compatible `/v1/chat/completions` endpoint. Store fixed synthetic cases in a versioned file named `behavior.json`.

   ```json
   {
     "schema": "doofusai.behavior.v1",
     "cases": [
       {
         "id": "structured-status",
         "input": "Return only a JSON object with a status field set to ready.",
         "expect": {"json_keys": ["status"], "contains": ["ready"], "max_chars": 120}
       }
     ]
   }
   ```

2. Inject `SPM_MODEL_TOKEN` through the CI secret manager if the deployment requires authentication. Run this step against the candidate before promotion.

   ```sh
   python3 app.py evaluate-model behavior.json --origin "$MODEL_ORIGIN" --model "$MODEL_ID"
   ```

3. Use the process exit status as the release gate. Archive the output with the build. It reports the model identifier, suite digest and case results while keeping prompts and responses out of the report. Add representative cases for the deployment contract and rerun after changes to the model or serving configuration. Keep signed artifact and external-scanner checks in the promotion pipeline.

Python applications can use `model_behavior.GuardedChat` with a pinned `ChatDeployment` and two `RuntimeClient` instances. Give the authorizer a model-authorization credential scoped to the agent and give the screening client an inspection credential. Configure the application with the agent and its registered model node. Route user text through `answer()`, handle rejection as a blocked request, and return only the screened result. Rejected requests must end at this boundary. This adapter handles text chat responses and rejects tool calls.

### Evaluate a named Google identity

Enable Google Cloud IAM Policy Troubleshooter for the ADC quota project and use an authorized operator credential with access to the relevant policies and bucket metadata. Run the review with an active inventoried bucket and specify a Google user or service account email.

```sh
python3 app.py --db "$DB" review-gcs-access "$PROJECT" "$ASSET" \
  --principal "$ACCOUNT_EMAIL" --permission storage.objects.get --quota-project "$QUOTA_PROJECT"
```

In **Access reviews**, open the result for the named account. The review records the provider verdict on the bucket, including an indeterminate result when Google lacks policy visibility or condition context. The review is an IAM assessment. Network restrictions and access to individual objects require separate verification. For before-and-after comparisons, use the same account, bucket, and permissions in both runs.

[Google IAM Policy Troubleshooter API](https://docs.cloud.google.com/policy-intelligence/docs/reference/policytroubleshooter/rest/v3/iam/troubleshoot)

### Route text chat through a shared enforcement endpoint

1. Register the agent and model as graph nodes. As a project administrator, allow the pairing through `POST /api/v1/agent-model-rules` with `{"agent":"support-agent","model":"support-model"}`.
2. Deploy the service with `serve --chat-gateway-config gateway.json`. On Kubernetes mount the file as `gateway.json` in the configuration Secret. Supply the upstream credential as `SPM_MODEL_TOKEN` through the deployment secret manager when required.

   ```json
   {
     "project": "pilot",
     "agent": "support-agent",
     "model_node": "support-model",
     "origin": "https://models.example.test",
     "model": "support-v1"
   }
   ```

3. Issue a short-lived runtime token using `issue-runtime pilot chat-client gateway --scope models --agent support-agent`. From your application's backend, send a JSON request to `POST /api/v1/runtime/chat` with that token as a bearer credential and the input in the `text` field.
4. Return the response's `text` only on HTTP 200. HTTP 403 can indicate an expired credential, revoked model policy or blocked content. HTTP 502 means the configured model did not return an eligible text response. Apply caller-specific request limits at the ingress. This configuration accepts the original request body with only the `text` field. Tool calls and streaming require a separate integration.

#### Configure multiple routes

Use a top-level `routes` array in `gateway.json` to publish up to 32 operator-configured routes. Each route pins its project, agent, registered model node, and upstream deployment. Use a unique lowercase `id` on each route.

```json
{
  "routes": [
    {
      "id": "support",
      "project": "support",
      "agent": "help-agent",
      "model_node": "help-model",
      "origin": "https://support-models.example.test",
      "model": "support-v1",
      "token_env": "DOOFUS_GATEWAY_TOKEN_SUPPORT"
    },
    {
      "id": "internal",
      "project": "operations",
      "agent": "ops-agent",
      "model_node": "ops-model",
      "origin": "https://ops-models.example.test",
      "model": "operations-v2",
      "token_env": "DOOFUS_GATEWAY_TOKEN_OPS"
    }
  ]
}
```

1. Inject each upstream credential into its named environment variable through your secret manager. Omit `token_env` only for upstreams that accept unauthenticated requests. The service rejects a named variable that is missing or empty.
2. Register and allow the agent/model pair in the project named by each route. Issue agent-bound runtime credentials for the applications using those routes.
3. Start or restart the service with the new file. Send `{"route":"support","text":"Return a status."}` to `POST /api/v1/runtime/chat`. Confirm HTTP 200 with an authorized credential and HTTP 403 when using a credential from the other project.
4. Keep the upstream origin and model under operator control. The request body accepts the route ID and text. A credential can use multiple routes only where its project, agent, and current model rules permit it.

## Collect Oracle Cloud, IBM Cloud, and Salesforce inventory

Authored by Aniza Inc.

The commands below run from the `spm` directory. Use an existing DoofusAI project and the database used by the serving process. Schedule each provider scope independently using an approved read-only service identity. After each run, open **Cloud syncs** to verify the provider, source scope and status. Open **Relationships** to browse the imported inventory. For OCI and IBM deployments, use **Inventory** and **Issues** to see source-linked deployment health assessments.

### Oracle Cloud Infrastructure Data Science

1. Install the OCI CLI on the collector and configure its approved profile or workload identity. Grant permission to list Data Science projects, models and model deployments in the selected compartment.
2. Use the target compartment OCID and region. Run a separate collection for each compartment and region.

   ```sh
   python3 app.py --db "$DB" sync-oci "$PROJECT" "$OCI_COMPARTMENT" "$OCI_REGION"
   ```

3. Select the OCI scope in **Relationships**. Projects link to returned models and deployments by their reported project OCIDs. A deployment in Failed or Needs Attention raises a health finding. The collector records Active as passing and leaves other lifecycle states without a verdict. To collect deployment-to-model bindings and access-log configuration, grant read access to deployment details and repeat with `--deployment-details`. This mode checks up to 100 deployments per compartment. It links supported single-model deployments to models visible in the current compartment and reports a missing access-log configuration when OCI explicitly returns it. Continue using the flag on subsequent refreshes to retain this coverage. This verifies configuration. Verify log delivery, model-group membership, networking and IAM separately.

[OCI Data Science model inventories](https://docs.oracle.com/en-us/iaas/Content/data-science/using/model-details.htm) · [OCI deployment CLI](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/data-science/model-deployment/list.html)

### IBM Cloud watsonx.ai

1. Choose a deployment space and its IBM Cloud region. Obtain a short-lived IBM IAM token with read access to that space. Inject it into the collector process as `DOOFUS_IBM_IAM_TOKEN` using your credential manager.
2. Sync the space using its UUID.

   ```sh
   python3 app.py --db "$DB" sync-ibm "$PROJECT" "$IBM_SPACE" "$IBM_REGION"
   ```

3. Check the IBM scope in **Relationships**. Deployment-to-model links require a model ID present in the same fetched space. A reported failed deployment raises a finding, ready passes, and transitional states yield no verdict. Repeat for each authorized deployment space.

[IBM watsonx.ai Runtime REST API](https://cloud.ibm.com/docs/apis/machine-learning)

### Salesforce

1. Get a Salesforce OAuth access token for an integration user allowed to query Organization and Tooling API FlowDefinition metadata. Inject it as `DOOFUS_SALESFORCE_TOKEN`. Record the expected org ID from Salesforce setup and use the HTTPS My Domain hostname without the URL scheme. A sandbox My Domain such as `company--uat.sandbox.my.salesforce.com` is supported.
2. Run the metadata collection.

   ```sh
   python3 app.py --db "$DB" sync-salesforce "$PROJECT" "$SF_MY_DOMAIN" "$SF_ORG_ID" --api-version 63.0
   ```

3. Check the Salesforce scope in **Relationships** for the organization and its Flow definitions. The inventory marks Flows with an active version and records namespaced API names. This scope collects automation metadata. Agentforce-specific assets, Flow logic, and CRM record data require separate connector scopes.

[Salesforce Organization object](https://developer.salesforce.com/docs/platform/object-reference/references/standard-objects/object-organization.html) · [Salesforce Tooling FlowDefinition](https://developer.salesforce.com/docs/platform/api-tooling/references/tooling-objects/tooling-flowdefinition.html)

For a staging gate, pass `--require-sync oci=<scope>`, `--require-sync ibm=<scope>`, or `--require-sync salesforce=<scope>` to `tools/qualify.py pilot`. Use the full source scope displayed in the latest Cloud syncs record. Failed refreshes preserve prior successful inventory and appear in sync history with failure status.

## Validate GGUF model artifacts before promotion

Run the signed artifact gate with the GGUF format policy. Provide the candidate file, its signed manifest and the trusted publisher's public key.

```sh
python3 app.py verify-artifact model.gguf manifest.json manifest.sig publisher.pem \
  --artifact-id "$ARTIFACT_ID" --format-policy gguf
```

On success the report includes the format, tensor count, metadata count, alignment, and data-region size. The policy accepts little-endian GGUF v3 with supported scalar and quantized weight types. It validates header bounds, metadata encodings, tensor dimensions, block sizes, offsets, zero padding and the file boundary without loading a model. Unsupported versions, types and layouts fail the gate. The finite-value option applies to Safetensors. GGUF releases can still require an independent signed threat-scanner verdict and a separate behavioral evaluation.

[GGUF format specification](https://github.com/ggml-org/ggml/blob/master/docs/gguf.md)

## Discover Agentforce definitions and dependencies

Authored by Aniza Inc.

For a Salesforce org with Agents enabled and Metadata API access, run the existing Salesforce collector with API version 68.0 or later.

```sh
python3 app.py --db "$DB" sync-salesforce "$PROJECT" "$SF_MY_DOMAIN" "$SF_ORG_ID" \
  --api-version 68.0 --agentforce
```

Use the existing Salesforce collector credential. After verifying the org ID through the REST API, the collector lists Agentforce definitions and versions through the Metadata API. Open **Relationships** and select the Salesforce scope. Version names such as `Support#1` link to the matching discovered definition. The collector does not retrieve agent scripts or activate agents. Subagents, tool bindings and legacy Agentforce metadata require additional discovery.

[Salesforce Agentforce metadata types](https://developer.salesforce.com/docs/ai/agentforce/references/agents-metadata-tooling/agents-metadata.html)

## Review data classification, exposure and access together

1. Run the provider's connector and open **Data posture** as a project administrator. Select **Review evidence** on a discovered data node. API clients can use `GET /api/v1/data-posture`.
2. Select an operator classification and choose **Save classification**. API clients can use `POST /api/v1/data-posture` with a body such as `{"node":"<discovered-node-id>","sensitivity":"high"}`. Allowed levels are `low`, `moderate`, `high`, and `unknown`. The write is audited.
3. Fetch the report again. It shows operator and provider classifications with their respective observation times. The `configuration_path` flag indicates a relationship from a reported public configuration or external access finding. Access evidence shows the latest decision per provider, principal, resource, and action, scoped to active inventory revisions. Review timestamps older than 72 hours are marked stale. An unsuccessful latest collection marks retained configuration evidence degraded. A missing entry means the report has no matching evidence. It does not establish absence of access.
4. Use `?after=<next_after>` to continue across pages. Run fresh provider access reviews after collection changes.

This surface works with discovered cloud graph data nodes. It records classifications provided by operators and connectors without reading object contents. An IAM decision and a configuration path are different forms of evidence. Use the scope and provider to interpret each result.

## Screen a buffered upstream stream

Set `"upstream_stream":true` on the existing chat gateway request. The upstream must send a single text choice as SSE and finish with a `stop` chunk and `[DONE]`. The gateway screens the complete assembled response, which allows the same policy to catch sensitive patterns split across chunks. It checks authorization again before returning one JSON response. Incomplete streams and tool-call chunks fail closed. Incremental client delivery remains unsupported.

## Mediate application-owned tool calls

Instantiate `runtime_client.GuardedTools` in the application with an agent-bound tool authorization client, an inspection client, and an operator-configured mapping from `(tool, operation, target)` to text handlers. Call `invoke(tool=..., operation=..., target=..., text=...)` for requests routed through the adapter. Register each permitted tuple and authorize it in DoofusAI before use. The adapter checks policy and input before calling a registered handler, then checks policy and screens the handler response before returning it. Each handler must use fixed downstream resources and its own application authorization. A response block cannot undo handler side effects.

## Detect unsafe raw Pickle operations

Run `verify-artifact` with the existing signed manifest arguments and `--format-policy pickle-data`. The gate scans raw Pickle files up to 8 MiB for opcodes outside a data-only allowlist and rejects object construction, external reference resolution, truncated input, and trailing bytes. The scanner never deserializes the artifact. This policy does not cover PyTorch archives, model backdoors or the safety of loading data in a downstream runtime.

[Python Pickle opcode inspection](https://docs.python.org/3/library/pickletools.html)

## Discover npm dependencies and review time-conditioned access

Run `python3 app.py --db "$DB" sync-npm-lock "$PROJECT" "$WORKLOAD" package-lock.json` for an inventoried workload. The importer reads npm lockfile versions 2 and 3, follows installed dependency paths and workspace links within the lockfile, and records a CycloneDX inventory. It reads only the supplied file. It does not execute npm, fetch packages, or infer dependencies missing from the lockfile.

To evaluate a named Google account at a specific request time, pass `--receive-time 2026-11-17T12:00:00Z` alongside `--principal` on `review-gcs-access`. Google IAM Policy Troubleshooter evaluates its visible inherited policies, group memberships, and conditions for the requested bucket permission. The review keeps the stated time and provider verdict, including unknown results. Compare conditional reviews only at the same request time. Time-conditioned decisions stay out of the general Data posture access evidence.

[Google Policy Troubleshooter](https://docs.cloud.google.com/policy-intelligence/docs/troubleshoot-access)

## Automatically classify a selected cloud object

1. Identify the data node in the **Data posture** workspace. AWS requires an inventoried S3 bucket. For Google, sync both Vertex and Cloud Storage for the same source project so the associated bucket has verified ownership metadata.
2. Supply an approved read-only cloud identity and the exact object key. Run this from the collector host.

   ```sh
   python3 app.py --db "$DB" classify-object "$PROJECT" "$DATA_NODE" "$OBJECT_KEY"
   ```

3. Review the latest sample in **Data posture**. The classifier examines a maximum 64 KiB UTF-8 prefix for supported email and credential patterns. An unknown result means no supported signal was detected in that sample. Results retain provider, byte count, sensitivity and signal counts. Object keys and sampled text are excluded from the report and audit record. AWS CLI uses a private temporary download that is removed at the end of the command. Use the deployment's approved temporary storage for that collector.

[Amazon S3 ranged reads](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object.html)

## Screen structured traffic at an application or gateway boundary

Use a short-lived inspection credential to send `{"document":{...}}` to `POST /api/v1/runtime/inspect-document` before forwarding an application JSON payload. The service inspects keys and strings, including joined string fragments, and returns HTTP 200 with an explicit allow or HTTP 403 with a block and signal counts. The caller must forward only on explicit allow and treat any other status or policy-service failure as blocked. The JSON envelope is limited to 8 KiB. This is an HTTP decision endpoint for participating applications and gateways.

## Require a data-only checkpoint archive

Use `verify-artifact --format-policy checkpoint-data` with the standard signed manifest arguments. The policy checks a restricted checkpoint-shaped ZIP profile up to 64 MiB and scans its embedded `data.pkl` without extraction or deserialization. It blocks object-building and other non-data opcodes, so ordinary PyTorch checkpoints that rely on object reconstruction can be rejected. This is suitable for enforcing a deliberately narrow data-only release policy. For ordinary checkpoints, keep a separately trusted scanning and artifact review process.

[PyTorch serialization format](https://docs.pytorch.org/docs/stable/notes/serialization)

### Classify several approved objects in one run

Create a local JSON array containing 1–32 distinct exact keys in one inventoried S3 or Google Cloud Storage bucket. Use the same read-only collector credentials as for single-object sampling.

```sh
python3 app.py --db "$DB" classify-batch "$PROJECT" "$DATA_NODE" approved-keys.json
```

The command uses up to four concurrent reads and the same 64 KiB prefix limit per object. It records the batch only after every sample succeeds and the inventory revision still matches. On failure the CLI identifies the ordinal in the manifest. It excludes object keys and sample text from its output. The Data posture workspace shows the sensitivity counts for distinct sampled objects on the current inventory revision. Reclassifying an object replaces its prior sample. Treat the manifest as sensitive if object names contain customer or internal identifiers.

## Discover objects and run recurring classification

From the collector host, run `python3 app.py --db "$DB" classify-prefix "$PROJECT" "$DATA_NODE" "approved/" --limit 32`. Use an S3 or Cloud Storage identity that can list the approved prefix and read its objects. The command samples eligible text files from the first bounded provider page. It reports skipped entries and whether the listing was truncated. Select narrower prefixes or use approved manifests for wider coverage. In addition to email and credentials, classification reports labeled U.S. Social Security number and checksum-valid payment card candidates without persisting the values.

On Linux, install the supplied `deploy/systemd/doofusai-classify@.service` and `doofusai-classify@.timer` on the collector host. Use a host where the `doofusai` service account can read the authorized cloud credentials and write the serving database. Create `/etc/doofusai/classify-approved.conf` with the four values below, then enable the instance with `systemctl enable --now doofusai-classify@approved.timer`.

```ini
SPM_CLASSIFY_DB=/data/posture.sqlite
SPM_CLASSIFY_PROJECT=pilot
SPM_CLASSIFY_NODE=replace-with-the-data-node-id
SPM_CLASSIFY_PREFIX=approved/
```

Check status with `systemctl status doofusai-classify@approved.timer` and examine the one-shot service's journal after it runs. The included timer runs daily. Each run rechecks the first page of the configured prefix. Do not mount the active Kubernetes claim into a second pod for this job.

## Review SageMaker workload dependencies and access

Refresh AWS inventory and select the endpoint or model in **Relationships**. SageMaker model VPC configuration supplies subnet and security-group attachments. Same-account, same-region ECR image references supply repository dependencies. These links describe configuration and do not establish network reachability.

Run `python3 app.py --db "$DB" review-aws-workload-access "$PROJECT" "$WORKLOAD"` to simulate `s3:ListBucket` for each discovered execution role and artifact bucket pair. For endpoints, each pair comes from one deployed model. Results are saved through the existing AWS access review workflow. This simulation covers bucket listing. Check exact object access and resource policy separately.

[Amazon SageMaker model description](https://docs.aws.amazon.com/cli/latest/reference/sagemaker/describe-model.html)

## Enforce JSON policy at ingress

Start the service with `serve --relay-config relay.json` or mount `relay.json` in the Kubernetes configuration Secret. Configure a fixed upstream URL and project.

```json
{"project":"pilot","target":"https://upstream.example.test/v1/predict"}
```

Supply the upstream bearer credential as `DOOFUS_RELAY_UPSTREAM_TOKEN` if required. Route the protected POST path through `/api/v1/runtime/relay`. Clients authenticate to the relay with a short-lived inspection credential. Bind the upstream to trusted network paths so callers cannot bypass the relay. The relay screens JSON before forwarding and after receiving the response, and accepts only bounded JSON objects or arrays. It forwards no client headers and follows no redirects. This deployment handles one fixed JSON destination. It does not intercept arbitrary network traffic or stream responses.

## Block external dependencies in signed ONNX models

Install `requirements-onnx.txt` in the verification environment and use the signed release gate with `--format-policy onnx-inline`. The scanner parses the bounded model protobuf directly and rejects external tensor references, custom operator domains, model-local functions and training graphs. It inspects nested graph attributes without resolving files or running inference. This policy is for self-contained inference artifacts up to 64 MiB.

[ONNX external data format](https://onnx.ai/onnx/repo-docs/ExternalData.html)

## Deploy and run platform-local collection agents

Authored by Aniza Inc.

The engine accepts outbound HTTPS reports from collectors on AWS, Google Cloud Storage, Vertex AI, Azure Machine Learning, Oracle Cloud Infrastructure, IBM watsonx.ai, Salesforce, and ESXi/vCenter. A collector can run on a Linux or macOS management host with Python 3.11 or later. For ESXi and vCenter use a management host with network access to the VMware API. Prepare the host and give the collector account the provider access listed in the relevant connector section.

### Enroll from the web console

1. Sign in as a project administrator and open **Agents**. Choose the provider and enter its target arguments as a JSON array. An AWS example is `["123456789012","us-east-1"]`. Enroll the agent and save the one-time credential in the platform's secret manager.
2. Download the collector bundle and unpack it on the prepared host. Inject `DOOFUS_AGENT_TOKEN` from the secret manager, or place the credential in a file readable only by the collector account and supply `--token-file`. Clear the displayed credential in the console.
3. Start the poller on the host with `python3 agent.py --origin "$SPM_ORIGIN" run`. Use the central HTTPS origin. The poller starts with no provider action until a job is queued.
4. In **Agents**, choose **Run now**. Check **Run history** for the result and **Cloud syncs** for collection evidence. Rotate or revoke the agent from the same console.

The console enrolls the collector, distributes its bundle, and dispatches jobs to running pollers. Installing Python, provider tooling, and the initial poller process on a new host is a platform provisioning step.

### Deploy and run from the CLI

Inject a short-lived central project-admin credential as `DOOFUS_ADMIN_TOKEN`. Run the deployment command on the prepared target host with the project's `agent.py`.

```sh
python3 agent.py --origin "$SPM_ORIGIN" deploy aws "$AGENT_DIR" \
  --name account-inventory --target 123456789012 --target us-east-1 --run-now
```

The command downloads the packaged collector, enrolls it, writes the credential into a private file in the new directory, queues the run, and runs the first collection. For a persistent collector, use the installed bundle and launch this process through a service supervisor.

```sh
python3 "$AGENT_DIR/agent.py" run --config "$AGENT_DIR/agent.json" --token-file "$AGENT_DIR/agent.token"
```

The Linux systemd unit in `deploy/systemd/doofusai-agent@.service` expects each instance under `/opt/doofusai-agents/<instance>` and runs it as the `doofusai` service account. Set directory ownership and provider identity for that account before enabling the unit. Use `agent.py --origin "$SPM_ORIGIN" list`, `queue <id>`, and `jobs <id>` with the project-admin credential. `rotate <id>` returns a new credential once and invalidates the old one. Update the secret and restart the poller after rotation. `revoke <id>` cancels pending jobs and disables agent reporting. Agent credentials default to 24 hours and can be issued for 1–720 hours.

### Provider arguments and host credentials

| Provider | CLI target arguments, in order | Host prerequisite |
|---|---|---|
| AWS | Account ID, region, optional Access Analyzer ARN | AWS CLI and read-only AWS identity |
| Google Cloud Storage | Project ID or number | Google CLI and Application Default Credentials |
| Vertex AI | Project ID or number, region | Google CLI and Application Default Credentials |
| Azure | Subscription, resource group, workspace | Azure CLI and read-only Azure identity |
| Oracle Cloud | Compartment OCID, region | OCI CLI and read-only profile or workload identity |
| IBM Cloud | Deployment-space UUID, region | `DOOFUS_IBM_IAM_TOKEN` |
| Salesforce | My Domain host, org ID, optional API version | `DOOFUS_SALESFORCE_TOKEN`. API v68+ includes Agentforce metadata. |
| VMware | ESXi/vCenter host, optional port | Install `requirements-vsphere.txt`. Set `SPM_VSPHERE_USER` and `SPM_VSPHERE_PASSWORD`. For a private CA, set `DOOFUS_AGENT_VSPHERE_CA` to its PEM file. |

Use one active agent per project and inventory scope. Enrolling a scope transfers inventory reconciliation to the agent. The runner sends normalized inventory metadata and relationships without forwarding platform credentials. The engine gives jobs expiring leases and deduplicates report retries. A failed collection keeps the previous inventory. Set the HTTPS ingress request-body allowance to at least 2 MiB for `/api/v1/agent/report`. Report coverage currently includes inventory and its existing posture assessments.
