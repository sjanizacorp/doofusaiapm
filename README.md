# DoofusAI SPM v4

**Authored by Aniza Inc.**

DoofusAI Security Posture Management is a self-hosted application for reviewing the security of AI infrastructure. It gives security teams, cloud administrators and AI operations teams a shared place to see collected assets, understand their relationships, review findings and track the next action.

The central engine combines supported cloud and VMware inventory with configuration assessments, data sensitivity evidence, selected access reviews and runtime findings. Administrators can collect directly from the server or add platform-local agents that report over HTTPS. Both collection methods feed the same workspace; adding an agent preserves direct server collection.

[Download the client package](https://github.com/sjanizacorp/doofusaiapm/releases/download/v4-client-2026-11-18/doofusai-spm-v4-client.zip) or [watch the product demo](https://github.com/sjanizacorp/doofusaiapm/releases/download/v4-client-2026-11-18/doofusai-spm-v4-demo.mp4). The narrated walkthrough covers installation, configuration, administration and user workflows, with explanatory captions and background music.

## What you can do with DoofusAI

- **Build an AI infrastructure inventory.** Create named connections such as “My AWS account” or “My Azure account,” test read-only access and run scans. Choose an inventory object set to see assets from that connection, retained provider metadata, discovered relationships and available assessment evidence. Objects without applicable assessments remain visible.
- **Investigate configuration risk.** Follow supported relationships among models, endpoints, agents, execution identities, storage, networks and repositories. Review sensitivity labels and selected access decisions alongside configuration exposure evidence.
- **Track remediation.** Review issues, prioritize work, assign owners, record time-limited exceptions and compare findings after configuration changes. Export supported security events and signed audit records for downstream review.
- **Review data protection evidence.** Combine imported sensitivity classifications and operator labels with bounded S3 and Google Cloud Storage content samples. Supported detectors identify email, credential, labeled U.S. SSN and checksum-valid payment-card candidates; sampled text is excluded from reports and audit events.
- **Know and manage your posture checks.** Browse the check catalogue, inspect evidence requirements, plan scans and read exact rule execution records. Administrators can build custom declarative checks, test and preview them, stage versioned packs, activate or roll back revisions and configure signed HTTPS update feeds.
- **Check model releases.** Verify signed manifests and optional external scanner reports, inspect supported artifact formats and run fixed behavioral checks against an approved staging deployment. Apply supported policies in release pipelines.
- **Protect participating applications.** Integrate text screening, model authorization, registered tool mediation or a fixed-destination JSON relay. Controls apply where the application or gateway has been configured to use them.
- **Collect from distributed environments.** Enroll platform-local collectors, download their bundles, queue on-demand work, configure recurring collection and review run history. Provider credentials stay on the collection host.

## Where it fits in an enterprise

DoofusAI supports the investigation and remediation workflow between cloud infrastructure, AI engineering and security operations. Cloud administrators configure read-only collection; security analysts examine evidence and issues; AI teams verify model releases; project administrators manage access and audit exports.

A typical deployment places the browser console and engine behind the organization’s HTTPS reverse proxy. The engine stores project inventory, assessments and audit records in SQLite. Direct collectors call provider APIs from the server. Additional agents call their assigned provider APIs locally and send reports to the engine over outbound HTTPS.

Projects and viewer, operator and administrator roles organize access. Local username/password accounts are available, or administrators can configure Microsoft Entra ID or AD FS sign-in. Organization MFA and conditional access remain with the identity provider.

The current service uses one serving database writer. Capacity, backup placement, recovery procedures, identity integration and network access must be qualified for the intended environment before production use.

## Supported platforms and collection scope

Coverage depends on the configured service, permissions and available provider evidence. A connection does not inventory every service in a provider account.

| Platform | Supported collection examples |
|---|---|
| AWS | SageMaker models and endpoints, selected Bedrock agent metadata, execution roles, artifact bucket references, model VPC attachments and same-account ECR references. Optional Access Analyzer evidence and scoped role policy simulations. |
| Google Cloud | Cloud Storage configuration, Vertex AI models, endpoints and agents, source relationships, imported sensitivity profiles and selected permission checks. |
| Azure | Machine Learning models and endpoints, optional Foundry agents, workspace relationships and selected direct managed-identity RBAC evidence. |
| Oracle Cloud | Data Science projects, models and deployments, with supported deployment bindings and access-log evidence. |
| IBM Cloud | watsonx.ai space models and deployments, known model references and lifecycle assessments. |
| Salesforce | Organization and Flow metadata, plus authorized Agentforce definitions and versions through supported Metadata API access. |
| VMware ESXi / vCenter | Hosts, virtual machines, datastores and networks through the vSphere API. Selected checks include lockdown, VM logging and EFI Secure Boot. Named-user privilege reviews require vCenter. |

## How DoofusAI evaluates evidence

The product uses provider metadata, deterministic checks, imported classifications, scoped permission evaluations and supported scanner results to explain findings. Its platform agents are read-only collectors, rather than autonomous remediation agents. They do not require a language model to collect inventory.

Dependency inventory supports CycloneDX, GitHub dependency-graph imports and offline npm lockfiles. The relationship graph combines declared relationships with supported provider-discovered links. Missing, stale, truncated or inconclusive evidence remains distinguishable from a successful check.

Artifact inspection covers supported Safetensors, GGUF v3, restricted model ZIP, data-only Pickle/checkpoint and ONNX dependency profiles. Inspection does not deserialize a model or run inference. Runtime integrations include configured text gateway routes, buffered SSE checks and registered application tools. These checks do not establish complete model safety, complete effective authorization or arbitrary network-level enforcement.

## Download, install and create an administrator

The client distribution runs on Linux or macOS and requires an installed **CPython 3.13** base interpreter. The package includes the application, lifecycle controls, operating instructions and illustrated PDF manuals. The installer creates a dedicated virtual environment; it does not download the base interpreter.

1. Download and extract the client ZIP. Open a terminal in the extracted folder and read `START-HERE.txt`.
2. Run `./install.sh`. Enter a dedicated installation directory when prompted, or press Enter to accept the displayed default. For unattended installation, use `./install.sh --installdir "/path/to/DoofusAI"`.
3. Follow the installation progress messages. They print the exact installed commands for the selected directory.
4. Create your first administrator with the printed `bin/spm.sh set-local-user ModelOps alex.smith admin` command. Replace ModelOps and alex.smith with your project and username. Enter a 12–128 character passphrase twice; password entry is hidden.
5. Run the printed start command, open the displayed console address and sign in. The default address is `http://127.0.0.1:8000` on the service host. Use an approved HTTPS ingress for access from other hosts.

No default administrator or password is created. Local usernames, roles, salts and password hashes reside in `data/posture.sqlite` under the installation directory, in the `local_users` table. Readable passwords are not stored. To reset a password, repeat the account command; resetting revokes previous local sessions. Protect the database and its backups.

Service and SSO settings reside in `config/`. Cloud credentials are configured separately through approved provider CLI profiles, SDK configuration or environment variables on the collection host. The console shows configured credential profile names rather than provider secrets. Read `OPERATOR-REFERENCE.txt` for provider and identity configuration.

## Connect a platform and run your first scan

1. Prepare the required provider CLI or VMware SDK and a read-only identity on the collection host.
2. Sign in as an administrator and open **Connections**. Enter a descriptive name, choose the platform and complete its target fields using the visible examples.
3. Select the server identity or a configured credential profile, then save and test the connection. Testing reads supported inventory without saving it.
4. Choose **Run scan** and refresh the operation results. Scanning saves supported inventory and assessments; tool, permission and authentication failures appear in operation history.
5. Open **Inventory**, choose the connection’s object set and inspect assets. Use **Relationships**, **Issues**, **Data posture**, **Access reviews** and **Scan history** to investigate available evidence and follow-up work.

## Keep the console current

Data views check for updates every five seconds by default. Choose 15 or 30 seconds, pause updates, or use **Refresh current view**. The console preserves account object sets, pages, relationship scopes and selected details when they remain available. Connection results and selected agent job histories update in place. The API console continues to run requests explicitly.

Updates pause while you edit or have unsaved form changes. Requests from an earlier view or selection cannot overwrite a newer screen. Network and proxy failures retain the current view with a readable error, and sign-out remains available after session expiry. Automatic refresh reads stored evidence; it does not start provider scans.

## Browse, customize and update checks

Open **Checks & policies** to search the 19 shipped posture checks and inspect their applicability, expected values, evidence requirements, remediation, reference links and revision. Plan a scan for an existing asset before running it. New scan reports preserve the configured catalogue digest and an execution record showing evaluated, skipped and disabled rules; missing or incompatible evidence is unknown.

Administrators can use the custom-check builder or import a JSON pack. Rules use typed comparisons against collected facts; they do not execute uploaded code or discover new provider fields. Validate regression fixtures, preview against saved inventory, stage the candidate and activate its revision. Export a pack to edit it, preserve its other rules and increase the version. Retained versions support explicit rollback. Disabling a check does not resolve existing findings.

For online updates, configure a trusted publisher's direct public HTTPS feed and independently obtained public key. The running service checks due sources at the configured interval. Notify, stage and automatic activation modes are available. Signature, schema, regression-fixture, immutable-version and downgrade checks protect updates. A new feed revision cannot silently overwrite a retained revision or undo an operator rollback by repeating the same version.

No public Aniza update feed is bundled. Vendor web pages and native vendor policy definitions are not directly executable packs; a publisher must map supported guidance to the collected evidence model and publish tested normalized rules. The [Checks & API Guide](https://github.com/sjanizacorp/doofusaiapm/releases/download/v4-client-2026-11-18/doofusai-spm-v4-checks-api.pdf) covers these workflows and the CLI/API.

## Add platform-local collectors

In **Agents**, choose a platform, complete its scope fields and enroll the collector. Save its one-time credential securely, download the bundle and start the poller on a prepared host. Then use **Run now** or configure a recurring frequency from five minutes to daily. Review **Run history** and **Cloud syncs** for results.

Credentials are scoped and expiring. Queued jobs use leases, and failed collections preserve prior inventory. The running poller must check in for work to be dispatched. Initial host provisioning and starting the poller are operator steps; automatic host provisioning and change/risk-event-triggered collection remain development work.

## Operate and maintain the service

Lifecycle scripts show progress and next-step instructions. Use the installed `bin/status.sh`, `bin/stop.sh` and `bin/start.sh` controls, or pass `--installdir` to scripts in the extracted package. Logs reside in `logs/service.log`. Back up and verify the database before upgrades, and exercise restore procedures in a separate environment.

Uninstall stops the service and removes application files, controls and the virtual environment. It retains data, configuration and logs, including account hashes and other sensitive records. Protect retained files. Reinstall from an extracted package using the same installation directory to reuse that state.

## Product manuals and demo

All manuals are authored by Aniza Inc. and contain screenshots, illustrations and step-by-step instructions. Copies are included in the archive’s `manuals/` folder.

- [Administration Manual](https://github.com/sjanizacorp/doofusaiapm/releases/download/v4-client-2026-11-18/doofusai-spm-v4-administration.pdf): installation, administrator setup, access, backup, recovery and lifecycle controls.
- [Configuration Manual](https://github.com/sjanizacorp/doofusaiapm/releases/download/v4-client-2026-11-18/doofusai-spm-v4-configuration.pdf): installation layout, connectivity, provider identities, sign-in and agents.
- [User Guide](https://github.com/sjanizacorp/doofusaiapm/releases/download/v4-client-2026-11-18/doofusai-spm-v4-user-guide.pdf): sign-in, inventory, scans, issues and evidence review.
- [Checks & API Guide](https://github.com/sjanizacorp/doofusaiapm/releases/download/v4-client-2026-11-18/doofusai-spm-v4-checks-api.pdf): catalogue, custom checks, fixtures, preview, revision management, signed feeds and API procedures.
- [Narrated product demo](https://github.com/sjanizacorp/doofusaiapm/releases/download/v4-client-2026-11-18/doofusai-spm-v4-demo.mp4): installation, configuration, administration and user workflows.
- [Release files and checksums](https://github.com/sjanizacorp/doofusaiapm/releases/tag/v4-client-2026-11-18): downloads and integrity checks.

## Validation and current limits

Release qualification includes 103 automated product checks, 10 lifecycle checks and a 25-scenario browser audit. The browser audit covers all 14 administrator tabs, role-specific views, 71 distinct button labels, saved changes, draft protection, delayed responses, error recovery and narrow layouts. Testing used controlled environments and simulated identity providers.

Live provider accounts, live identity tenants, production-scale traffic and physical-node failover require deployment-specific testing. Broader service discovery, comprehensive cross-provider access analysis, native behavioral model threat detection and wider runtime enforcement remain areas for further development. The current release is suitable for evaluation in a controlled enterprise pilot; full commercial-platform parity and production readiness have not been demonstrated.

## Software notice

Authored by Aniza Inc. This software is provided “as is,” without warranty of any kind, express or implied. Use is at your own risk. The author is not liable for claims, damages or other liability arising from use of the software. This notice does not replace review of applicable third-party component licenses or establish a separate commercial license.
