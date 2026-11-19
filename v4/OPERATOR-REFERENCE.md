# DoofusAI SPM v4 operator reference

Authored by Aniza Inc.

## Configuration files

Place these files in `config/` under your installation directory. Stop and restart the service after a change. The installer manages `service.json`; use `install.sh --port` and `--listen-address` to change its settings. Keep the default local listener unless an approved proxy needs remote access.

- **Organization identity.** Put the issuer's RSA public signing key in `config/` and create `issuer.json` using the issuer URL, expected API audience, allowed client IDs, and the signing key's actual key ID. Keys may be listed by relative path. Ask your identity administrator to issue RFC 9068 RS256 access tokens. Optional browser device sign-in requires a separately configured and tested provider device flow.
- **Metrics.** Place the monitoring bearer token in `metrics.token` and restrict the file to the service account. Scrape `/metrics` with that credential.
- **Model traffic.** For approved deployments, `gateway.json` configures model chat routes and `relay.json` pins a project to a fixed JSON upstream. Store upstream secrets through your approved process environment or supervisor. Keep provider hosts and broad network access behind appropriate policy.

Example issuer settings. Replace every sample value with one supplied by your identity administrator.

```json
{
  "issuer": "https://id.example.com",
  "audience": "doofusai-api",
  "clients": ["doofusai-client"],
  "keys": {"issuer-key-id": "issuer-public.pem"}
}
```

Map an identity using its stable subject value rather than its display name.

```sh
./spm.sh map-identity https://id.example.com opaque-subject ModelOps Reader viewer
./spm.sh unmap-identity https://id.example.com opaque-subject
```

## Direct collection is available without agents

Use existing direct server connector commands when the service host has approved provider access. For example, the command below refreshes a Google Cloud Storage scope using its local Application Default Credentials. Agents can be enrolled independently for the same scope.

```sh
./spm.sh sync-gcs ModelOps my-cloud-project
```

Open **Cloud syncs** to check the refresh and **Inventory** to review the updated assets. Use an approved credential for the provider and project. The commands for your installation are listed by `./spm.sh --help`.

## Collector host prerequisites

Use the provider's approved read-only permissions. On the collector host, use AWS CLI credentials for AWS, Google Application Default Credentials for Google, Azure CLI credentials for Azure, and an OCI CLI profile for Oracle. For IBM Cloud inject `DOOFUS_IBM_IAM_TOKEN`. For Salesforce inject `DOOFUS_SALESFORCE_TOKEN`. For VMware install `requirements-vsphere.txt` in the collector Python environment and set `SPM_VSPHERE_USER`, `SPM_VSPHERE_PASSWORD`, and optional `DOOFUS_AGENT_VSPHERE_CA`.

Direct server connectors remain available for scopes with enrolled agents. If a direct sync completes while an agent job is running, the stale agent snapshot is cancelled. The engine and agents use distinct credentials. Serve the central engine behind an approved HTTPS ingress with a request limit large enough for agent reports of up to 2 MiB. Agents need outbound connectivity to the central engine and their assigned provider APIs. A waiting agent polls until an administrator selects **Run now**. To run a queued job once, add `--once` to the poller command.

## Maintenance

Keep verified backups outside the installation directory. Test restoration in a separate installation. Contact the system owner before using recovery promotion on production or changing a source-of-record database. The default installation does not register an automatic startup service. Arrange supervised startup with your platform administrator if required.

## Configure cloud connections in the console

Open **Connections** as a project administrator. Choose the platform, use the visible examples and field hints to enter its account or workspace target, choose a server credential profile, and select **Save connection**. **Test connection** reads provider inventory without saving it. **Run scan** updates inventory and the existing assessments. Choose **Refresh results** for operation status. Results then appear in Inventory, Relationships, Issues, and Cloud syncs.

The default profile uses the server's existing read-only identity. To offer multiple identities, set the service environment variable `DOOFUS_CONNECTION_PROFILES` to the absolute path of a JSON profile file with permissions 600. Restart the service after changing its environment. The console receives profile names only. Example contents follow.

```json
{
  "aws-production": {"AWS_PROFILE": "read-only-production"},
  "azure-production": {"AZURE_CONFIG_DIR": "/secure/azure-production"},
  "oracle-production": {"OCI_CLI_PROFILE": "READ_ONLY"},
  "ibm-production": {"DOOFUS_IBM_IAM_TOKEN": "replace-with-current-token"},
  "vmware-production": {
    "SPM_VSPHERE_USER": "readonly@example",
    "SPM_VSPHERE_PASSWORD": "replace-with-current-password",
    "DOOFUS_AGENT_VSPHERE_CA": "/secure/vcenter-ca.pem"
  }
}
```

Use a Google profile with `CLOUDSDK_CONFIG` pointing to the intended Google CLI configuration. Authenticate its Application Default Credentials. Salesforce profiles use `DOOFUS_SALESFORCE_TOKEN`. Keep this file under the secret management and rotation process. Install AWS, Google, Azure and OCI tools, and the VMware SDK as appropriate on the server or on a chosen agent host.

## Local username and password

Create or reset a local account with `./spm.sh set-local-user ModelOps alex.smith admin`. Enter a passphrase of 12–128 characters twice. The stored value is a salted PBKDF2 hash. After five failed attempts the account is locked for 15 minutes. Password reset clears the lock and revokes existing local sessions. Browser sessions last eight hours and Sign out revokes the current browser session.

## Active Directory and Entra ID sign-in

Use OpenID Connect authorization code flow for a single Entra tenant or an Active Directory Federation Services deployment with OIDC enabled. Active Directory Domain Services users sign in through their configured Entra or AD FS provider. Install `requirements-sso.txt` in the Python 3.13 environment running the product. Register the application's exact HTTPS root URL as a web redirect URI with the identity provider.

Place `sso.json` in the installation's `config/` folder. Replace the following tenant and application IDs with your own. Supply `DOOFUS_SSO_CLIENT_SECRET` in the service environment if the registered confidential client requires it.

```json
{
  "issuer": "https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0",
  "discovery_url": "https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0/.well-known/openid-configuration",
  "client_id": "YOUR-APPLICATION-ID",
  "redirect_uri": "https://spm.example.com/"
}
```

For AD FS, use the issuer and discovery URL published by your federation administrator, typically `https://adfs.example.com/adfs/.well-known/openid-configuration` for discovery. The discovered issuer must exactly match configuration.

Map the authorized subject to a project using `./spm.sh map-identity <issuer> <subject> ModelOps alex.smith admin`. The stable subject comes from the provider. End users sign in at the familiar provider page with their normal credentials. Restart the product after configuring SSO. Confirm that the **Sign in with AD / Entra ID** button appears, that an authorized user enters the correct project, and an unmapped account is denied. Changing or deleting a mapping revokes its existing browser sessions. Keep identity-provider MFA and conditional access policies enabled as required by your organization.

The callback verifies the authorization state, PKCE challenge, ID token signature, issuer, audience, expiry, and nonce. Validate this configuration in your real tenant before production use.


## Choose the installation directory

Run `./install.sh` to choose the destination interactively. The prompt shows the default destination. Enter a different dedicated path or press Enter to accept the default.

For an unattended install, supply `./install.sh --installdir "/path/to/DoofusAI"`. Quote paths containing spaces. Use the same option with start, stop, status, uninstall, or spm when running the controls from an extracted package. The controls installed under the chosen directory's bin folder infer that installation location. The older --prefix spelling remains supported.

The installer preserves data and configuration when reinstalling in an existing product directory, and rejects a nonempty directory that does not contain a DoofusAI installation marker.


## Python compatibility

Lifecycle scripts check the Python version and compiled runtime compatibility before starting. They prefer python3.13 and check standard Python 3.13 locations. If your default python3 is 3.9, 3.14, or 3.15, it will not be used for the compiled client. For a custom installation use `DOOFUS_PYTHON=/path/to/python3.13 ./install.sh`. An explicit incompatible override is rejected with a setup message.


## Installation virtual environment

Installation creates a dedicated CPython 3.13 environment at <installation>/venv. The service and product CLI run with that environment, including when launched from the extracted package using --installdir. You do not need to activate it manually. Reinstall reuses the environment and preserves its installed packages; uninstall removes the environment while retaining data, configuration, and logs.

Install optional Python integrations into this environment. For example, run `"/path/to/installation/venv/bin/python" -m pip install -r "/path/to/installation/runtime/requirements-sso.txt"` to enable OIDC sign-in. VMware and ONNX have their own requirements files in the same runtime folder. Provider command-line tools retain their normal installation and credential setup.

A virtual environment uses the selected Python 3.13 installation. Keep that base interpreter installed. If Python 3.13 is unavailable, the launcher explains how to select it before installation can continue.
