"use strict";

const byId = (id) => document.getElementById(id);
let credential = "";
let user;
const types = {
  storage: { encrypted: "Encrypted at rest", public: "Public access" },
  registry: { signatures_required: "Trusted signatures required", public: "Public access" },
  agent: { approval_required: "Sensitive actions require approval", redaction_enabled: "Sensitive-data redaction enabled" },
};

// A response may update the screen only while its session, view and interaction remain current.
let viewVersion = 0;
let interactionVersion = 0;
let activeView = "";
let activeActions = 0;
let refreshing = false;
let inventoryAfter = "";
let dataAfter = "";
let ruleBefore = "";
let selectedDetail = null;
let plannedAsset = "";
const detailActions = new Map();
const responseCache = new Map();
const drafts = new Set();
const draftEdits = new WeakMap();
const savingElements = new Map();
let editVersion = 0;
let loadingView = -1;
class StaleResponse extends Error {}
function context() { return [credential, viewVersion, interactionVersion]; }
function isCurrent(stamp) { return stamp[0] === credential && stamp[1] === viewVersion && stamp[2] === interactionVersion; }
function hasDrafts() {
  for (const element of drafts) if (!element.isConnected) drafts.delete(element);
  return [...drafts].some((element) => element.closest(".view")?.id === activeView);
}
function isEditing() {
  const element = document.activeElement;
  return element?.matches("input:not([readonly]),textarea,select") && element.closest(".view")?.id === activeView;
}
function trackDraft(event) {
  if (!event.target.closest(".view")) return;
  editVersion++;
  const form = event.target.closest("form");
  if (form && !["local-session", "session", "issue-filter", "check-plan-form", "api-form"].includes(form.id)) { drafts.add(form); draftEdits.set(form, editVersion); }
  if (event.target.closest("#agent-list") && event.target.tagName === "SELECT") {
    const group = event.target.closest("label").parentElement; drafts.add(group); draftEdits.set(group, editVersion);
  }
  if (event.target.closest("#data-posture-detail") && event.target.tagName === "SELECT") {
    const group = byId("data-posture-detail"); drafts.add(group); draftEdits.set(group, editVersion);
  }
}
byId("workspace").addEventListener("input", trackDraft);
byId("workspace").addEventListener("change", trackDraft);

function protectedDrafts() {
  hasDrafts();
  return [...drafts].some((element) => element.closest(".view")?.id === activeView &&
    (!savingElements.has(element) || draftEdits.get(element) > savingElements.get(element)));
}
async function call(path, body, method = "POST", cacheResult = true) {
  const originalEdit = editVersion;
  const protectsForms = body === undefined && loadingView !== viewVersion &&
    ["/api/v1/issues", "/api/v1/data-posture", "/api/v1/agents", "/api/v1/checks"].includes(path.split("?")[0]);
  const stamp = context();
  const background = refreshing && activeActions === 0;
  const request = { headers: { Authorization: "Bearer " + credential }, cache: "no-store" };
  if (body !== undefined) {
    request.method = method;
    request.headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(body);
  }
  let response;
  try { response = await fetch(path, request); }
  catch (error) {
    if (!isCurrent(stamp)) throw new StaleResponse();
    throw Error("Cannot reach the server. Check your connection and retry.");
  }
  let data;
  try { data = await response.json(); }
  catch (error) {
    if (!isCurrent(stamp)) throw new StaleResponse();
    throw Error("The server returned an unexpected response (HTTP " + response.status + "). Retry or contact your administrator.");
  }
  if (!isCurrent(stamp) || (background && (hasDrafts() || isEditing())) ||
      (protectsForms && (originalEdit !== editVersion || protectedDrafts()))) throw new StaleResponse();
  if (!response.ok) {
    if (response.status === 401 && user) {
      byId("auto-refresh").value = "0";
      byId("refresh-status").textContent = "Session expired. Sign out and sign in again.";
      throw Error("Your session expired. Sign out and sign in again.");
    }
    throw Error(data.error || "Request failed (HTTP " + response.status + ").");
  }
  if (body === undefined && cacheResult) {
    responseCache.set(path, JSON.stringify(data));
    if (responseCache.size > 200) responseCache.delete(responseCache.keys().next().value);
  }
  return { status: response.status, data };
}

function perform(action) {
  return async (event) => {
    event.preventDefault();
    interactionVersion++;
    const stamp = context();
    const button = event.submitter ?? event.currentTarget;
    const form = button.closest("form");
    const dirtyGroups = [...drafts].filter((element) => element.contains(button) || element === form);
    const submittedEdit = editVersion;
    const saving = [...new Set([...dirtyGroups, ...(form ? [form] : [])])];
    for (const element of saving) savingElements.set(element, submittedEdit);
    const clearSubmitted = () => { for (const element of dirtyGroups) if ((draftEdits.get(element) || 0) <= submittedEdit) drafts.delete(element); };
    byId("status").textContent = "";
    button.disabled = true;
    activeActions++;
    try {
      await action();
      clearSubmitted();
    } catch (error) {
      if (error instanceof StaleResponse) clearSubmitted();
      if (!(error instanceof StaleResponse) && stamp[0] === credential && stamp[2] === interactionVersion) byId("status").textContent = error.message;
    } finally {
      button.disabled = false;
      for (const element of saving) savingElements.delete(element);
      activeActions--;
    }
  };
}

function watchedPaths() {
  const detail = selectedDetail?.view === activeView ? selectedDetail.key : "";
  const id = detail?.slice(detail.indexOf(":") + 1);
  const paths = {
    inventory: ["/api/v1/inventory/sets", "/api/v1/inventory/objects?set=" + encodeURIComponent(inventorySet) + "&after=" + encodeURIComponent(inventoryAfter)],
    issues: ["/api/v1/issues?status=" + byId("issue-status").value],
    history: ["/api/v1/scans"], checks: ["/api/v1/checks"],
    relationships: ["/api/v1/graph/nodes", "/api/v1/graph/edges", "/api/v1/cloud-graph"],
    boms: ["/api/v1/boms"], runtime: ["/api/v1/runtime-findings"], syncs: ["/api/v1/sync-runs"],
    connections: ["/api/v1/connections"], agents: ["/api/v1/agents"],
    "data-posture": ["/api/v1/data-posture" + (dataAfter ? "?after=" + encodeURIComponent(dataAfter) : "")],
    "access-reviews": ["/api/v1/access-reviews"], audit: ["/api/v1/audit"], api: [],
  }[activeView] || [];
  if (activeView === "checks" && user.role === "admin") paths.push("/api/v1/rule-packs" + (ruleBefore ? "?before=" + ruleBefore : ""), "/api/v1/rule-sources");
  if (activeView === "connections" && detail) paths.push("/api/v1/connections/" + id + "/runs");
  if (activeView === "agents" && detail) paths.push("/api/v1/agents/" + id + "/jobs");
  if (activeView === "relationships" && byId("cloud-scope").value) paths.push("/api/v1/cloud-graph?scope=" + encodeURIComponent(byId("cloud-scope").value));
  if (activeView === "access-reviews" && detail) paths.push("/api/v1/access-reviews/" + id);
  if (activeView === "issues" && detail) paths.push("/api/v1/issues/" + id, "/api/v1/issues/" + id + "/exceptions");
  return paths;
}
async function refreshView(force = false) {
  if (!user || !activeView || refreshing || activeActions || document.hidden) return;
  if (hasDrafts() || isEditing()) {
    byId("refresh-status").textContent = "Updates paused while editing. Save your changes to resume.";
    return;
  }
  refreshing = true;
  const stamp = context();
  try {
    let changed = force;
    for (const path of watchedPaths()) {
      const before = responseCache.get(path);
      const {data} = await call(path, undefined, "POST", false);
      if (before !== JSON.stringify(data)) changed = true;
    }
    if (!isCurrent(stamp) || hasDrafts() || isEditing()) return;
    if (changed) await navigate(activeView, true);
    if (isCurrent(stamp)) byId("refresh-status").textContent = "Last checked " + new Date().toLocaleTimeString();
  } catch (error) {
    if (!(error instanceof StaleResponse) && isCurrent(stamp)) byId("refresh-status").textContent = "Refresh failed: " + error.message + " Your current view is retained.";
  } finally { refreshing = false; }
}
byId("refresh-view").onclick = async () => {
  const button = byId("refresh-view"); button.disabled = true;
  try { await refreshView(true); }
  catch (error) { byId("refresh-status").textContent = error.message; }
  finally { button.disabled = false; }
};
let lastRefresh = 0;
setInterval(() => {
  const seconds = Number(byId("auto-refresh").value);
  if (seconds && Date.now() - lastRefresh >= seconds * 1000) { lastRefresh = Date.now(); refreshView(); }
}, 1000);

function fillFacts() {
  const fields = Object.entries(types[byId("kind").value]).map(([key, name]) => {
    const label = document.createElement("label");
    label.textContent = name;
    const field = document.createElement("select");
    field.name = key;
    for (const [value, text] of [["", "Unknown"], ["true", "Yes"], ["false", "No"]]) {
      field.add(new Option(text, value));
    }
    label.append(field);
    return label;
  });
  byId("facts").replaceChildren(...fields);
}

function row(text, label, action, detailKey = null) {
  const entry = document.createElement("div");
  entry.className = "entry";
  const summary = document.createElement("span");
  summary.textContent = text;
  entry.append(summary);
  if (action) {
    const button = document.createElement("button");
    button.textContent = label;
    if (detailKey) detailActions.set(detailKey, action);
    button.onclick = perform(async () => {
      if (detailKey) selectedDetail = {view: activeView, key: detailKey};
      await action();
    });
    entry.append(button);
  }
  return entry;
}

const agentTargets = {
  aws: ["AWS account ID", "AWS region", "Access Analyzer ARN (optional)"],
  gcs: ["Google project ID"], vertex: ["Google project ID", "Google region"],
  azure: ["Azure subscription ID", "Resource group", "ML workspace"],
  oci: ["OCI compartment OCID", "OCI region"], ibm: ["IBM deployment space UUID", "IBM region"],
  salesforce: ["Salesforce My Domain hostname", "Salesforce organization ID", "API version (optional)"],
  vsphere: ["vCenter or ESXi hostname", "Port (optional)"],
};

const fieldExamples = {
  "AWS account ID": ["123456789012", "Your 12-digit AWS account number."],
  "AWS region": ["us-east-1", "Choose the region containing your SageMaker or Bedrock resources."],
  "Access Analyzer ARN (optional)": ["arn:aws:access-analyzer:us-east-1:123456789012:analyzer/read-only", "Leave blank to collect without Access Analyzer findings."],
  "Google project ID": ["my-model-project", "Use the project ID from Google Cloud, rather than its display name."],
  "Google region": ["us-central1", "Use the region containing your Vertex AI resources."],
  "Azure subscription ID": ["12345678-1234-1234-1234-123456789abc", "Copy the subscription ID from the Azure portal."],
  "Resource group": ["rg-model-production", "The resource group containing your ML workspace."],
  "ML workspace": ["production-ml", "The Azure Machine Learning workspace name."],
  "OCI compartment OCID": ["ocid1.compartment.oc1..example", "Copy the full compartment OCID from Oracle Cloud. Replace this illustration."],
  "OCI region": ["us-ashburn-1", "The region containing your Data Science resources."],
  "IBM deployment space UUID": ["12345678-1234-1234-1234-123456789abc", "Copy the watsonx.ai deployment space ID."],
  "IBM region": ["us-south", "The region hosting your watsonx.ai deployment space."],
  "Salesforce My Domain hostname": ["company.my.salesforce.com", "Enter the hostname without https:// or a trailing slash."],
  "Salesforce organization ID": ["00D000000000001", "Copy your org ID from Salesforce Company Information."],
  "API version (optional)": ["68.0", "Use 68.0 or later for Agentforce discovery; blank uses 63.0."],
  "vCenter or ESXi hostname": ["vcenter.example.com", "Use a hostname reachable from the collector."],
  "Port (optional)": ["443", "Leave blank for the standard HTTPS port 443."],
};
function targetField(name, index, prefix) {
  const label = document.createElement("label");
  const id = prefix + "-" + index;
  label.htmlFor = id;
  const title = document.createElement("span");
  title.textContent = name;
  const input = document.createElement("input");
  input.id = id;
  input.maxLength = 300;
  input.required = !name.includes("(optional)");
  input.placeholder = fieldExamples[name][0];
  const hint = document.createElement("small");
  hint.id = id + "-help";
  hint.className = "field-help";
  hint.textContent = "Example: " + fieldExamples[name][0] + ". " + fieldExamples[name][1];
  input.setAttribute("aria-describedby", hint.id);
  label.append(title, input, hint);
  return label;
}

let connectionRequirements = {};
for (const option of byId("agent-provider").options) {
  byId("connection-provider").add(new Option(option.text, option.value));
}
byId("connection-provider").onchange = () => {
  const provider = byId("connection-provider").value;
  byId("connection-fields").replaceChildren(...agentTargets[provider].map(
    (name, index) => targetField(name, index, "connection")));
  byId("connection-help").textContent = connectionRequirements[provider] ?? "";
};
byId("connection-provider").onchange();
byId("connection-form").onsubmit = perform(async () => {
  const args = Array.from(byId("connection-fields").querySelectorAll("input"), (input) => input.value.trim());
  while (args.length && !args[args.length - 1]) args.pop();
  await call("/api/v1/connections", {
    name: byId("connection-name").value, provider: byId("connection-provider").value,
    arguments: args, profile: byId("connection-profile").value,
  });
  await loadConnections();
  byId("status").textContent = "Connection saved. Choose Test connection or Run scan.";
});
async function loadConnections() {
  const { data } = await call("/api/v1/connections");
  connectionRequirements = data.requirements;
  const select = byId("connection-profile");
  const previous = select.value;
  select.replaceChildren(...data.profiles.map((name) => new Option(
    name === "server" ? "Current server identity" : name, name)));
  if (data.profiles.includes(previous)) select.value = previous;
  byId("connection-help").textContent = data.requirements[byId("connection-provider").value];
  async function history(connection) {
    selectedDetail = {view: "connections", key: "connection:" + connection.id};
    const { data } = await call("/api/v1/connections/" + connection.id + "/runs");
    byId("connection-runs").replaceChildren(row(connection.name + " results"),
      ...data.runs.map((run) => row([run.mode, run.status, run.created_at,
        run.result?.error ?? (run.status === "completed" ? "Successful" : "Use Refresh results for progress"),
      ].join(" · "))));
  }
  byId("connection-list").replaceChildren(...data.connections.map((connection) => {
    const group = document.createElement("div");
    const path = "/api/v1/connections/" + connection.id;
    group.append(row([connection.name, connection.provider, connection.scope, connection.profile].join(" · ")));
    for (const [operation, label] of [["test", "Test connection"], ["scan", "Run scan"]]) {
      group.append(row("", label, async () => {
        await call(path + "/" + operation, {});
        byId("status").textContent = "Operation started. Choose Refresh results to check progress.";
        await history(connection);
      }));
    }
    group.append(row("", "Refresh results", () => history(connection), "connection:" + connection.id));
    group.append(row("", "Remove connection", async () => {
      if (!window.confirm("Remove this saved connection? Collected inventory is retained.")) return;
      await call(path, {}, "DELETE");
      await loadConnections();
    }));
    return group;
  }));
  if (!data.connections.length) byId("connection-list").textContent = "No connections configured.";
  if (selectedDetail?.view === "connections" && !data.connections.some((item) => "connection:" + item.id === selectedDetail.key)) {
    selectedDetail = null; byId("connection-runs").replaceChildren();
  }
}

function revealAgentToken(token) {
  byId("agent-token").value = token;
  byId("agent-secret").hidden = !token;
}

async function loadAgents() {
  const { data } = await call("/api/v1/agents");
  const list = byId("agent-list");
  if (!data.agents.length) {
    list.replaceChildren(row("No agents enrolled."));
    return;
  }
  list.replaceChildren(...data.agents.map((agent) => {
    const group = document.createElement("div");
    const path = "/api/v1/agents/" + encodeURIComponent(agent.id);
    async function jobs() {
      selectedDetail = {view: "agents", key: "agent:" + agent.id};
      const { data } = await call(path + "/jobs");
      byId("agent-jobs").replaceChildren(row(agent.name + " collections"),
        ...data.jobs.map((job) => row([job.created_at, job.status, job.id].join(" · "))));
    }
    group.append(row([agent.name, agent.provider, agent.scope,
      agent.revoked_at ? "Revoked" : "Credential expires " + agent.expires_at,
      agent.last_seen ? "Last seen " + agent.last_seen : "Awaiting first check-in",
    ].join(" · "), "Run history", jobs, "agent:" + agent.id));
    if (!agent.revoked_at) {
      const schedule = document.createElement("label");
      schedule.textContent = "Collection frequency";
      const frequency = document.createElement("select");
      for (const [minutes, label] of [[0, "On demand"], [5, "Every 5 minutes"], [15, "Every 15 minutes"],
        [30, "Every 30 minutes"], [60, "Hourly"], [360, "Every 6 hours"], [1440, "Daily"]]) {
        frequency.add(new Option(label, minutes));
      }
      frequency.value = String(agent.interval_minutes);
      schedule.append(frequency);
      group.append(schedule, row("", "Save frequency", async () => {
        await call(path + "/schedule", {interval_minutes: Number(frequency.value)});
        await loadAgents();
      }));
      group.append(
        row("", "Run now", async () => {
          const { data } = await call(path + "/jobs", {});
          await jobs();
          byId("status").textContent = "Collection " + data.status + ".";
        }),
        row("", "Rotate credential", async () => {
          const { data } = await call(path + "/rotate", {ttl_hours: Number(byId("agent-ttl").value)});
          revealAgentToken(data.token);
          await loadAgents();
        }),
        row("", "Revoke agent", async () => {
          if (!window.confirm("Revoke this agent and cancel outstanding collections?")) return;
          await call(path, {}, "DELETE");
          revealAgentToken("");
          await loadAgents();
        }),
      );
    }
    return group;
  }));
}

byId("agent-provider").onchange = () => {
  byId("agent-target-fields").replaceChildren(...agentTargets[byId("agent-provider").value].map(
    (name, index) => targetField(name, index, "agent")));

};
byId("agent-provider").onchange();
byId("agent-enroll").onsubmit = perform(async () => {
  const args = Array.from(byId("agent-target-fields").querySelectorAll("input"), (input) => input.value.trim());
  while (args.length && args[args.length - 1] === "") args.pop();
  const { data } = await call("/api/v1/agents", {
    name: byId("agent-name").value, provider: byId("agent-provider").value, arguments: args,
    ttl_hours: Number(byId("agent-ttl").value),
  });
  revealAgentToken(data.token);
  await loadAgents();
});
byId("agent-hide").onclick = () => revealAgentToken("");
byId("agent-copy").onclick = perform(async () => {
  if (!navigator.clipboard) throw Error("Clipboard access is unavailable. Select and copy the credential manually.");
  try { await navigator.clipboard.writeText(byId("agent-token").value); }
  catch (error) { throw Error("Clipboard permission was denied. Select and copy the credential manually."); }
  byId("status").textContent = "Credential copied. Store it securely, then clear the display.";
});
byId("agent-package").onclick = perform(async () => {
  const response = await fetch("/api/v1/agents/package", {headers: {Authorization: "Bearer " + credential}});
  if (!response.ok) throw Error("Collector bundle could not be downloaded.");
  const url = URL.createObjectURL(await response.blob());
  const download = document.createElement("a");
  download.href = url;
  download.download = "doofusai-agent.zip";
  download.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

async function loadDataPosture(after = "") {
  dataAfter = after;
  const { data } = await call("/api/v1/data-posture" + (after ? "?after=" + encodeURIComponent(after) : ""));
  const list = byId("data-posture-list");
  const detail = byId("data-posture-detail");
  detail.replaceChildren();
  const entries = data.data.map((item) => row([
    item.name, item.scope, "Operator: " + (item.operator_sensitivity ?? "unclassified"),
    "Provider: " + (item.provider_sensitivity ?? "unclassified"),
    ...Object.entries(item.content_sample_counts ?? {}).map(
      ([level, count]) => count + " " + level + " sample" + (count === 1 ? "" : "s")),
    item.configuration_path ? "Exposure path reported" : "No exposure path in collected evidence",
    "Configuration evidence: " + item.configuration_freshness,
  ].join(" · "), "Review evidence", async () => {
    const heading = document.createElement("h3");
    heading.textContent = item.name;
    const sensitivity = document.createElement("select");
    for (const level of ["unknown", "low", "moderate", "high"]) {
      sensitivity.add(new Option(level, level));
    }
    sensitivity.value = item.operator_sensitivity ?? "unknown";
    const label = document.createElement("label");
    label.textContent = "Operator classification";
    label.append(sensitivity);
    const save = row("", "Save classification", async () => {
      await call("/api/v1/data-posture", { node: item.id, sensitivity: sensitivity.value });
      await loadDataPosture(after);
      await detailActions.get("data:" + item.id)?.();
      byId("status").textContent = "Classification saved.";
    });
    const evidence = item.access_evidence.flatMap((review) => review.decisions.map((decision) =>
      row([review.provider, review.principal, decision.action, decision.decision,
        review.freshness, review.evaluated_at].join(" · "))));
    if (!evidence.length) evidence.push(row("No matching access reviews in current inventory."));
    if (item.access_evidence_truncated) evidence.push(row("Showing the 100 most recent matching decisions."));
    const sample = item.latest_content_sample;
    if (sample) evidence.unshift(row([
      sample.provider + " content sample", sample.sample_bytes + " bytes", sample.sampled_at,
      ...Object.entries(sample.signals).map(([kind, count]) => kind + " × " + count),
    ].join(" · ")));
    detail.replaceChildren(heading, label, save, ...evidence);
  }, "data:" + item.id));
  if (!entries.length) entries.push(row("No discovered data nodes on this page."));
  if (after) entries.push(row("", "First page", () => loadDataPosture()));
  if (data.next_after) entries.push(row("", "Next page", () => loadDataPosture(data.next_after)));
  list.replaceChildren(...entries);
}

async function showAccessReview(id) {
  const { data } = await call("/api/v1/access-reviews/" + id);
  const mode = {"aws-iam-policy-simulation": "AWS policy simulation", "vcenter-privilege-check": "vCenter privilege check",
    "google-iam-policy-troubleshooter": "Google IAM Policy Troubleshooter", "google-storage-caller-permissions": "Cloud Storage caller permissions"}[data.mode] || data.provider;
  const heading = document.createElement("h3");
  heading.textContent = mode;
  const subject = document.createElement("p");
  subject.textContent = data.principal + " · " + data.resource + " · " + data.evaluated_at;
  const notice = document.createElement("p");
  notice.textContent = data.inventory_changed
    ? "Inventory has changed since this review. Run a new check for current evidence."
    : "Review covers the selected operations and recorded conditions.";
  const panel = byId("access-detail");
  panel.replaceChildren(heading, subject, notice, ...data.decisions.map((item) => {
    const summary = [item.action, item.decision];
    if (item.missing_context?.length) summary.push("Missing context: " + item.missing_context.join(", "));
    if (typeof item.permissions_boundary_allows === "boolean") {
      summary.push("Permissions boundary: " + (item.permissions_boundary_allows ? "allows" : "denies"));
    }
    if (typeof item.organizations_allows === "boolean") {
      summary.push("Organizations policy: " + (item.organizations_allows ? "allows" : "denies"));
    }
    return row(summary.join(" · "));
  }));
  if (data.prior_reviews.length) {
    const form = document.createElement("form");
    const label = document.createElement("label");
    label.textContent = "Baseline review";
    const select = document.createElement("select");
    select.replaceChildren(...data.prior_reviews.map((entry) => new Option(entry.evaluated_at, entry.id)));
    label.append(select);
    const button = document.createElement("button");
    button.textContent = "Compare decisions";
    form.append(label, button);
    const result = document.createElement("div");
    form.onsubmit = perform(async () => {
      result.replaceChildren();
      const { data: comparison } = await call("/api/v1/access-reviews/" + id +
        "/compare?baseline=" + encodeURIComponent(select.value));
      result.replaceChildren(...comparison.transitions.map((item) =>
        row(item.action + " · " + item.before + " → " + item.after + " · " + item.change.replaceAll("-", " "))));
    });
    panel.append(form, result);
  }
}

function showReport(scan) {
  const title = document.createElement("h3");
  title.textContent = (scan.snapshot.evidence?.bucket ?? scan.snapshot.evidence?.name ?? scan.asset) + " assessment";
  const description = document.createElement("p");
  const result = scan.result;
  description.textContent = result.score === null
    ? "Incomplete coverage · no posture score"
    : "Complete coverage · posture score " + result.score + "/100";
  const evidence = document.createElement("p");
  evidence.textContent = "Source: " + scan.snapshot.source + " · policy version " + result.policy_version;
  if (scan.snapshot.evidence) {
    const { recorded_by, recorded_at } = scan.snapshot.evidence;
    evidence.textContent += " · Recorded by " + recorded_by + " · " + new Date(recorded_at).toLocaleString();
  }
  byId("report").replaceChildren(title, description, evidence, ...result.outcomes.map(
    (item) => row(item.field + " · " + item.status + " · observed " + JSON.stringify(item.observed) +
      " · expected " + JSON.stringify(item.expected) + (item.status === "finding" ? " · " + item.remediation : ""))
  ));
  if (result.execution) {
    const detail = document.createElement("details");
    const heading = document.createElement("summary");
    heading.textContent = "Check execution record · " + result.counts.pass + " passed · " + result.counts.finding +
      " findings · " + result.counts.unknown + " unknown · " + result.counts.skipped + " skipped · " + result.counts.disabled + " disabled";
    detail.append(heading, ...result.execution.map((item) =>
      row(item.id + " · revision " + item.version + " · " + item.status + " · " + item.reason)));
    byId("report").append(detail);
  } else {
    byId("report").append(row("Legacy report: a complete rule execution record was not recorded by this release."));
  }
}

async function loadIssues() {
  const status = byId("issue-status").value;
  const { data } = await call("/api/v1/issues?status=" + status);
  byId("issue-history").replaceChildren();
  byId("issue-list").replaceChildren(...data.issues.map((issue) =>
    row((issue.bucket_name ?? issue.asset) + " · " + issue.kind + " · " + issue.field +
      (issue.source_active === 0 ? " · No longer discovered" : "") +
      " · Risk: " + issue.risk.score + (issue.active_exception ? " · Active exception" : "") +
      " · Latest check: " + issue.last_outcome + " · " + (issue.assignee ?? "Unassigned"),
      "View issue history", async () => {
        const detail = (await call("/api/v1/issues/" + issue.id)).data;
        const heading = document.createElement("h3");
        heading.textContent = (issue.bucket_name ?? detail.issue.asset) + " · " + detail.issue.field;
        const risk = document.createElement("p");
        risk.textContent = "Risk " + detail.issue.risk.score + "/100 · Policy " +
          detail.issue.risk.policy_weight + " · Criticality " + detail.issue.risk.criticality_weight +
          " · Exposure " + detail.issue.risk.exposure_weight +
          " · Data sensitivity " + detail.issue.risk.sensitivity_weight + " · " + detail.issue.risk.evidence;
        const exceptions = (await call("/api/v1/issues/" + issue.id + "/exceptions")).data.exceptions;
        const controls = [risk, ...exceptions.map((exception) =>
          row("Exception · " + exception.reason + " · " +
            (exception.revoked_at ? "Revoked" : "Expires " + exception.expires_at)))];
        const describePath = (path) => path.map((edge) =>
          (edge.via ? edge.via + " → " : "") + (edge.name ?? edge.id)).join(" → ");
        const context = detail.risk_evidence;
        if (context.declared_path) {
          controls.push(row("Declared configuration path · " + describePath(context.declared_path)));
        }
        for (const entry of context.cloud_paths) {
          const description = entry.path ? describePath(entry.path) : "No configuration path to this asset observed";
          controls.push(row(entry.scope + " · " + entry.freshness + " · " + description +
            (entry.target_sensitivity ? " · Reported sensitivity: " + entry.target_sensitivity : "")));
        }
        if (detail.issue.status === "resolved" && detail.issue.source_active !== 0) {
          const { data: proof } = await call("/api/v1/issues/" + issue.id + "/remediation-proof");
          if (proof.verified) {
            for (const [label, result] of [["Baseline finding", proof.before], ["Verified reassessment", proof.after]]) {
              controls.push(row(label + " · " + result.sync.finished_at, "View assessment", async () => {
                const scan = (await call("/api/v1/scans/" + result.id)).data;
                await navigate("history");
                showReport(scan);
              }));
            }
          } else if (proof.reason !== "source-asset-not-active") {
            controls.push(row("No verified source-backed remediation · " + proof.reason.replaceAll("-", " ")));
          }
        }
        if (user.role === "admin") {
          if (["aws-role", "vsphere-host", "vsphere-vm", "gcs-bucket"].includes(issue.kind)) {
            const { data } = await call("/api/v1/access-reviews?asset=" + encodeURIComponent(issue.asset));
            if (data.reviews.length > 0) {
              const recent = data.reviews[0];
              controls.push(row("Access review · " + recent.evaluated_at, "View decisions", async () => {
                await navigate("access-reviews");
                await showAccessReview(recent.id);
              }));
            }
          }
          const form = document.createElement("form");
          const label = document.createElement("label");
          label.textContent = "Assignee principal";
          const field = document.createElement("input");
          field.placeholder = "e.g. Model Operations";
          field.maxLength = 80;
          field.placeholder = "Leave blank to unassign";
          field.value = detail.issue.assignee ?? "";
          label.append(field);
          const submit = document.createElement("button");
          submit.textContent = "Save assignment";
          form.append(label, submit);
          form.onsubmit = perform(async () => {
            await call("/api/v1/issues/" + issue.id + "/assignment", { assignee: field.value.trim() || null });
            await loadIssues();
            await detailActions.get("issue:" + issue.id)?.();
          });
          controls.push(form);
          const exceptionForm = document.createElement("form");
          const reasonLabel = document.createElement("label");
          const reason = document.createElement("input");
          reason.placeholder = "e.g. Approved temporary exception while encryption is enabled";
          reasonLabel.textContent = "Exception reason";
          reason.maxLength = 500;
          reason.required = true;
          reasonLabel.append(reason);
          const expiresLabel = document.createElement("label");
          const expires = document.createElement("input");
          expiresLabel.textContent = "Expires in local time";
          expires.type = "datetime-local";
          expires.required = true;
          expiresLabel.append(expires);
          const approve = document.createElement("button");
          approve.textContent = "Approve exception";
          exceptionForm.append(reasonLabel, expiresLabel, approve);
          exceptionForm.onsubmit = perform(async () => {
            await call("/api/v1/issues/" + issue.id + "/exceptions", {
              reason: reason.value, expires_at: new Date(expires.value).toISOString(),
            });
            await loadIssues();
            await detailActions.get("issue:" + issue.id)?.();
          });
          if (!detail.issue.active_exception) controls.push(exceptionForm);
          else {
            const revoke = document.createElement("button");
            revoke.textContent = "Revoke active exception";
            revoke.onclick = perform(async () => {
              await call("/api/v1/issues/" + issue.id + "/exceptions",
                { id: detail.issue.active_exception.id }, "DELETE");
              await loadIssues();
            await detailActions.get("issue:" + issue.id)?.();
            });
            controls.push(revoke);
          }
        }
        byId("issue-history").replaceChildren(heading, ...controls, ...detail.events.map((event) =>
          row(event.action + " · " + event.outcome + " · " + event.created_at + " UTC", "View assessment", async () => {
            const scan = (await call("/api/v1/scans/" + event.scan)).data;
            await navigate("history");
            showReport(scan);
          })));
      }, "issue:" + issue.id)));
  if (data.issues.length === 0) {
    byId("issue-list").textContent = "No " + status + " issues.";
  }
}

let inventorySet = "all";
let inventoryRequest = 0;
byId("inventory-set").onchange = perform(async () => {
  inventorySet = byId("inventory-set").value;
  await loadInventory();
});
async function loadInventory(after = "") {
  inventoryAfter = after;
  const request = ++inventoryRequest;
  const { data: choices } = await call("/api/v1/inventory/sets");
  if (request !== inventoryRequest) return;
  const selector = byId("inventory-set");
  selector.replaceChildren(...choices.sets.map((set) => new Option(set.name, set.id)));
  if (!choices.sets.some((set) => set.id === inventorySet)) inventorySet = "all";
  selector.value = inventorySet;
  const selected = inventorySet;
  const base = "/api/v1/inventory/objects?set=" + encodeURIComponent(selected);
  const { data } = await call(base + "&after=" + encodeURIComponent(after));
  if (request !== inventoryRequest) return;
  byId("inventory-detail").replaceChildren();
  byId("asset").hidden = user.role === "viewer" || !["all", "manual"].includes(selected);
  byId("inventory-set-info").textContent = data.total + " object(s) · " + (data.set.scope ?
    data.set.provider.toUpperCase() + " · " + data.set.scope : data.set.name);
  const entries = data.objects.map((asset) => {
    const entry = document.createElement("div");
    entry.append(row([asset.name, asset.kind, asset.provider,
      asset.active ? "Observed " + asset.observed_at : "No longer discovered",
      asset.assessment ? "Assessment available" : "No applicable assessment recorded",
    ].filter(Boolean).join(" · "), "View object", async () => {
      const { data } = await call(base + "&object=" + encodeURIComponent(asset.id));
      if (selected !== inventorySet) return;
      const item = data.object;
      const heading = document.createElement("h3");
      heading.textContent = item.name;
      const metadata = document.createElement("pre");
      metadata.textContent = JSON.stringify({
        id: item.id, provider: item.provider, resource: item.resource, kind: item.kind,
        scope: item.scope, observed_at: item.observed_at, active: item.active,
        exposure: item.exposure, sensitivity: item.sensitivity,
        sensitivity_observed_at: item.profile_observed, facts: item.facts,
        collection_evidence: item.evidence, latest_collection: item.latest_collection,
      }, null, 2);
      const relationships = item.relationships.map((edge) =>
        row(edge.origin_name + " → " + edge.relation + " → " + edge.target_name));
      if (!relationships.length) relationships.push(row("No relationships collected for this object."));
      if (item.relationships_truncated) relationships.push(row("Showing the first 500 relationships."));
      const summary = document.createElement("div");
      for (const [label, value] of [
        ["Provider", item.provider ?? "Manual entry"], ["Object type", item.kind],
        ["Provider resource", item.resource], ["Account / workspace scope", item.scope ?? "Manual inventory"],
        ["Last observed", item.observed_at], ["Currently discovered", item.active ? "Yes" : "No"],
        ["Reported exposure", item.exposure ?? "No value collected"],
        ["Sensitivity", item.sensitivity ?? "No classification collected"],
      ]) summary.append(row(label + " · " + value));
      for (const [key, value] of Object.entries(item.facts)) {
        summary.append(row(key.replaceAll("_", " ") + " · " + String(value)));
      }
      const raw = document.createElement("details");
      const rawTitle = document.createElement("summary");
      rawTitle.textContent = "Collected metadata and source evidence";
      raw.append(rawTitle, metadata);
      const relationshipTitle = document.createElement("h4");
      relationshipTitle.textContent = "Discovered relationships";
      const details = [heading, summary, relationshipTitle, ...relationships, raw];
      if (item.assessment) details.push(row("Latest assessment · " + item.assessment.created_at,
        "Open assessment", async () => {
          const { data } = await call("/api/v1/scans/" + item.assessment.id);
          await navigate("history");
          showReport(data);
        }));
      byId("inventory-detail").replaceChildren(...details);
    }, "object:" + asset.id));
    if (user.role !== "viewer" && !asset.scope && types[asset.kind]) {
      entry.append(row("", "Run assessment", async () => {
        const { data: scan } = await call("/api/v1/scans", {asset: asset.id});
        await navigate("history");
        showReport(scan);
      }));
    }
    return entry;
  });
  if (!entries.length) entries.push(row("No objects collected in this set. Run its connection scan to populate inventory."));
  if (after) entries.push(row("", "First page", () => loadInventory()));
  if (data.next_after) entries.push(row("", "Next page", () => loadInventory(data.next_after)));
  byId("asset-list").replaceChildren(...entries);
}

async function navigate(view, refresh = false) {
  if (!refresh) {
    viewVersion++;
    selectedDetail = null;
    detailActions.clear();
    activeView = view;
    loadingView = viewVersion;
  }
  const stamp = context();
  const selected = refresh ? selectedDetail : null;
  if (refresh) detailActions.clear();
  const panel = byId(view);
  panel.setAttribute("aria-busy", "true");
  byId("refresh-status").textContent = "Loading " + document.querySelector('[data-view="' + view + '"]').textContent + "…";
  try {
  for (const panel of document.querySelectorAll(".view")) panel.hidden = panel.id !== view;
  for (const tab of document.querySelectorAll("[data-view]")) {
    if (tab.dataset.view === view) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  }
  if (view === "inventory") await loadInventory(refresh ? inventoryAfter : "");
  if (view === "checks") await loadChecks(refresh ? ruleBefore : "");
  if (view === "history") {
    const { data } = await call("/api/v1/scans");
    byId("report").replaceChildren();
    byId("scan-list").replaceChildren(...data.scans.map((scan) =>
      row((scan.bucket_name ?? scan.asset) + " · " + scan.created_at + " UTC · " + scan.result.coverage, "Open report",
        async () => showReport((await call("/api/v1/scans/" + scan.id)).data), "scan:" + scan.id)));
    if (!data.scans.length) byId("scan-list").textContent = "No assessments recorded. Run a connection scan or assess a manual asset.";
  }
  if (view === "issues") await loadIssues();
  if (view === "syncs") {
    const { data } = await call("/api/v1/sync-runs");
    const entries = data.runs.map((run) => row(
      run.source_project + " · " + run.finished_at + " · " +
      (run.status === "completed" ? run.assets + (run.provider === "gcs" ? " bucket(s) assessed" : " graph node(s)") : run.error)));
    byId("sync-list").replaceChildren(...entries);
    if (!entries.length) byId("sync-list").textContent = "No cloud syncs recorded.";
  }
  if (view === "connections") await loadConnections();
  if (view === "agents") await loadAgents();
  else revealAgentToken("");
  if (view === "data-posture") await loadDataPosture(refresh ? dataAfter : "");
  if (view === "relationships") {
    const previousScope = byId("cloud-scope").value;
    const [inventory, graph, cloud] = await Promise.all([
      call("/api/v1/graph/nodes"), call("/api/v1/graph/edges"), call("/api/v1/cloud-graph"),
    ]);
    const nodes = inventory.data.nodes.map((item) =>
      row(item.id + " · " + item.kind + " · " + item.criticality + (item.public ? " · Public endpoint" : "")));
    const edges = graph.data.edges.map((item) => row(item.origin + " → " + item.relation + " → " + item.target));
    byId("graph-list").replaceChildren(...nodes, ...edges);
    if (!nodes.length) byId("graph-list").textContent = "No relationship nodes configured.";
    const area = byId("cloud-graph");
    const select = byId("cloud-scope");
    area.hidden = !cloud.data.scopes.length;
    select.replaceChildren(...cloud.data.scopes.map((scope) => new Option(scope, scope)));
    if (cloud.data.scopes.includes(previousScope)) select.value = previousScope;
    function showCloud(data) {
      const names = new Map(data.nodes.map((node) => [node.id, node.name]));
      byId("cloud-list").replaceChildren(
        ...data.nodes.map((node) => row([node.name, node.kind, node.exposure, node.sensitivity &&
          "Profile: " + node.sensitivity + " · " + node.profile_observed].filter(Boolean).join(" · "))),
        ...data.edges.map((edge) => row(names.get(edge.origin) + " → " + edge.relation + " → " + names.get(edge.target))),
      );
    }
    showCloud(select.value && select.value !== cloud.data.scope ? (await call("/api/v1/cloud-graph?scope=" + encodeURIComponent(select.value))).data : cloud.data);
    select.onchange = perform(async () => {
      const { data } = await call("/api/v1/cloud-graph?scope=" + encodeURIComponent(select.value));
      showCloud(data);
    });
  }
  if (view === "boms") {
    const { data } = await call("/api/v1/boms");
    byId("bom-detail").replaceChildren();
    byId("bom-list").replaceChildren(...data.boms.map((entry) => row(
      entry.workload + " · " + entry.total_components + " components · " + entry.imported_at,
      "View components", async () => {
        const { data: detail } = await call("/api/v1/boms/" + entry.id);
        const heading = document.createElement("h3");
        heading.textContent = detail.workload + " · " + detail.document.source_format + " " + detail.spec_version;
        const notes = document.createElement("p");
        notes.textContent = detail.total_dependencies + " relationships · SHA-256 " + detail.digest +
          (detail.total_components > 200 ? " · Showing the first 200 components" : "");
        byId("bom-detail").replaceChildren(heading, notes, ...detail.document.components.slice(0, 200).map(
          (item) => row([item.name, item.type, item.version, item.purl].filter(Boolean).join(" · "))
        ));
      }, "bom:" + entry.id,
    )));
    if (!data.boms.length) byId("bom-list").textContent = "No bills of materials imported.";
  }
  if (view === "runtime") {
    const { data } = await call("/api/v1/runtime-findings");
    byId("runtime-list").replaceChildren(...data.findings.map((finding) =>
      row(finding.node + " · " + finding.severity + " · " + finding.category +
        " · " + finding.source + " · " + finding.observed_at)));
    if (!data.findings.length) byId("runtime-list").textContent = "No runtime findings received.";
  }
  if (view === "audit") {
    const { data } = await call("/api/v1/audit");
    byId("events").replaceChildren(...data.events.map((event) =>
      row([event.created_at + " UTC", event.principal, event.action, event.resource].join(" · "))));
    if (!data.events.length) byId("events").textContent = "No audit events recorded.";
  }
  if (view === "access-reviews") {
    const { data } = await call("/api/v1/access-reviews");
    byId("access-detail").replaceChildren();
    byId("access-list").replaceChildren(...data.reviews.map((entry) =>
      row(entry.provider + " · " + entry.principal + " · " + entry.resource + " · " + entry.evaluated_at,
        "View decisions", () => showAccessReview(entry.id), "review:" + entry.id)));
    if (data.reviews.length === 0) byId("access-list").textContent = "No access reviews recorded.";
  }
  if (selected && isCurrent(stamp)) {
    const restore = detailActions.get(selected.key);
    if (restore) { selectedDetail = selected; await restore(); }
    else selectedDetail = null;
  }
  if (isCurrent(stamp)) byId("refresh-status").textContent = "Last checked " + new Date().toLocaleTimeString();
  } finally {
    if (isCurrent(stamp) || activeView !== view) panel.removeAttribute("aria-busy");
    if (loadingView === stamp[1]) loadingView = -1;
  }
}

for (const tab of document.querySelectorAll("[data-view]")) {
  tab.onclick = perform(() => navigate(tab.dataset.view));
}
async function openProject(accessToken) {
  if (credential !== accessToken) responseCache.clear();
  credential = accessToken;
  const { data } = await call("/api/v1/me");
  user = data;
  const endpoints = ["/api/v1/me", "/api/v1/assets", "/api/v1/scans", "/api/v1/issues", "/api/v1/checks"];
  if (user.role === "admin") endpoints.push("/api/v1/audit");
  byId("endpoint").replaceChildren(...endpoints.map((path) => new Option(path, path)));
  byId("token").value = "";
  byId("project").textContent = user.project;
  byId("identity").textContent = user.principal + " · " + user.role;
  byId("audit-tab").hidden = user.role !== "admin";
  byId("connections-tab").hidden = user.role !== "admin";
  byId("agents-tab").hidden = user.role !== "admin";
  byId("data-posture-tab").hidden = user.role !== "admin";
  byId("access-tab").hidden = user.role !== "admin";
  byId("asset").hidden = user.role === "viewer";
  await navigate("inventory");
  byId("login").hidden = true;
  byId("workspace").hidden = false;
  byId("logout").hidden = false;
}

byId("local-session").onsubmit = perform(async () => {
  const { data } = await call("/auth/local", {
    username: byId("username").value.trim(), password: byId("password").value,
  });
  byId("password").value = "";
  await openProject(data.access_token);
});
fetch("/auth/options").then((response) => response.json()).then((data) => {
  byId("sso-login").hidden = !data.sso;
}).catch(() => {});
byId("start-sso").onclick = perform(async () => {
  const { data } = await call("/auth/sso/start", {});
  sessionStorage.setItem("doofus-sso-state", data.state);
  location.assign(data.url);
});
(async () => {
  const query = new URLSearchParams(location.search);
  if (!query.has("code") && !query.has("error")) return;
  const state = sessionStorage.getItem("doofus-sso-state");
  sessionStorage.removeItem("doofus-sso-state");
  history.replaceState(null, "", "/");
  try {
    if (query.has("error") || !state || state !== query.get("state")) {
      throw Error("Organization sign-in was cancelled or could not be verified.");
    }
    const { data } = await call("/auth/sso/complete", {state, code: query.get("code")});
    await openProject(data.access_token);
  } catch (error) {
    byId("status").textContent = error.message;
  }
})();

byId("session").onsubmit = perform(async () => {
  await openProject(byId("token").value.trim());
});

let loginAttempt = null;
fetch("/auth/device").then((response) => response.json()).then((data) => {
  byId("enterprise-login").hidden = data.enabled !== true;
}).catch(() => {});

byId("start-device").onclick = perform(async () => {
  byId("session").hidden = true;
  try {
    const { data: challenge } = await call("/auth/device/start", {});
    loginAttempt = challenge.session;
    byId("device-code").textContent = challenge.user_code;
    byId("device-link").href = challenge.verification_uri;
    byId("device-challenge").hidden = false;
    let retry = challenge.retry_in;
    const deadline = Date.now() + challenge.expires_in * 1000;
    while (loginAttempt === challenge.session) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(retry * 1000, Math.max(0, deadline - Date.now()))));
      if (loginAttempt !== challenge.session) return;
      if (Date.now() >= deadline) throw Error("Sign-in expired. Start a new attempt.");
      const { data } = await call("/auth/device/poll", { session: challenge.session });
      if (loginAttempt !== challenge.session) return;
      if (data.status === "approved") {
        await openProject(data.access_token);
        return;
      }
      retry = data.retry_in;
    }
  } finally {
    loginAttempt = null;
    byId("device-challenge").hidden = true;
    byId("session").hidden = false;
    byId("device-link").removeAttribute("href");
    byId("device-code").textContent = "";
  }
});

byId("cancel-device").onclick = perform(async () => {
  const session = loginAttempt;
  loginAttempt = null;
  byId("device-challenge").hidden = true;
  byId("session").hidden = false;
  if (session) await call("/auth/device/cancel", { session });
});

byId("logout").onclick = perform(async () => {
  try { await call("/api/v1/session/logout", {}); }
  finally { credential = ""; user = null; location.reload(); }
});
byId("kind").onchange = fillFacts;
fillFacts();
byId("issue-filter").onsubmit = perform(loadIssues);
byId("asset").onsubmit = perform(async () => {
  const facts = JSON.parse(byId("custom-facts").value || "{}");
  if (!facts || Array.isArray(facts) || typeof facts !== "object") throw Error("Additional facts must be a JSON object.");
  for (const field of byId("facts").querySelectorAll("select")) {
    if (field.value) facts[field.name] = field.value === "true";
  }
  await call("/api/v1/assets", { id: byId("asset-id").value, kind: byId("kind").value, facts });
  await navigate("inventory");
});
byId("endpoint").onchange = () => { byId("response").hidden = true; byId("response").textContent = ""; };
byId("api-form").onsubmit = perform(async () => {
  const output = byId("response");
  output.hidden = true;
  const { status, data } = await call(byId("endpoint").value);
  output.textContent = "HTTP " + status + "\n" + JSON.stringify(data, null, 2);
  output.hidden = false;
});

let checkRows = [];
function downloadJSON(name, value) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], {type: "application/json"}));
  const link = document.createElement("a");
  link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function renderChecks() {
  const search = byId("check-search").value.toLowerCase();
  const kind = byId("check-kind-filter").value;
  const rows = checkRows.filter((r) => (!kind || r.kind === kind) && JSON.stringify(r).toLowerCase().includes(search));
  byId("check-list").replaceChildren(row(rows.length + " of " + checkRows.length + " checks"), ...rows.map((r) => {
    const detail = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = r.title + " · " + r.severity + " · " + (r.enabled ? "Enabled" : "Disabled");
    const metadata = document.createElement("pre");
    metadata.textContent = JSON.stringify({id: r.catalogue_id, pack: r.pack, revision: r.version, asset_kind: r.kind,
      description: r.description, required_fact: r.field, operator: r.operator, expected: r.expected,
      remediation: r.remediation, reference: r.source_url, disabled_reason: r.disabled_reason,
      regression_fixtures: r.tests}, null, 2);
    detail.append(summary, metadata);
    if (r.source_url) {
      const reference = document.createElement("a");
      reference.textContent = "Open source reference"; reference.href = r.source_url;
      reference.target = "_blank"; reference.rel = "noopener noreferrer"; detail.append(reference);
    }
    if (user.role === "admin") {
      const form = document.createElement("form");
      const label = document.createElement("label"); label.textContent = "Reason for changing check state";
      const reason = document.createElement("input"); reason.required = true; reason.maxLength = 500;
      reason.placeholder = "e.g. Exception approved under change CHG-123"; label.append(reason);
      const button = document.createElement("button"); button.textContent = r.enabled ? "Disable check" : "Enable check";
      form.append(label, button); form.onsubmit = perform(async () => {
        await call("/api/v1/checks/setting", {id: r.catalogue_id, enabled: !r.enabled, reason: reason.value});
        await loadChecks();
      }); detail.append(form);
    }
    return detail;
  }));
}
async function loadChecks(before = "") {
  const previousChecks = JSON.stringify(checkRows);
  const {data} = await call("/api/v1/checks");
  checkRows = data.checks;
  const selected = byId("check-kind-filter").value;
  byId("check-kind-filter").replaceChildren(new Option("All kinds", ""), ...data.kinds.map((v) => new Option(v, v)));
  byId("check-kind-filter").value = selected;
  const previousKind = byId("custom-kind").value;
  const previousOperator = byId("custom-operator").value;
  byId("custom-kind").replaceChildren(...data.kinds.map((v) => new Option(v, v)));
  byId("custom-operator").replaceChildren(...data.operators.map((v) => new Option(v, v)));
  byId("custom-kind").value = previousKind || "storage";
  byId("custom-operator").value = previousOperator || "ge";
  byId("check-admin").hidden = user.role !== "admin";
  renderChecks();
  if (user.role === "admin") {
    await loadRulePacks(before);
    await loadRuleSources();
  }
  if (plannedAsset && previousChecks !== JSON.stringify(checkRows)) await showPlan(plannedAsset);
}
async function loadRulePacks(before = "") {
  ruleBefore = before;
  const {data: packs} = await call("/api/v1/rule-packs" + (before ? "?before=" + before : ""));
    byId("pack-list").replaceChildren(...packs.packs.map((p) => {
      const entry = document.createElement("div");

      entry.append(row(p.id + " · revision " + p.version + " · " + (p.active ? "Active" : "Retained") +
        " · SHA256 " + p.digest + " · " + (p.verified_source ? "Verified feed: " + p.verified_source : "Local administrator import")));
      entry.append(row("", "Export / edit", async () => {
        const {data: packDocument} = await call("/api/v1/rule-packs/" + encodeURIComponent(p.id) + "/" + p.version);
        byId("pack-json").value = JSON.stringify(packDocument, null, 2);
        downloadJSON(p.id + "-v" + p.version + ".json", packDocument);
      }));
      entry.append(row("", p.active ? "Deactivate pack" : "Activate / roll back to this revision", async () => {
        await call("/api/v1/rule-packs/activate", {id: p.id, version: p.active ? 0 : p.version});
        await loadChecks();
      }));
      return entry;
    }));
  if (before) byId("pack-list").append(row("", "Newest revisions", () => loadRulePacks()));
  if (packs.next_before) byId("pack-list").append(row("", "Older revisions", () => loadRulePacks(packs.next_before)));
}
async function loadRuleSources() {
  const {data} = await call("/api/v1/rule-sources");
  byId("rule-source-list").replaceChildren(...data.sources.map((source) => {
    const entry = document.createElement("div");
    entry.append(row(source.id + " · " + source.mode + " · next check " + source.next_check + " · " + source.last_status));
    entry.append(row("", "Edit source", () => {
      for (const [field, value] of [["id", source.id], ["url", source.url], ["key", source.public_key],
        ["mode", source.mode], ["interval", source.interval_minutes]]) byId("rule-source-" + field).value = value;
    }));
    if (source.mode !== "disabled") entry.append(row("", "Check now", async () => {
      await call("/api/v1/rule-sources/check", {id: source.id}); await loadRuleSources();
    }));
    return entry;
  }));
}
byId("check-search").oninput = renderChecks;
byId("check-kind-filter").onchange = renderChecks;
async function showPlan(asset) {
  const {data} = await call("/api/v1/checks/plan", {asset});
  plannedAsset = asset;
  byId("check-plan-result").replaceChildren(row("Plan for " + asset + " · rule-set SHA256: " + data.policy_version),
    ...data.plan.map((r) => row(r.id + " · revision " + r.version + " · " + r.status + " · " + r.reason)));
}
byId("check-plan-form").onsubmit = perform(() => showPlan(byId("check-plan-asset").value));
byId("custom-check-form").onsubmit = perform(async () => {
  const value = (id) => byId("custom-" + id).value;
  const pack = {schema: "doofusai.rules.v1", id: value("pack"), version: Number(value("version")), rules: [{
    id: value("id"), title: value("title"), description: value("description"), kind: value("kind"),
    field: value("field"), operator: value("operator"), expected: JSON.parse(value("expected")), severity: value("severity"),
    remediation: value("remediation"), source_url: value("source"), tests: JSON.parse(value("tests"))}]};
  const {data} = await call("/api/v1/rule-packs/stage", pack);
  byId("rule-operation-result").textContent = JSON.stringify(data, null, 2) + "\nStaged. Review and activate the revision below.";
  await loadChecks();
});
byId("pack-import-form").onsubmit = (event) => perform(async () => {
  const action = event.submitter.value;
  const pack = JSON.parse(byId("pack-json").value);
  const {data} = await call("/api/v1/rule-packs/" + action, action === "preview" ? {pack, asset: byId("pack-preview-asset").value} : pack);
  byId("rule-operation-result").textContent = JSON.stringify(data, null, 2);
  await loadChecks();
})(event);
byId("export-builtin").onclick = perform(async () => {
  const {data} = await call("/api/v1/rule-packs/builtin");
  byId("pack-json").value = JSON.stringify(data, null, 2); downloadJSON("builtin-v1.json", data);
});
byId("rule-source-form").onsubmit = perform(async () => {
  const {data} = await call("/api/v1/rule-sources", {id: byId("rule-source-id").value, url: byId("rule-source-url").value,
    public_key: byId("rule-source-key").value, mode: byId("rule-source-mode").value,
    interval_minutes: Number(byId("rule-source-interval").value)});
  byId("rule-operation-result").textContent = JSON.stringify(data, null, 2); await loadRuleSources();
});
byId("refresh-rule-sources").onclick = perform(loadRuleSources);
