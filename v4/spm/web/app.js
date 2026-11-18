"use strict";

const byId = (id) => document.getElementById(id);
let credential = "";
let user;
const types = {
  storage: { encrypted: "Encrypted at rest", public: "Public access" },
  registry: { signatures_required: "Trusted signatures required", public: "Public access" },
  agent: { approval_required: "Sensitive actions require approval", redaction_enabled: "Sensitive-data redaction enabled" },
};

async function call(path, body, method = "POST") {
  const request = { headers: { Authorization: "Bearer " + credential } };
  if (body !== undefined) {
    request.method = method;
    request.headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(body);
  }
  const response = await fetch(path, request);
  const data = await response.json();
  if (!response.ok) throw Error(data.error);
  return { status: response.status, data };
}

function perform(action) {
  return async (event) => {
    event.preventDefault();
    byId("status").textContent = "";
    const button = event.submitter ?? event.currentTarget;
    button.disabled = true;
    try {
      await action();
    } catch (error) {
      byId("status").textContent = error.message;
    } finally {
      button.disabled = false;
    }
  };
}

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

function row(text, label, action) {
  const entry = document.createElement("div");
  entry.className = "entry";
  const summary = document.createElement("span");
  summary.textContent = text;
  entry.append(summary);
  if (action) {
    const button = document.createElement("button");
    button.textContent = label;
    button.onclick = perform(action);
    entry.append(button);
  }
  return entry;
}

const agentTargets = {
  aws: '["account ID","region","optional Access Analyzer ARN"]',
  gcs: '["cloud project ID"]', vertex: '["cloud project ID","region"]',
  azure: '["subscription ID","resource group","workspace"]',
  oci: '["compartment OCID","region"]', ibm: '["deployment space UUID","region"]',
  salesforce: '["My Domain hostname","org ID","optional API version"]',
  vsphere: '["ESXi/vCenter host","optional port as a string"]',
};

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
      const { data } = await call(path + "/jobs");
      byId("agent-jobs").replaceChildren(row(agent.name + " collections"),
        ...data.jobs.map((job) => row([job.created_at, job.status, job.id].join(" · "))));
    }
    group.append(row([agent.name, agent.provider, agent.scope,
      agent.revoked_at ? "Revoked" : "Credential expires " + agent.expires_at,
      agent.last_seen ? "Last seen " + agent.last_seen : "Awaiting first check-in",
    ].join(" · "), "Run history", jobs));
    if (!agent.revoked_at) {
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
  byId("agent-target-help").textContent = agentTargets[byId("agent-provider").value];
};
byId("agent-provider").onchange();
byId("agent-enroll").onsubmit = perform(async () => {
  let args;
  try {
    args = JSON.parse(byId("agent-target").value);
  } catch {
    throw Error("Enter the target as a JSON array of strings.");
  }
  const { data } = await call("/api/v1/agents", {
    name: byId("agent-name").value, provider: byId("agent-provider").value, arguments: args,
    ttl_hours: Number(byId("agent-ttl").value),
  });
  revealAgentToken(data.token);
  await loadAgents();
});
byId("agent-hide").onclick = () => revealAgentToken("");
byId("agent-copy").onclick = perform(() => navigator.clipboard.writeText(byId("agent-token").value));
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
  }));
  if (!entries.length) entries.push(row("No discovered data nodes on this page."));
  if (after) entries.push(row("", "First page", () => loadDataPosture()));
  if (data.next_after) entries.push(row("", "Next page", () => loadDataPosture(data.next_after)));
  list.replaceChildren(...entries);
}

async function showAccessReview(id) {
  const { data } = await call("/api/v1/access-reviews/" + id);
  const mode = {aws: "AWS policy simulation", vsphere: "vCenter privilege check",
                gcs: "Cloud Storage caller permissions"}[data.provider];
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
    (item) => row(item.field + " · " + item.status + (item.status === "finding" ? " · " + item.remediation : ""))
  ));
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
          });
          controls.push(form);
          const exceptionForm = document.createElement("form");
          const reasonLabel = document.createElement("label");
          const reason = document.createElement("input");
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
          });
          if (!detail.issue.active_exception) controls.push(exceptionForm);
          else {
            const revoke = document.createElement("button");
            revoke.textContent = "Revoke active exception";
            revoke.onclick = perform(async () => {
              await call("/api/v1/issues/" + issue.id + "/exceptions",
                { id: detail.issue.active_exception.id }, "DELETE");
              await loadIssues();
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
      })));
  if (data.issues.length === 0) {
    byId("issue-list").textContent = "No " + status + " issues.";
  }
}

async function loadInventory(after = "") {
  const { data } = await call("/api/v1/assets?after=" + encodeURIComponent(after));
  const entries = data.assets.map((asset) => {
    if (asset.source) {
      const state = asset.source.active ? "Last observed " + asset.source.last_seen : "No longer discovered";
      const provider = ({ vertex: "Google AI endpoint", aws: "AWS IAM role", azure: "Azure AI", oci: "OCI Data Science", ibm: "IBM watsonx.ai", vsphere: "VMware vSphere", gcs: "Google Cloud Storage" }[asset.source.provider] ?? "Cloud asset");
      return row(asset.source.name + " · " + provider + " · " + state);
    }
    return row(asset.id + " · " + asset.kind, "Run assessment", user.role === "viewer" ? null : async () => {
      const { data: scan } = await call("/api/v1/scans", { asset: asset.id });
      await navigate("history");
      showReport(scan);
    });
  });
  if (after) entries.push(row("Inventory", "First page", () => loadInventory()));
  if (data.next_after) entries.push(row("More assets", "Next page", () => loadInventory(data.next_after)));
  byId("asset-list").replaceChildren(...entries);
}

async function navigate(view) {
  for (const panel of document.querySelectorAll(".view")) panel.hidden = panel.id !== view;
  for (const tab of document.querySelectorAll("[data-view]")) {
    if (tab.dataset.view === view) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  }
  if (view === "inventory") await loadInventory();
  if (view === "history") {
    const { data } = await call("/api/v1/scans");
    byId("report").replaceChildren();
    byId("scan-list").replaceChildren(...data.scans.map((scan) =>
      row((scan.bucket_name ?? scan.asset) + " · " + scan.created_at + " UTC · " + scan.result.coverage, "Open report",
        async () => showReport((await call("/api/v1/scans/" + scan.id)).data))));
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
  if (view === "agents") await loadAgents();
  else revealAgentToken("");
  if (view === "data-posture") await loadDataPosture();
  if (view === "relationships") {
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
    function showCloud(data) {
      const names = new Map(data.nodes.map((node) => [node.id, node.name]));
      byId("cloud-list").replaceChildren(
        ...data.nodes.map((node) => row([node.name, node.kind, node.exposure, node.sensitivity &&
          "Profile: " + node.sensitivity + " · " + node.profile_observed].filter(Boolean).join(" · "))),
        ...data.edges.map((edge) => row(names.get(edge.origin) + " → " + edge.relation + " → " + names.get(edge.target))),
      );
    }
    showCloud(cloud.data);
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
      },
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
  }
  if (view === "access-reviews") {
    const { data } = await call("/api/v1/access-reviews");
    byId("access-detail").replaceChildren();
    byId("access-list").replaceChildren(...data.reviews.map((entry) =>
      row(entry.provider + " · " + entry.principal + " · " + entry.resource + " · " + entry.evaluated_at,
        "View decisions", () => showAccessReview(entry.id))));
    if (data.reviews.length === 0) byId("access-list").textContent = "No access reviews recorded.";
  }
}

for (const tab of document.querySelectorAll("[data-view]")) {
  tab.onclick = perform(() => navigate(tab.dataset.view));
}
async function openProject(accessToken) {
  credential = accessToken;
  const { data } = await call("/api/v1/me");
  user = data;
  byId("token").value = "";
  byId("project").textContent = user.project;
  byId("identity").textContent = user.principal + " · " + user.role;
  byId("audit-tab").hidden = user.role !== "admin";
  byId("agents-tab").hidden = user.role !== "admin";
  byId("data-posture-tab").hidden = user.role !== "admin";
  byId("access-tab").hidden = user.role !== "admin";
  byId("asset").hidden = user.role === "viewer";
  await navigate("inventory");
  byId("login").hidden = true;
  byId("workspace").hidden = false;
  byId("logout").hidden = false;
}

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

byId("logout").onclick = () => location.reload();
byId("kind").onchange = fillFacts;
fillFacts();
byId("issue-filter").onsubmit = perform(loadIssues);
byId("asset").onsubmit = perform(async () => {
  const facts = {};
  for (const field of byId("facts").querySelectorAll("select")) {
    if (field.value) facts[field.name] = field.value === "true";
  }
  await call("/api/v1/assets", { id: byId("asset-id").value, kind: byId("kind").value, facts });
  await navigate("inventory");
});
byId("api-form").onsubmit = perform(async () => {
  const output = byId("response");
  output.hidden = true;
  const { status, data } = await call(byId("endpoint").value);
  output.textContent = "HTTP " + status + "\n" + JSON.stringify(data, null, 2);
  output.hidden = false;
});
