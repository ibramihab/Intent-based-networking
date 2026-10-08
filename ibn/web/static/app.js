"use strict";

// ------------------------------------------------------------------ helpers
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
  return data;
}

let toastTimer;
function toast(msg, kind = "error") {
  const t = $("toast");
  t.textContent = msg;
  t.className = `toast ${kind === "info" ? "info" : ""}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 6000);
}

async function busy(button, label, fn) {
  const original = button.innerHTML;
  button.disabled = true;
  button.innerHTML = `<span class="spinner"></span>${esc(label)}`;
  try { return await fn(); }
  catch (e) { toast(e.message); }
  finally { button.disabled = false; button.innerHTML = original; }
}

function table(headers, rows, rowClass = () => "") {
  if (!rows.length) return `<p class="muted">Nothing here yet.</p>`;
  return `<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r, i) => `<tr class="${rowClass(i)}">${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

const badge = (text, cls = text) => `<span class="badge ${esc(cls)}">${esc(text)}</span>`;
const step = (n, title) => `<div class="step"><span class="num">${n}</span><h3>${esc(title)}</h3></div>`;
const services = (svcs) => svcs.map((s) => s.ports.length ? `${s.protocol}/${s.ports.join(",")}` : s.protocol).join(" ");
const endpoint = (e) => e.group || e.host || e.subnet;

function stages(report, showInfo = false) {
  if (!report) return "";
  return report.stages.map((s) => {
    const status = s.skipped ? badge("skipped", "skip") : s.passed ? badge("pass") : badge("FAIL", "fail");
    const issues = s.issues.filter((i) => showInfo || i.severity !== "info" || s.skipped);
    return `<div class="stage">${status} ${esc(s.name)}
      ${issues.length ? `<ul class="issues">${issues.map((i) =>
        `<li class="sev-${i.severity}">${esc(i.severity.toUpperCase())}${i.device ? ` [${esc(i.device)}]` : ""}: ${esc(i.message)}</li>`).join("")}</ul>` : ""}
    </div>`;
  }).join("");
}

// ------------------------------------------------------------------ navigation
const loaders = {};
document.querySelectorAll("#nav button").forEach((btn) => btn.addEventListener("click", () => show(btn.dataset.view)));
function show(view) {
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("hidden", v.id !== `view-${view}`));
  loaders[view]?.();
}

// ------------------------------------------------------------------ status
async function loadStatus() {
  try {
    const kb = await api("GET", "/api/kb");
    const pill = $("llm-status");
    if (kb.gemini) {
      pill.textContent = `Gemini: ${kb.model}`;
      pill.classList.add("ok");
    } else {
      pill.textContent = "Gemini key not set – offline parser";
      $("parser").value = "offline";
      $("parser").querySelector('[value="gemini"]').disabled = true;
    }
    return kb;
  } catch (e) { toast(e.message); }
}

// ------------------------------------------------------------------ new intent
const EXAMPLES = [
  "Block HR from reaching Finance on ssh",
  "Isolate HR and Finance completely",
  "HR may only reach VPC5 over https",
  "Deny ping from Finance to HR using firewall",
];
$("examples").innerHTML = EXAMPLES.map((e) => `<button type="button">${esc(e)}</button>`).join("");
$("examples").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => { $("intent-text").value = b.textContent; }));

let conversation = null; // {id, request}

$("analyze").addEventListener("click", () => {
  const text = $("intent-text").value.trim();
  if (!text) return toast("Type an intent first");
  $("clarify").classList.add("hidden");
  $("plan-area").innerHTML = "";
  busy($("analyze"), "Understanding…", async () => {
    const res = await api("POST", "/api/interpret", { text, offline: $("parser").value === "offline" });
    await handleInterpret(res, text);
  });
});

$("clarify-send").addEventListener("click", () => {
  const answer = $("clarify-answer").value.trim();
  if (!answer || !conversation) return;
  busy($("clarify-send"), "Sending…", async () => {
    const res = await api("POST", "/api/interpret", { text: answer, conversation_id: conversation.id });
    $("clarify-answer").value = "";
    await handleInterpret(res, `${conversation.request} (${answer})`);
  });
});
$("clarify-answer").addEventListener("keydown", (e) => { if (e.key === "Enter") $("clarify-send").click(); });

async function handleInterpret(res, request) {
  if (res.clarifications.length) {
    if (!res.conversation_id) {
      return toast(`Please rephrase: ${res.clarifications.join(" ")}`);
    }
    conversation = { id: res.conversation_id, request };
    $("clarify-questions").innerHTML = res.clarifications.map((q) => `<li>${esc(q)}</li>`).join("");
    $("clarify").classList.remove("hidden");
    $("clarify-answer").focus();
    return;
  }
  conversation = null;
  $("clarify").classList.add("hidden");
  await makePlan(res.intents, request, false);
}

async function makePlan(intents, request, raisePriority) {
  $("plan-area").innerHTML = `<div class="card"><span class="spinner"></span>Translating and validating…</div>`;
  const plan = await api("POST", "/api/plans", {
    intents, request, solution: $("solution").value || null, raise_priority: raisePriority,
  });
  renderPlan(plan, { intents, request });
}

function renderPlan(plan, ctx) {
  const area = $("plan-area");
  const isWithdraw = plan.kind === "withdraw";
  let html = "";

  html += `<div class="card">${step(1, isWithdraw ? "Intent to withdraw" : "Understood intent")}
    ${table(["id", "action", "source", "destination", "services", "direction", "priority"],
      plan.intents.map((i) => [esc(i.id), badge(i.action, i.action === "deny" ? "fail" : "pass"), esc(endpoint(i.source)),
        esc(endpoint(i.destination)), esc(services(i.services)), i.bidirectional ? "both ways" : "one way", esc(i.priority)]))}
  </div>`;

  if (plan.intent_report) {
    const conflict = plan.intent_report.stages.find((s) => s.name === "Conflict detection" && !s.passed);
    html += `<div class="card">${step(2, "Intent checks")}${stages(plan.intent_report)}
      ${conflict && ctx ? `<div class="row"><span>This conflicts with an intent that is already deployed.</span>
        <button id="raise-priority" class="primary">Give the new intent higher priority</button></div>` : ""}</div>`;
  }

  if (plan.options.length) {
    html += `<div class="card">${step(3, "Solution selection")}
      ${table(["solution", "feasible", "score", "why"],
        plan.options.map((o) => [`<b>${esc(o.kind)}</b>${plan.chosen === o.kind ? " ✔" : ""}`,
          o.feasible ? "yes" : "no", esc(o.score), o.reasons.map(esc).join("<br>")]),
        (i) => plan.options[i].kind === plan.chosen ? "chosen" : "")}
      ${plan.attempts.filter((a) => !a.passed).map((a) =>
        `<p class="sev-warning">Tried <b>${esc(a.solution)}</b> but it failed validation, so the next option was used.</p>`).join("")}
    </div>`;
  }

  if (plan.candidate) {
    const changes = plan.candidate.changes;
    html += `<div class="card">${step(4, "Generated configuration")}
      ${changes.length ? "" : `<p class="muted">No configuration change is needed.</p>`}
      ${changes.map((c, i) => `<div class="device-config">
        <div class="row"><b>${esc(c.device)}</b><span class="muted">${esc(c.platform)}</span><span class="grow"></span>
          <div class="tabs"><button class="active" data-dev="${i}" data-kind="commands">Config</button>
          <button data-dev="${i}" data-kind="rollback">Rollback</button></div></div>
        <pre class="code" id="cfg-${i}">${esc(c.commands.join("\n"))}</pre></div>`).join("")}
    </div>`;
  }

  if (plan.validation) {
    html += `<div class="card">${step(5, `Validation (${plan.chosen})`)}${stages(plan.validation)}</div>`;
  }

  if (plan.probes.length) {
    html += `<div class="card">${step(6, "Checks after deployment")}
      <ul>${plan.probes.map((p) => `<li>${esc(p.device)}: ping ${esc(p.target)} from ${esc(p.source_interface)} →
        expect <b>${p.expected ? "success" : "failure"}</b> <span class="muted">(${esc(p.purpose)})</span></li>`).join("")}</ul></div>`;
  }

  html += `<div class="card">
    <div class="banner ${plan.ok ? "ok" : "bad"}">${plan.ok ? "✔ Ready to deploy" : "✖ Not deployable – see the errors above"}
      <span class="muted"> · plan ${esc(plan.plan_id)}</span></div>
    ${plan.ok ? `${step(7, "Approve")}
      <p class="muted">Dry run goes through every step without touching the devices. Live pushes to the EVE-NG lab.</p>
      <div class="approve">
        <label><input type="checkbox" id="record-state"> Record dry run as deployed (for testing without the lab)</label>
        <span class="grow"></span>
        <button id="deploy-dry" class="primary">Approve – dry run</button>
        <button id="deploy-live" class="danger">Approve – deploy LIVE</button>
      </div>` : ""}
    <div id="deploy-result"></div></div>`;

  area.innerHTML = html;
  area.scrollIntoView({ behavior: "smooth", block: "start" });

  area.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
    const c = plan.candidate.changes[b.dataset.dev];
    $(`cfg-${b.dataset.dev}`).textContent = c[b.dataset.kind].join("\n");
    b.parentElement.querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
  }));
  $("raise-priority")?.addEventListener("click", (e) =>
    busy(e.target, "Re-planning…", () => makePlan(ctx.intents, ctx.request, true)));
  $("deploy-dry")?.addEventListener("click", (e) => deploy(plan.plan_id, false, e.target));
  $("deploy-live")?.addEventListener("click", (e) => {
    if (confirm(`Push plan ${plan.plan_id} to the LIVE devices?`)) deploy(plan.plan_id, true, e.target);
  });
}

function deploy(planId, live, button) {
  busy(button, live ? "Deploying…" : "Running…", async () => {
    const rep = await api("POST", `/api/plans/${planId}/deploy`, { live, record_state: $("record-state")?.checked || false });
    $("deploy-result").innerHTML = deploymentHtml(rep);
    document.querySelectorAll("#deploy-dry, #deploy-live").forEach((b) => { if (rep.success) b.remove(); });
  });
}

function deploymentHtml(rep) {
  return `<h3 style="margin-top:1rem">Deployment ${esc(rep.deployment_id)} ${rep.dry_run ? "(dry run)" : "(LIVE)"}</h3>
    <div class="banner ${rep.success ? "ok" : "bad"}">${rep.success ? "✔ Success" : "✖ Failed"}${rep.rolled_back ? " – all changes were rolled back" : ""}</div>
    ${table(["device", "status", "backup", "details"], rep.devices.map((d) =>
      [esc(d.device), badge(d.status), `<span class="muted">${esc(d.backup || "")}</span>`,
        (d.errors.length ? d.errors : d.verification).map(esc).join("<br>")]))}
    ${rep.probes.length ? `<ul>${rep.probes.map((p) => `<li>${esc(p.probe)} → <b>${p.actual === null ? "not run (dry run)" : p.ok ? "OK" : "MISMATCH"}</b></li>`).join("")}</ul>` : ""}
    ${rep.messages.map((m) => `<p class="muted">${esc(m)}</p>`).join("")}`;
}

// ------------------------------------------------------------------ intents
loaders.intents = async () => {
  try {
    const records = await api("GET", "/api/intents");
    const latestPlan = records.filter((r) => r.status === "deployed").map((r) => r.plan_id).pop();
    $("intents-table").innerHTML = `
      <div class="approve"><label><input type="checkbox" id="intents-live"> Apply actions to LIVE devices</label>
        <label><input type="checkbox" id="intents-record"> Record dry runs as real</label></div>
      ${table(["id", "status", "solution", "intent", "plan", "updated", ""], records.slice().reverse().map((r) => [
        esc(r.intent.id), badge(r.status), esc(r.solution), esc(r.summary), `<span class="muted">${esc(r.plan_id || "")}</span>`,
        esc((r.updated_at || "").slice(0, 16).replace("T", " ")),
        r.status === "deployed" ? `<button data-withdraw="${esc(r.intent.id)}">Withdraw</button>
          ${r.plan_id === latestPlan ? `<button data-rollback="${esc(r.plan_id)}">Undo last deployment</button>` : ""}` : ""]))}`;
    $("intents-table").querySelectorAll("[data-withdraw]").forEach((b) => b.addEventListener("click", () =>
      busy(b, "Planning…", async () => {
        const plan = await api("POST", `/api/intents/${b.dataset.withdraw}/withdraw`);
        show("submit");
        $("clarify").classList.add("hidden");
        renderPlan(plan, null);
      })));
    $("intents-table").querySelectorAll("[data-rollback]").forEach((b) => b.addEventListener("click", () => {
      const live = $("intents-live").checked;
      if (!confirm(`Undo ${b.dataset.rollback}${live ? " on the LIVE devices" : " (dry run)"}?`)) return;
      busy(b, "Rolling back…", async () => {
        const rep = await api("POST", `/api/plans/${b.dataset.rollback}/rollback`,
          { live, record_state: $("intents-record").checked });
        toast(rep.success ? "Rollback finished" : "Rollback failed – see History", rep.success ? "info" : "error");
        loaders.intents();
      });
    }));
  } catch (e) { toast(e.message); }
};
$("intents-refresh").addEventListener("click", () => loaders.intents());

// ------------------------------------------------------------------ network
loaders.network = async () => {
  const kb = await loadStatus();
  if (!kb) return;
  $("kb-issues").innerHTML = kb.issues.length
    ? `<ul class="issues">${kb.issues.map((i) => `<li class="sev-${i.severity}">${esc(i.message)}</li>`).join("")}</ul>`
    : `<div class="banner ok">✔ Inventory and topology are consistent</div>`;
  $("kb-issues").innerHTML += `<p class="muted">Protected infrastructure subnets: ${kb.protected.map(esc).join(", ")}</p>`;
  $("kb-groups").innerHTML = table(["group", "subnet", "gateway", "switch"],
    kb.groups.map((g) => [esc(g.name), esc(g.subnet), esc(g.gateway), esc(g.switch)]));
  $("kb-hosts").innerHTML = table(["host", "ip", "group", "attached to"],
    kb.hosts.map((h) => [esc(h.name), esc(h.ip), esc(h.group), esc(h.attach)]));
  $("kb-devices").innerHTML = table(["device", "role", "platform", "management", "interfaces"],
    kb.devices.map((d) => [`<b>${esc(d.name)}</b>`, esc(d.role), `${esc(d.platform)}<br><span class="muted">${esc(d.os)}</span>`,
      esc(d.mgmt), d.interfaces.map((i) => `${esc(i.name)} ${esc(i.ip || (i.vlan ? `vlan ${i.vlan}` : ""))}
        <span class="muted">${esc(i.description)}</span>`).join("<br>")]));
};

$("sim-run").addEventListener("click", () => busy($("sim-run"), "Tracing…", async () => {
  const port = $("sim-port").value ? Number($("sim-port").value) : null;
  const r = await api("POST", "/api/simulate", {
    src: $("sim-src").value, dst: $("sim-dst").value, protocol: $("sim-proto").value, port,
  });
  $("sim-result").innerHTML = `<div class="banner ${r.allowed ? "ok" : "bad"}">${esc(r.flow)}: ${r.allowed ? "PERMIT" : "DENY"}</div>
    <pre class="code">${esc(r.trace.join("\n"))}</pre>`;
}));

$("kb-sync").addEventListener("click", () => {
  if (!confirm("Connect to every device and download its running config?")) return;
  busy($("kb-sync"), "Connecting…", async () => {
    const res = await api("POST", "/api/kb/sync");
    $("kb-sync-result").innerHTML = `<ul class="issues">${res.map((r) =>
      `<li class="${r.ok ? "" : "sev-error"}">${esc(r.device)}: ${esc(r.message)}</li>`).join("")}</ul>`;
  });
});

// ------------------------------------------------------------------ history
loaders.history = async () => {
  try {
    const events = await api("GET", "/api/history");
    $("history-table").innerHTML = table(["time (UTC)", "user", "event", "details"], events.map((e) => {
      const { ts, user, event, commands, ...rest } = e;
      const details = Object.entries(rest).map(([k, v]) => `<b>${esc(k)}</b>: ${esc(typeof v === "object" ? JSON.stringify(v) : v)}`);
      if (commands) details.push(`<details><summary>${commands.length} commands</summary><pre class="code">${esc(commands.join("\n"))}</pre></details>`);
      return [esc(ts.slice(0, 19).replace("T", " ")), esc(user), esc(event), details.join("<br>")];
    }));
  } catch (e) { toast(e.message); }
};
$("history-refresh").addEventListener("click", () => loaders.history());

loadStatus();
