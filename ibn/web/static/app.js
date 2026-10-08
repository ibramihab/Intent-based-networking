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
      pill.textContent = `AI: ${kb.model}`;
      pill.classList.add("ok");
    } else {
      pill.textContent = "AI not configured – add GEMINI_API_KEY to .env";
      pill.classList.add("bad");
    }
    return kb;
  } catch (e) { toast(e.message); }
}

// ------------------------------------------------------------------ new intent
const EXAMPLES = [
  "Block HR from reaching the Finance network over SSH, everything else must keep working",
  "Isolate HR and Finance completely",
  "HR may only reach VPC5 over https",
  "Traffic from HR to Finance must go through R2 instead of the GRE tunnel",
  "Finance must not be able to ping the HR gateway, but HR can still ping Finance",
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
    const res = await api("POST", "/api/interpret", { text });
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
    conversation = { id: res.conversation_id, request };
    $("clarify-questions").innerHTML = res.clarifications.map((q) => `<li>${esc(q)}</li>`).join("");
    $("clarify").classList.remove("hidden");
    $("clarify-answer").focus();
    return;
  }
  conversation = null;
  $("clarify").classList.add("hidden");
  await makePlan(res.intents, request, false, res.conversation_id);
}

async function makePlan(intents, request, override, conversationId) {
  $("plan-area").innerHTML = `<div class="card"><span class="spinner"></span>Designing the configuration and validating it…
    <p class="muted">The AI designs the change, the Validation Layer checks it, and rejected designs go back to the AI.
    This can take a minute.</p></div>`;
  try {
    const plan = await api("POST", "/api/plans", {
      intents, request, override, conversation_id: conversationId || null,
    });
    renderPlan(plan, { intents, request, conversationId });
  } catch (e) {
    $("plan-area").innerHTML = "";
    throw e;
  }
}

const expectationRow = (e) => [esc(e.src), esc(e.dst), esc(e.protocol + (e.port ? `/${e.port}` : "")),
  badge(e.expect, e.expect === "allow" ? "pass" : "fail")];

function renderPlan(plan, ctx) {
  const area = $("plan-area");
  const isWithdraw = plan.kind === "withdraw";
  let html = "";

  html += `<div class="card">${step(1, isWithdraw ? "Intent to withdraw" : "Understood intent")}
    ${plan.intents.map((i) => `<div class="intent">
      <p><b>${esc(i.description)}</b> <span class="pill">${esc(i.category)}</span> <span class="muted">priority ${esc(i.priority)} · ${esc(i.id)}</span></p>
      ${i.requirements.length ? `<ul>${i.requirements.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
      <p class="muted">Scope: ${esc(Object.entries(i.scope).filter(([, v]) => v.length).map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ") || "—")}</p>
      ${i.expectations.length ? `<p class="muted">Testable expectations</p>${table(["from", "to", "traffic", "expected"], i.expectations.map(expectationRow))}` : ""}
    </div>`).join("")}
  </div>`;

  if (plan.intent_report) {
    const conflict = plan.intent_report.stages.find((s) => s.name === "Conflict detection" && !s.passed);
    html += `<div class="card">${step(2, "Intent checks")}${stages(plan.intent_report)}
      ${conflict && ctx ? `<div class="row"><span>This request contradicts an intent that is already deployed.</span>
        <button id="override" class="danger">Override the deployed intent</button></div>` : ""}</div>`;
  }

  const redesigns = plan.attempts.filter((a) => a.errors.length);
  if (redesigns.length && plan.design) {
    html += `<div class="card warn"><h3>The Validation Layer sent the design back to the AI ${redesigns.length} time(s)</h3>
      ${redesigns.map((a) => `<p>Attempt ${a.number} (<b>${esc(a.approach)}</b>) was rejected:</p>
        <ul class="issues">${a.errors.map((e) => `<li class="sev-error">${esc(e)}</li>`).join("")}</ul>`).join("")}
      ${plan.ok ? `<p class="muted">The AI corrected it; the design below passed.</p>` : ""}</div>`;
  }

  if (plan.design_error) {
    html += `<div class="card"><p class="sev-error">${esc(plan.design_error)}</p></div>`;
  }

  const d = plan.design;
  if (d) {
    html += `<div class="card">${step(3, "AI design")}
      <p><b>Approach:</b> ${esc(d.approach)}</p>
      <p>${esc(d.reasoning)}</p>
      ${d.risks.length ? `<p class="muted">Risks noted by the AI:</p><ul>${d.risks.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
      <details><summary>Vendor-neutral model (${d.neutral_model.length} object${d.neutral_model.length === 1 ? "" : "s"})</summary>
        <pre class="code">${esc(JSON.stringify(d.neutral_model, null, 2))}</pre></details>
    </div>`;
    html += `<div class="card">${step(4, "Device configuration")}
      ${d.devices.map((c, i) => `<div class="device-config">
        <div class="row"><b>${esc(c.device)}</b><span class="grow"></span>
          <div class="tabs"><button class="active" data-dev="${i}" data-kind="commands">Config</button>
          <button data-dev="${i}" data-kind="rollback">Rollback</button>
          <button data-dev="${i}" data-kind="verify">Verify</button></div></div>
        <pre class="code" id="cfg-${i}">${esc(c.commands.join("\n"))}</pre></div>`).join("")}
    </div>`;
  }

  if (plan.validation) {
    html += `<div class="card">${step(5, "Validation")}${stages(plan.validation)}
      ${plan.limited_verification.length ? `<div class="banner warn-banner">⚠ Limited verification: the simulator cannot model
        ${esc(plan.limited_verification.join("; "))}. Review the configuration yourself before approving.</div>` : ""}</div>`;
  }

  if (plan.probes.length || (d && d.devices.some((c) => c.verify.length))) {
    html += `<div class="card">${step(6, "Checks after deployment")}
      <ul>${plan.probes.map((p) => `<li>${esc(p.device)}: ping ${esc(p.target)} from ${esc(p.source_interface)} →
        expect <b>${p.expected ? "success" : "failure"}</b> <span class="muted">(${esc(p.purpose)})</span></li>`).join("")}
      ${d ? d.devices.flatMap((c) => c.verify.map((v) => `<li>${esc(c.device)}: <code>${esc(v.command)}</code>
        ${v.expect_contains.length ? ` must show ${v.expect_contains.map((x) => `“${esc(x)}”`).join(", ")}` : ""}</li>`)).join("") : ""}</ul></div>`;
  }

  const limited = plan.limited_verification.length > 0;
  html += `<div class="card">
    <div class="banner ${plan.ok ? "ok" : "bad"}">${plan.ok ? "✔ Ready to deploy" : "✖ Not deployable – see the errors above"}
      <span class="muted"> · plan ${esc(plan.plan_id)}</span></div>
    ${plan.ok ? `${step(7, "Approve")}
      <p class="muted">Dry run goes through every step without touching the devices. Live pushes to the EVE-NG lab.</p>
      ${limited ? `<label class="ack"><input type="checkbox" id="ack"> I reviewed the AI-generated configuration; parts of it could
        not be verified by simulation.</label>` : ""}
      <div class="approve">
        <label><input type="checkbox" id="record-state"> Record dry run as deployed (for testing without the lab)</label>
        <span class="grow"></span>
        <button id="deploy-dry" class="primary">Approve – dry run</button>
        <button id="deploy-live" class="danger" ${limited ? "disabled" : ""}>Approve – deploy LIVE</button>
      </div>` : ""}
    <div id="deploy-result"></div></div>`;

  area.innerHTML = html;
  area.scrollIntoView({ behavior: "smooth", block: "start" });

  area.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
    const c = d.devices[b.dataset.dev];
    $(`cfg-${b.dataset.dev}`).textContent = b.dataset.kind === "verify"
      ? c.verify.map((v) => `${v.command}\n  must contain: ${v.expect_contains.join(", ") || "-"}\n  must not contain: ${v.expect_absent.join(", ") || "-"}`).join("\n") || "(no verification commands)"
      : c[b.dataset.kind].join("\n");
    b.parentElement.querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
  }));
  $("ack")?.addEventListener("change", (e) => { $("deploy-live").disabled = !e.target.checked; });
  $("override")?.addEventListener("click", (e) => {
    if (confirm("The new intent will take precedence over the deployed intent it contradicts. Continue?")) {
      busy(e.target, "Re-planning…", () => makePlan(ctx.intents, ctx.request, true, ctx.conversationId));
    }
  });
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
      ${table(["id", "status", "intent", "approach (AI)", "plan", "updated", ""], records.slice().reverse().map((r) => [
        esc(r.intent.id), badge(r.status), esc(r.summary), esc(r.approach), `<span class="muted">${esc(r.plan_id || "")}</span>`,
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
  const sel = $("cfg-device");
  sel.innerHTML = Object.keys(kb.configs).map((n) => `<option>${esc(n)}</option>`).join("");
  const showCfg = () => { $("cfg-view").textContent = kb.configs[sel.value] || ""; };
  sel.onchange = showCfg;
  showCfg();
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
