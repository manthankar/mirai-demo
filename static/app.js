(() => {
  const $ = s => document.querySelector(s);
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const md = s => esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>")
      .split(/\n/).map(l => /^\s*[-*•]\s+/.test(l) ? "<li>" + l.replace(/^\s*[-*•]\s+/, "") + "</li>" : l + "<br>").join("")
      .replace(/(<li>.*?<\/li>)+/g, m => "<ul>" + m + "</ul>").replace(/(<br>)+$/, "");
  const lvlClass = l => l >= 12 ? "l-crit" : l >= 10 ? "l-high" : l >= 7 ? "l-med" : "l-low";
  const now = () => new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
  const ago = iso => { const m = Math.max(1, Math.round((Date.parse("2026-10-21T16:45:00Z") - Date.parse(iso)) / 60000)); return m + "m ago"; };

  let DATA = null, history = [], busy = false;
  const state = {}; // alert id -> status
  const stats = {tri: 0, auto: 0, pend: 0, hum: 0};
  const setStats = () => { for (const k in stats) $("#s-" + k).textContent = stats[k]; };

  function audit(kind, who, text) {
    const li = document.createElement("li"); li.className = kind;
    li.innerHTML = `<div><span class="who">${esc(who)}</span><span class="ts">${now()}</span></div><div>${text}</div>`;
    $("#audit").prepend(li);
  }
  function quota(n) { if (n !== undefined) $("#quota").textContent = `AI calls left this hour: ${n}`; }
  function addMsg(cls, html) {
    const d = document.createElement("div"); d.className = "msg " + cls;
    d.innerHTML = `<div class="bubble">${html}</div>`; $("#chat").appendChild(d);
    $("#chat").scrollTop = $("#chat").scrollHeight; return d;
  }
  const typing = () => addMsg("ai", `<span class="typing"><span></span><span></span><span></span></span> <span class="muted small">analysing…</span>`);

  function renderAlerts() {
    const ul = $("#alerts"); ul.innerHTML = "";
    DATA.alerts.forEach((a, i) => {
      const li = document.createElement("li"); li.className = `alert ${lvlClass(a.level)}`; li.dataset.id = a.id;
      li.style.animationDelay = (i * 0.12) + "s";
      const st = state[a.id];
      const stHtml = st === "run" ? `<span class="status run">● triaging</span>` : st === "wait" ? `<span class="status wait">● awaiting human</span>`
        : st === "done" ? `<span class="status done">✓ handled</span>` : `<span class="status muted">new</span>`;
      li.innerHTML = `<div class="row"><span class="lvl ${lvlClass(a.level)}">L${a.level}</span><span class="tagx">rule ${esc(a.rule_id)}</span><span class="tagx">${esc(a.agent)}</span>${stHtml}</div>
        <div class="t">${esc(a.title)}</div><div class="row"><span>${esc(a.id)}</span><span>· ${ago(a.timestamp)}</span><span>· ${esc(a.groups.slice(0,2).join(", "))}</span></div>`;
      li.onclick = () => triage(a);
      if ($("#alerts").dataset.sel === a.id) li.classList.add("sel");
      ul.appendChild(li);
    });
  }
  function showAsset(a) {
    const s = DATA.assets[a.agent] || {};
    const rows = [["Host", a.agent], ["Owner", s.owner], ["OS", s.os], ["Role", s.role], ["Criticality", s.criticality], ["Patch status", s.patch_status], ["Kaseya agent", s.kaseya_agent], ["Last seen", s.last_seen]];
    $("#asset .asset-b").innerHTML = `<table>${rows.map(r => `<tr><td>${esc(r[0])}</td><td>${esc(r[1] ?? "n/a")}</td></tr>`).join("")}</table>`;
    $("#asset .asset-b").classList.remove("muted");
  }

  async function api(path, body) {
    const r = await fetch(path, {method: body ? "POST" : "GET", headers: {"Content-Type": "application/json"}, body: body ? JSON.stringify(body) : undefined});
    const j = await r.json().catch(() => ({error: "Bad response"}));
    if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  }

  async function triage(a) {
    if (busy) return;
    $("#alerts").dataset.sel = a.id; showAsset(a);
    if (state[a.id] === "wait" || state[a.id] === "done") { renderAlerts(); }
    busy = true; state[a.id] = "run"; renderAlerts();
    addMsg("user", `Triage <b>${esc(a.id)}</b> · rule ${esc(a.rule_id)} (L${a.level}) on <code>${esc(a.agent)}</code><br><span class="small">${esc(a.title)}</span>`);
    audit("sys", "Wazuh → Mirai", `Alert ${esc(a.id)} (rule ${esc(a.rule_id)}, L${a.level}, ${esc(a.agent)}) sent to AI Security Engineer.`);
    const t = typing();
    try {
      const j = await api("/api/triage", {alert_id: a.id}); quota(j.remaining_this_hour);
      t.remove(); renderCard(a, j.result);
      history.push({role: "user", content: `Triage alert ${a.id}`}, {role: "assistant", content: `${a.id}: ${j.result.severity} – ${j.result.summary} Decision: ${j.result.decision}.`});
    } catch (e) {
      t.remove(); addMsg("err", "⚠ " + esc(e.message)); state[a.id] = undefined;
      audit("warn", "System", `Triage failed for ${esc(a.id)}: ${esc(e.message)}`);
    }
    busy = false; renderAlerts();
  }

  function renderCard(a, r) {
    const sev = ["Critical","High","Medium","Low","Informational"].includes(r.severity) ? r.severity : "Medium";
    const conf = Math.max(0, Math.min(100, parseInt(r.confidence) || 0));
    const m = r.mitre || {}; const tid = String(m.technique_id || "").trim();
    const murl = /^T\d{4}(\.\d{3})?$/.test(tid) ? `https://attack.mitre.org/techniques/${tid.replace(".", "/")}/` : "#";
    const human = r.decision !== "auto_handle";
    const acts = (r.recommended_actions || []).map(x => `<tr><td>${esc(x.action)}</td><td><span class="risk ${x.risk === "high" ? "high" : "low"}">${x.risk === "high" ? "HIGH RISK" : "LOW RISK"}</span></td><td class="small muted">${x.requires_approval ? "needs approval" : "AI can do"}</td></tr>`).join("");
    const id = "c" + Math.random().toString(36).slice(2, 8);
    const html = `<div class="card">
      <div class="hdr"><span class="sev ${sev}">${sev}</span>
        <span class="conf">Confidence <span class="bar"><i style="width:${conf}%"></i></span> ${conf}%</span>
        <span class="verdict">${esc(String(r.verdict || "").replace(/_/g, " "))}</span><span class="muted small">${esc(a.id)}</span></div>
      <div class="summary">${esc(r.summary)}</div>
      <a class="mitre" href="${murl}" target="_blank" rel="noopener">MITRE ATT&amp;CK <b>${esc(tid)}</b> ${esc(m.technique_name)} <span class="muted">· ${esc(m.tactic)}</span></a>
      <div class="sec">Reasoning</div><ul class="reason">${(r.reasoning || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul>
      <div class="sec">Recommended actions</div><table class="acts">${acts}</table>
      <div class="decision ${human ? "human" : "auto"}" id="${id}">
        <div class="dt">${human ? "⏸ Needs human approval" : "✓ Auto-handled by AI (low risk)"}</div>
        <div class="small">${esc(r.decision_rationale)}</div>
        ${human && r.proposed_action_for_approval ? `<div style="margin-top:6px"><b>Proposed:</b> ${esc(r.proposed_action_for_approval)}</div>` : ""}
        ${(r.auto_actions_taken || []).length ? `<div class="small" style="margin-top:6px"><b>AI already did:</b> ${r.auto_actions_taken.map(esc).join(" · ")}</div>` : ""}
        ${human ? `<div class="btns"><button class="btn ok">Approve</button><button class="btn no">Reject</button><button class="btn esc">Escalate to SOC analyst</button></div><div class="outcome"></div>` : ""}
      </div></div>`;
    addMsg("ai", html);
    stats.tri++;
    audit("ai", "AI Security Engineer", `Triaged ${esc(a.id)} → <b>${sev}</b> (${conf}% conf), ${esc(tid)} ${esc(m.technique_name)}.`);
    (r.auto_actions_taken || []).forEach(x => audit("ai", "AI Security Engineer · auto", `${esc(a.id)}: ${esc(x)}`));
    if (!human) { stats.auto++; state[a.id] = "done"; audit("ai", "AI Security Engineer", `${esc(a.id)} closed as auto-handled (low risk, within policy).`); }
    else {
      stats.pend++; state[a.id] = "wait";
      audit("warn", "Approval requested", `${esc(a.id)}: “${esc(r.proposed_action_for_approval || "Review recommended actions")}” awaiting analyst decision.`);
      const box = document.getElementById(id), out = box.querySelector(".outcome");
      const decide = (label, kind, text) => {
        box.querySelectorAll(".btn").forEach(b => b.disabled = true);
        out.innerHTML = text; stats.pend--; stats.hum++; state[a.id] = "done"; setStats(); renderAlerts();
        audit("human", "SOC Analyst (demo user)", `${label} on ${esc(a.id)}: ${esc(r.proposed_action_for_approval || "recommended actions")}.`);
        if (kind === "approve") setTimeout(() => audit("ai", "AI Security Engineer", `Executing approved action for ${esc(a.id)} via Wazuh active response / Kaseya (simulated). Ticket updated.`), 600);
        if (kind === "escalate") setTimeout(() => audit("sys", "SOC queue", `${esc(a.id)} assigned to Tier-2 SOC analyst with AI triage notes attached (simulated).`), 600);
        if (kind === "reject") setTimeout(() => audit("ai", "AI Security Engineer", `Action withheld for ${esc(a.id)}. Monitoring continues; feedback recorded for tuning.`), 600);
      };
      box.querySelector(".ok").onclick = () => decide("APPROVED", "approve", `<span style="color:var(--low)">✓ Approved by analyst. Action queued for execution (simulated).</span>`);
      box.querySelector(".no").onclick = () => decide("REJECTED", "reject", `<span style="color:#ff8fa3">✕ Rejected by analyst. No action taken.</span>`);
      box.querySelector(".esc").onclick = () => decide("ESCALATED", "escalate", `<span style="color:#c99bff">↑ Escalated to SOC analyst (Tier 2) with full AI context.</span>`);
    }
    setStats();
  }

  async function chat(text) {
    if (busy || !text.trim()) return;
    busy = true; addMsg("user", esc(text)); history.push({role: "user", content: text});
    audit("human", "SOC Analyst (demo user)", `Asked: “${esc(text.slice(0, 90))}${text.length > 90 ? "…" : ""}”`);
    const t = typing();
    try {
      const j = await api("/api/chat", {messages: history.slice(-8)}); quota(j.remaining_this_hour);
      t.remove(); addMsg("ai", md(j.reply)); history.push({role: "assistant", content: j.reply});
    } catch (e) { t.remove(); addMsg("err", "⚠ " + esc(e.message)); history.pop(); }
    busy = false;
  }

  $("#form").onsubmit = e => { e.preventDefault(); const v = $("#input").value; $("#input").value = ""; chat(v); };
  document.querySelectorAll(".chip").forEach(c => c.onclick = () => chat(c.textContent));

  (async () => {
    DATA = await api("/api/data"); renderAlerts();
    audit("sys", "System", "Mirai demo session started. Sample Wazuh feed and Kaseya asset inventory loaded.");
    try { quota((await api("/api/status")).remaining_this_hour); } catch {}
  })();
})();
