// Triage agent demo: deterministic rules over a synthetic dataset.
// No model, no network beyond loading the local JSON file. Every "tool" is
// a read-only lookup; the agent can only recommend, and a person approves.
"use strict";

const DATA_URL = "data/bionic-footwear.json";
const STEP_DELAY = 700; // ms between visible steps
const PERSONAL_DOMAINS = ["mail.example"]; // stand-in for consumer email providers

const $ = (id) => document.getElementById(id);
const fmt = new Intl.DateTimeFormat("en-US", {
  timeZone: "America/Los_Angeles", weekday: "short", month: "short", day: "numeric",
  hour: "numeric", minute: "2-digit",
});
const fmtShort = new Intl.DateTimeFormat("en-US", {
  timeZone: "America/Los_Angeles", hour: "numeric", minute: "2-digit",
});
const when = (iso) => fmt.format(new Date(iso));
const ms = (iso) => Date.parse(iso);
const MIN = 60 * 1000;

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

let DB = null;
let runId = 0;

// ---------- read-only "tools" ----------
const tools = {
  get_user(email) {
    return DB.employees.find((e) => e.email === email) || null;
  },
  get_signins(email) {
    return DB.signins.filter((e) => e.user === email);
  },
  get_endpoint_alerts(email) {
    return DB.endpoint_alerts.filter((e) => e.user === email);
  },
  get_file_events(email) {
    return DB.saas_events.filter((e) => e.user === email);
  },
};

// ---------- the four investigation steps ----------
// Each returns { call, output: [lines], findings: [{text, why, points, kind, evidence, tag}] }

function stepIdentity(email) {
  const u = tools.get_user(email);
  const findings = [];
  const out = [
    `status ${u.status} · ${u.department} · ${u.title}`,
    `groups: ${u.groups.join(", ")}`,
    `MFA: ${u.mfa_factors.join(", ")}`,
    `laptop ${u.device.id} (${u.device.os}, ${u.device.compliant ? "compliant" : "NOT compliant"})`,
  ];
  if (u.last_day) {
    out.push(`last day: ${u.last_day}`);
    findings.push({
      kind: "context", points: 0, tag: "departing",
      text: `Leaving the company on ${u.last_day}.`,
      why: "Not a risk by itself. It raises the weight of any unusual data movement found later.",
    });
  }
  if (u.groups.some((g) => /admin/i.test(g))) {
    findings.push({
      kind: "context", points: 0, tag: "privileged",
      text: "Member of an admin group.",
      why: "A compromise of this account would reach further, so the bar for 'nothing to see' is higher.",
    });
  }
  if (!findings.length) {
    findings.push({ kind: "ok", points: 0, text: "Active, ordinary account. No admin rights, not leaving.",
      why: "Sets the baseline for the next steps." });
  }
  return { call: `get_user(email="${email}")`, output: out, findings, user: u };
}

function stepSignins(email, user) {
  const ev = tools.get_signins(email);
  const usual = new Set([...DB.meta.office_ips, user.home_ip]);
  const unfamiliar = ev.filter((e) => !usual.has(e.ip));
  const countries = [...new Set(ev.map((e) => e.country))];
  const fails = ev.filter((e) => e.event === "user.session.start" && e.outcome === "FAILURE");
  const pushes = ev.filter((e) => e.event === "system.push.send_factor_verify_push");
  const findings = [];

  const out = [
    `${ev.length} events over 7 days · ${new Set(ev.map((e) => e.ip)).size} addresses · countries: ${countries.join(", ")}`,
    `failed passwords: ${fails.length} · MFA pushes sent: ${pushes.length}`,
    `from addresses outside the office and home baseline: ${unfamiliar.length}`,
  ];

  // Password-guessing burst: 4+ failures within 5 minutes.
  const burst = windowed(fails, 5 * MIN, 4);
  if (burst) {
    const after = ev.filter((e) => ms(e.time) > ms(burst[burst.length - 1].time) &&
      ms(e.time) - ms(burst[burst.length - 1].time) < 10 * MIN);
    const reset = after.find((e) => e.event === "user.account.reset_password" && usual.has(e.ip));
    if (reset) {
      findings.push({
        kind: "ok", points: 0, evidence: [...burst, reset],
        text: `${burst.length} wrong passwords in a row, then a password reset and a normal sign-in from a usual address.`,
        why: "Looks like someone who forgot a password, not an attacker: same address, reset flow, then success.",
      });
    } else {
      findings.push({
        kind: "risk", points: 15, evidence: burst,
        text: `${burst.length} wrong passwords within 5 minutes.`,
        why: "Repeated failures in a short burst are what password guessing looks like.",
      });
    }
  }

  // MFA fatigue: 5+ pushes within 15 minutes with 3+ denials or timeouts.
  const pushBurst = windowed(pushes, 15 * MIN, 5);
  if (pushBurst) {
    const t0 = ms(pushBurst[0].time), t1 = ms(pushBurst[pushBurst.length - 1].time) + 2 * MIN;
    const inWin = ev.filter((e) => ms(e.time) >= t0 && ms(e.time) <= t1);
    const denies = inWin.filter((e) => e.event === "user.mfa.okta_verify.deny_push");
    const approved = inWin.find((e) => e.event === "user.authentication.auth_via_mfa");
    if (denies.length >= 3) {
      findings.push({
        kind: "risk", points: 30, evidence: [pushBurst[0], ...denies.slice(-1), pushBurst[pushBurst.length - 1]],
        evidenceCount: pushBurst.length + denies.length,
        text: `${pushBurst.length} MFA pushes in ${Math.round((t1 - t0) / MIN)} minutes; ${denies.length} denied or timed out.`,
        why: "Someone who already has the password keeps sending pushes, hoping the user taps Approve to make it stop (MFA fatigue).",
      });
      if (approved) {
        findings.push({
          kind: "risk", points: 25, evidence: [approved], tag: "mfa_takeover",
          text: `A push was approved at ${fmtShort.format(new Date(approved.time))} after the denials.`,
          why: "The attacker is probably in. An approval at the end of a burst is the moment fatigue works.",
        });
      }
    }
  }

  // New MFA factor added from an unfamiliar address: persistence.
  for (const e of unfamiliar.filter((x) => x.event === "user.mfa.factor.activate")) {
    findings.push({
      kind: "risk", points: 15, evidence: [e], tag: "mfa_takeover",
      text: `A new MFA factor was added from ${e.ip} (${e.country}).`,
      why: "Adding their own factor lets an attacker come back without needing the user again.",
    });
  }

  // Successful sign-ins from unfamiliar addresses.
  const unfamiliarOk = unfamiliar.filter((e) => e.event === "user.session.start" && e.outcome === "SUCCESS");
  for (const e of unfamiliarOk) {
    const t = ms(e.time);
    const mfaNear = ev.some((x) => x.event === "system.push.send_factor_verify_push" &&
      Math.abs(ms(x.time) - t) < 2 * MIN);
    const knownDevice = e.device === user.device.id;
    if (!mfaNear) {
      findings.push({
        kind: "risk", points: 20, evidence: [e], tag: "session_reuse",
        text: `Signed in to ${e.app} from ${e.ip} (${e.country}) with no MFA prompt, on an unknown browser.`,
        why: "No MFA step at all suggests a stolen session or token, not a fresh sign-in.",
      });
    } else if (!knownDevice) {
      findings.push({
        kind: "risk", points: 15, evidence: [e],
        text: `Correct password from ${e.ip} (${e.country}) on an unknown browser.`,
        why: "The password worked from a place and device this person has never used.",
      });
    } else if (!findings.some((f) => f.tag === "travel")) {
      const n = unfamiliarOk.filter((x) => x.device === user.device.id).length;
      findings.push({
        kind: "context", points: 5, evidence: [e], tag: "travel",
        text: `${n} sign-in${n > 1 ? "s" : ""} from ${e.city}, ${e.country}, on their own laptop, with MFA approved.`,
        why: "Own device and normal MFA: most likely travel. Worth confirming, not alarming.",
      });
    }
  }

  if (!findings.length) {
    findings.push({ kind: "ok", points: 0, text: "Sign-ins look normal: usual addresses, usual laptop, MFA every time.",
      why: "Nothing outside the baseline." });
  }
  return { call: `get_signins(user="${email}", window="7d")`, output: out, findings, events: ev };
}

function stepEndpoint(email, user, prior) {
  const alerts = tools.get_endpoint_alerts(email);
  const findings = [];
  const out = alerts.length
    ? alerts.map((a) => `${a.source.padEnd(3)} ${a.severity.padEnd(6)} ${a.title}`)
    : ["no alerts for this user's laptop"];
  let high = 0, med = 0;
  for (const a of alerts) {
    if (a.severity === "high") {
      const pts = high < 2 ? 20 : 0; high++;
      findings.push({ kind: "risk", points: pts, evidence: [a], tag: /credential/i.test(a.title) ? "cred_theft_device" : "malware",
        text: `${a.source}: ${a.title}.`, why: explainAlert(a) });
    } else if (a.severity === "medium") {
      const pts = med < 2 ? 8 : 0; med++;
      findings.push({ kind: "risk", points: pts, evidence: [a], tag: /usb/i.test(a.title) ? "usb" : "malware",
        text: `${a.source}: ${a.title}.`, why: explainAlert(a) });
    } else {
      findings.push({ kind: "ok", points: 0, evidence: [a], text: `${a.source}: ${a.title} (${a.action_taken}).`,
        why: "Low severity and already handled. Recorded, not scored." });
    }
  }
  if (!user.device.compliant && !alerts.some((a) => /compliance/i.test(a.title))) {
    findings.push({ kind: "risk", points: 10, text: "The laptop is out of compliance.",
      why: "Security settings changed or stopped reporting, often a side effect of tampering." });
  }
  // Correlation: credential theft on the laptop, then a session with no MFA from elsewhere.
  const theft = alerts.find((a) => /credential/i.test(a.title));
  const reuse = prior.findings.find((f) => f.tag === "session_reuse");
  if (theft && reuse && ms(reuse.evidence[0].time) > ms(theft.time)) {
    const gap = Math.round((ms(reuse.evidence[0].time) - ms(theft.time)) / MIN);
    findings.push({ kind: "risk", points: 10, tag: "cred_theft_device",
      text: `The no-MFA sign-in came ${gap} minutes after the laptop's password store was read.`,
      why: "Two separate sources tell the same story: stolen from the laptop, then used from somewhere else." });
  }
  if (!alerts.length && user.device.compliant) {
    findings.push({ kind: "ok", points: 0, text: "No endpoint alerts; laptop compliant.", why: "Nothing to add from the laptop." });
  }
  return { call: `get_endpoint_alerts(user="${email}", device="${user.device.id}")`, output: out, findings };
}

function explainAlert(a) {
  if (/macro/i.test(a.title)) return "Documents shouldn't start scripts. This is a common first step for malware.";
  if (/credential/i.test(a.title)) return "Saved passwords on this laptop should be treated as stolen.";
  if (/beacon/i.test(a.title)) return "Regular check-ins to a new domain look like malware waiting for instructions.";
  if (/compliance/i.test(a.title)) return "The laptop stopped meeting security settings right after the other alerts.";
  if (/usb/i.test(a.title)) return "An unapproved drive is a simple way to copy files out without leaving cloud logs.";
  return a.detail;
}

function stepData(email, user, prior) {
  const ev = tools.get_file_events(email);
  const findings = [];
  const ext = ev.filter((e) => e.visibility === "external" && e.action === "file.shared");
  const personal = ext.filter((e) => PERSONAL_DOMAINS.some((d) => String(e.target).endsWith("@" + d)));
  const exports = ev.filter((e) => e.action === "takeout.export_started");
  const publicLinks = ev.filter((e) => e.visibility === "public");
  const downloads = ev.filter((e) => e.action === "file.downloaded");
  const mb = (list) => Math.round(list.reduce((s, e) => s + e.size_mb, 0));
  const out = [
    `${ev.length} file events · internal shares: ${ev.filter((e) => e.visibility === "internal").length}`,
    `external shares: ${ext.length} (${mb(ext)} MB) · to personal accounts: ${personal.length}`,
    `bulk exports: ${exports.length} · made public: ${publicLinks.length} · downloads: ${downloads.length}`,
  ];
  const burst = windowed(ext, 24 * 60 * MIN, 10);
  if (burst) {
    findings.push({ kind: "risk", points: 25, evidence: [burst[0], burst[burst.length - 1]], evidenceCount: burst.length, tag: "exfil",
      text: `${burst.length} files shared outside the company within a day (${mb(burst)} MB).`,
      why: "Ordinary work shares a few files. Dozens in one sitting is moving data out." });
  }
  if (personal.length) {
    findings.push({ kind: "risk", points: 10, evidence: personal.slice(0, 1), evidenceCount: personal.length, tag: "exfil",
      text: `Shared to a personal email account: ${[...new Set(personal.map((e) => e.target))].join(", ")}.`,
      why: "A personal account is outside the company's control once the person leaves." });
    const names = [...new Set(personal.map((e) => e.file))].slice(0, 4);
    out.push(`examples: ${names.join(" · ")}`);
  }
  for (const e of exports) {
    findings.push({ kind: "risk", points: 20, evidence: [e], tag: "exfil",
      text: `Started an export of ${e.file} (${(e.size_mb / 1024).toFixed(1)} GB).`,
      why: "A full export copies everything at once." });
  }
  for (const e of publicLinks) {
    findings.push({ kind: "risk", points: 15, evidence: [e], tag: "public_link",
      text: `"${e.file}" was made public to anyone with the link.`,
      why: "Business files shouldn't be public. Here it happened minutes after a suspicious sign-in." });
  }
  const reuse = prior.find((f) => f.tag === "session_reuse");
  for (const e of downloads) {
    const linked = reuse && Math.abs(ms(e.time) - ms(reuse.evidence[0].time)) < 30 * MIN;
    findings.push({ kind: "risk", points: linked ? 10 : 0, evidence: [e],
      text: `Downloaded "${e.file}" (${e.size_mb} MB)${linked ? " in the suspicious session" : ""}.`,
      why: linked ? "Data taken during a session that skipped MFA." : "A single download is normal." });
  }
  const departing = prior.find((f) => f.tag === "departing");
  const usb = prior.find((f) => f.tag === "usb");
  if (departing && (burst || exports.length || usb)) {
    findings.push({ kind: "risk", points: 10, tag: "exfil",
      text: `This happened in the person's last ${daysUntil(user.last_day, (burst || exports)[0]?.time)} days${usb ? ", alongside a USB drive" : ""}.`,
      why: "Data leaving just before someone does is the classic insider pattern." });
  }
  if (!findings.length) {
    findings.push({ kind: "ok", points: 0, text: "File sharing looks normal: internal colleagues, small files.",
      why: "Nothing left the company." });
  }
  return { call: `get_file_events(user="${email}", window="7d")`, output: out, findings };
}

function daysUntil(day, iso) {
  return Math.max(1, Math.round((Date.parse(day + "T00:00:00Z") - ms(iso)) / (24 * 60 * MIN)));
}

// First run of `min` events that fit in `span` ms, or null.
function windowed(events, span, min) {
  const s = [...events].sort((a, b) => ms(a.time) - ms(b.time));
  let best = null;
  for (let i = 0, j = 0; j < s.length; j++) {
    while (ms(s[j].time) - ms(s[i].time) > span) i++;
    if (j - i + 1 >= min && (!best || j - i + 1 > best.length)) best = s.slice(i, j + 1);
  }
  return best;
}

// ---------- verdict and actions ----------
const ACTIONS = {
  suspend_user: "Suspend the account",
  revoke_sessions: "Sign the account out everywhere",
  reset_mfa: "Remove the MFA factor that was added, and re-enroll the user in person",
  reset_password: "Force a password reset",
  isolate_device: "Isolate the laptop from the network",
  remove_external_shares: "Remove external and public sharing on the affected files",
  escalate_hr_legal: "Escalate to HR and legal before talking to the employee",
  ask_user: "Ask the user (by phone, not email) whether this was them",
  watch_user: "Watch the account for 7 days",
  no_action: "No action",
};

function recommend(score, tags) {
  const a = [];
  const add = (...k) => k.forEach((x) => !a.includes(x) && a.push(x));
  if (tags.has("mfa_takeover")) add("suspend_user", "revoke_sessions", "reset_mfa");
  if (tags.has("cred_theft_device")) add("isolate_device", "revoke_sessions", "reset_password");
  if (tags.has("exfil")) add("revoke_sessions", "remove_external_shares", "escalate_hr_legal");
  if (tags.has("public_link")) add("remove_external_shares");
  if (score >= 70 && !tags.has("exfil")) add("ask_user");
  if (!a.length) {
    if (score >= 40) add("ask_user", "revoke_sessions");
    else if (score >= 5) add("ask_user", "watch_user");
    else add("no_action");
  }
  return a;
}

function level(score) {
  if (score >= 70) return ["high", "High risk: act now"];
  if (score >= 40) return ["medium", "Suspicious: needs a person"];
  if (score >= 5) return ["low", "Low: worth confirming"];
  return ["", "Nothing found"];
}

// ---------- rendering ----------
const sleep = (t) => new Promise((r) => setTimeout(r, t));
const reduced = () => $("fast").checked || matchMedia("(prefers-reduced-motion: reduce)").matches;

function renderStep(num, title, call) {
  const li = el("li", "step running");
  const head = el("div", "step-head");
  head.append(el("strong", null, `${num}. ${title}`), el("span", "step-state", "running…"));
  const pre = el("pre");
  pre.append(el("span", "t-dim", "tool call  "), document.createTextNode(call));
  li.append(head, pre);
  $("steps").append(li);
  return li;
}

function finishStep(li, res) {
  const pre = li.querySelector("pre");
  pre.append(document.createTextNode("\n"));
  for (const line of res.output) {
    pre.append(el("span", "t-dim", "→ "), document.createTextNode(line + "\n"));
  }
  const ul = el("ul", "findings");
  for (const f of res.findings) {
    const item = el("li", f.kind);
    item.append(document.createTextNode(f.text));
    if (f.points) item.append(el("span", "pts", `+${f.points}`));
    item.append(el("span", "why", "Why: " + f.why));
    ul.append(item);
  }
  li.append(ul);
  li.classList.replace("running", "done");
  li.querySelector(".step-state").textContent = "done · read-only";
}

function describe(e) {
  if (e.event) {
    const where = `${e.ip} (${e.city}, ${e.country})`;
    const names = {
      "user.session.start": e.outcome === "SUCCESS" ? `Signed in to ${e.app}` : `Wrong password`,
      "system.push.send_factor_verify_push": "MFA push sent",
      "user.mfa.okta_verify.deny_push": `MFA push ${e.reason === "TIMEOUT" ? "timed out" : "denied"}`,
      "user.authentication.auth_via_mfa": "MFA push approved",
      "user.mfa.factor.activate": "New MFA factor added",
      "user.account.reset_password": "Password reset",
    };
    return `${names[e.event] || e.event} · ${where}`;
  }
  if (e.source) return `${e.source} ${e.severity}: ${e.title}`;
  return `${e.action.replace(/_/g, " ")}: ${e.file} → ${e.target}`;
}

function renderTimeline(results, signins) {
  const items = [];
  const summarized = new Set(); // findings over the same batch of events get one "and N more" line
  for (const r of results) {
    for (const f of r.findings) {
      for (const e of f.evidence || []) items.push({ e, kind: f.kind });
      if (f.evidenceCount && f.evidence && f.evidenceCount > f.evidence.length &&
          !summarized.has(f.evidence[0].id) && summarized.add(f.evidence[0].id)) {
        const last = f.evidence[f.evidence.length - 1];
        items.push({ e: last, kind: f.kind, more: f.evidenceCount - f.evidence.length });
      }
    }
  }
  const normal = signins.filter((s) => s.event === "user.session.start" && s.outcome === "SUCCESS" &&
    !items.some((i) => i.e === s));
  if (normal.length) {
    items.push({ e: normal[0], kind: "", note: "first normal sign-in in the window" });
    items.push({ e: normal[normal.length - 1], kind: "", note: "last normal sign-in in the window" });
  }
  const seen = new Set();
  const list = $("timeline");
  list.replaceChildren();
  items.sort((a, b) => ms(a.e.time) - ms(b.e.time) || (a.more ? 1 : 0) - (b.more ? 1 : 0));
  for (const it of items) {
    const key = it.e.id + (it.more ? "+" : "");
    if (seen.has(key)) continue;
    seen.add(key);
    const li = el("li", it.kind === "ok" ? "" : it.kind);
    const t = el("time", null, when(it.e.time));
    t.dateTime = it.e.time;
    li.append(t, document.createTextNode(
      it.more ? `… and ${it.more} more like this` : describe(it.e) + (it.note ? ` (${it.note})` : "")));
    list.append(li);
  }
}

async function investigate(email) {
  const my = ++runId;
  const wait = async () => { if (!reduced()) await sleep(STEP_DELAY); return my === runId; };
  $("steps").replaceChildren();
  $("result").hidden = true;
  $("approval-result").hidden = true;
  delete $("approval").dataset.decided;
  $("approve").disabled = $("deny").disabled = false;
  $("run").hidden = false;
  $("go").disabled = true;

  const user = tools.get_user(email);
  $("run-title").textContent = `Investigation: ${user.name}`;
  const results = [];
  const plan = [
    ["Identity lookup", () => stepIdentity(email)],
    ["Sign-in anomalies", () => stepSignins(email, user)],
    ["Endpoint", () => stepEndpoint(email, user, results[1])],
    ["Data movement", () => stepData(email, user, results.flatMap((r) => r.findings))],
  ];
  try {
    for (const [i, [title, fn]] of plan.entries()) {
      const res = fn();
      const li = renderStep(i + 1, title, res.call);
      if (!(await wait())) return;
      finishStep(li, res);
      results.push(res);
    }
    if (!(await wait())) return;

    const all = results.flatMap((r) => r.findings);
    const score = Math.min(100, all.reduce((s, f) => s + f.points, 0));
    const [cls, label] = level(score);
    $("score-num").textContent = score;
    $("verdict-label").textContent = label;
    $("result").querySelector(".verdict").className = "verdict " + cls;
    const risks = all.filter((f) => f.points > 0).sort((a, b) => b.points - a.points);
    $("verdict-summary").textContent = risks.length
      ? `Top findings: ${risks.slice(0, 3).map((f) => f.text.replace(/\.$/, "")).join("; ")}.`
      : "Nothing outside this person's normal pattern in the last 7 days.";

    const tb = $("breakdown");
    tb.replaceChildren();
    for (const f of risks) {
      const tr = el("tr");
      tr.append(el("td", null, f.text), el("td", null, `+${f.points}`));
      tb.append(tr);
    }
    const capped = all.reduce((s, f) => s + f.points, 0) > 100;
    const tr = el("tr");
    tr.append(el("td", null, capped ? "Total (capped at 100)" : "Total"), el("td", null, String(score)));
    tr.style.fontWeight = "600";
    tb.append(tr);

    renderTimeline(results, results[1].events);

    const tags = new Set(all.map((f) => f.tag).filter(Boolean));
    renderActions(recommend(score, tags));
    $("result").hidden = false;
  } finally {
    if (my === runId) $("go").disabled = false;
  }
}

// Actions that lock the user out or cut them off. When any of these is
// recommended, asking the user is a follow-up by phone, so it still works
// after the lockout; otherwise asking comes first.
const CONTAINMENT = new Set(["suspend_user", "revoke_sessions", "reset_mfa", "reset_password", "isolate_device"]);

function renderActions(acts) {
  const contain = acts.some((k) => CONTAINMENT.has(k));
  const ordered = acts.includes("ask_user") && !contain
    ? ["ask_user", ...acts.filter((k) => k !== "ask_user")]
    : acts;
  const ul = $("actions");
  ul.replaceChildren();
  for (const k of ordered) {
    const box = el("input");
    box.type = "checkbox";
    box.value = k;
    box.checked = true;
    box.addEventListener("change", updateApprove);
    const label = el("label");
    label.append(box, " ", el("code", null, k), document.createTextNode(" — " + ACTIONS[k]));
    if (k === "ask_user" && contain) label.append(" ", el("span", "tag", "follow-up · by phone"));
    const li = el("li");
    li.append(label);
    ul.append(li);
  }
  updateApprove();
}

function actionBoxes() {
  return [...$("actions").querySelectorAll("input[type=checkbox]")];
}

function updateApprove() {
  const n = actionBoxes().filter((b) => b.checked).length;
  $("approve").textContent = `Approve selected (${n})`;
  if (!$("approval").dataset.decided) $("approve").disabled = n === 0;
}

// One decision per investigation: the first click locks the buttons and
// boxes, and any later click returns here without changing the record.
function decide(approved) {
  const box = $("approval");
  if (box.dataset.decided) return;
  box.dataset.decided = "1";
  $("approve").disabled = $("deny").disabled = true;
  const boxes = actionBoxes();
  boxes.forEach((b) => { b.disabled = true; });
  const yes = approved ? boxes.filter((b) => b.checked).map((b) => b.value) : [];
  const skipped = boxes.map((b) => b.value).filter((k) => !yes.includes(k));
  const now = fmtShort.format(new Date());
  const r = $("approval-result");
  r.textContent = approved
    ? `Decision by you at ${now}. Approved: ${yes.join(", ")}. Skipped: ${skipped.join(", ") || "none"}. Nothing ran, because this is a simulation. In my lab's design, a separate program (not the agent) would run only the approved actions, then check that each one happened.`
    : `Denied at ${now}. Skipped: ${skipped.join(", ")}. Nothing changes, and the agent can't override it.`;
  r.hidden = false;
}

// ---------- startup ----------
function resolve(input) {
  const q = input.trim().toLowerCase();
  if (!q) return null;
  return DB.employees.find((e) => e.email === q || e.name.toLowerCase() === q) ||
    (() => {
      const m = DB.employees.filter((e) => e.name.toLowerCase().includes(q) || e.email.includes(q));
      return m.length === 1 ? m[0] : null;
    })();
}

async function start() {
  try {
    const r = await fetch(DATA_URL);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    DB = await r.json();
  } catch (err) {
    const e = $("error");
    e.textContent = `Couldn't load the dataset (${err.message}). Open this page through a local web server, for example: python3 -m http.server`;
    e.hidden = false;
    $("go").disabled = true;
    return;
  }
  const dl = $("people");
  for (const e of DB.employees) {
    const o = el("option");
    o.value = e.email;
    o.label = e.name;
    dl.append(o);
  }
  // Three seeded stories, two look-alikes that should score low, and one ordinary person.
  const picks = [1, 12, 24, 5, 30, 8].map((i) => DB.employees[i]);
  const sug = $("suggest");
  for (const p of picks) {
    const b = el("button", "chip", p.name);
    b.type = "button";
    b.addEventListener("click", () => { $("who").value = p.email; $("pick").requestSubmit(); });
    sug.append(b);
  }
  $("pick").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const u = resolve($("who").value);
    const e = $("error");
    if (!u) {
      e.textContent = "No single employee matches that. Pick a name from the list or one of the suggestions.";
      e.hidden = false;
      return;
    }
    e.hidden = true;
    investigate(u.email);
  });
  // Shareable link: index.html#who=<email> runs that investigation on load.
  const h = decodeURIComponent(location.hash.replace(/^#who=/, ""));
  if (h && h !== location.hash) { $("who").value = h; $("pick").requestSubmit(); }
  $("approve").addEventListener("click", () => decide(true));
  $("deny").addEventListener("click", () => decide(false));
}

start();
