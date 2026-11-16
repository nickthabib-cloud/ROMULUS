// Progressive enhancement for the server-rendered pages: every control works without scripts, these only make
// it smoother. All telemetry-derived text is inserted with textContent (never innerHTML).

// Theme: dark by default; the choice is kept in this browser only.
(function () {
  const button = document.getElementById("theme-toggle");
  if (!button) return;
  button.hidden = false;
  button.addEventListener("click", () => {
    const light = document.documentElement.getAttribute("data-theme") !== "light";
    if (light) document.documentElement.setAttribute("data-theme", "light");
    else document.documentElement.removeAttribute("data-theme");
    try { window.localStorage.setItem("romulus-theme", light ? "light" : "dark"); } catch (error) { /* not kept */ }
  });
})();

// Menus are <details> elements: close them on an outside click or Escape.
(function () {
  const menus = () => Array.from(document.querySelectorAll("details.menu[open]"));
  document.addEventListener("click", ev => {
    for (const menu of menus()) if (!menu.contains(ev.target)) menu.removeAttribute("open");
  });
  document.addEventListener("keydown", ev => {
    if (ev.key !== "Escape") return;
    for (const menu of menus()) { menu.removeAttribute("open"); menu.querySelector("summary").focus(); }
  });
})();

// Confirmation dialogs: a link with data-dialog opens the named <dialog> instead of the confirmation page it
// points to (which stays the fallback). A dialog's submit button stays disabled until the typed confirmation
// matches; the server checks the confirmation again.
(function () {
  for (const opener of document.querySelectorAll("a[data-dialog]")) {
    const dialog = document.getElementById(opener.dataset.dialog);
    if (!dialog || typeof dialog.showModal !== "function") continue;
    opener.addEventListener("click", ev => {
      ev.preventDefault();
      const menu = opener.closest("details.menu");
      if (menu) menu.removeAttribute("open");
      dialog.showModal();
      const input = dialog.querySelector("input[data-expected]");
      if (input) { input.value = ""; input.dispatchEvent(new Event("input")); input.focus(); }
    });
  }
  for (const input of document.querySelectorAll("dialog input[data-expected]")) {
    const submit = input.form && input.form.querySelector("button[type=submit]");
    input.addEventListener("input", () => { if (submit) submit.disabled = input.value !== input.dataset.expected; });
  }
  for (const close of document.querySelectorAll("dialog [data-close]")) {
    close.addEventListener("click", () => close.closest("dialog").close());
  }
})();

// Live hunt view: subscribe to the server-sent event stream and append new findings.
(function () {
  const live = document.getElementById("live");
  if (!live || live.dataset.live !== "true" || !window.EventSource) return;
  const state = document.getElementById("live-state");
  const feed = document.getElementById("feed");
  const section = document.getElementById("newfeed");
  const known = new Set(Array.from(document.querySelectorAll('a[data-finding-id]'))
    .map(a => a.dataset.findingId));
  const initial = new Set(known);
  const shown = new Map();   // id -> feed line, so a finding revised in place updates its line
  // A finding the server rendered with the page: a revision updates that row (its link text, lane pill and row
  // class) instead of adding a second line beside the stale one.
  const rendered = id => Array.from(document.querySelectorAll('a[data-finding-id]'))
    .find(a => !(feed && feed.contains(a)) && a.dataset.findingId === id);
  const agentBadge = () => {
    const badge = document.createElement("b");
    badge.className = "agent-provenance";
    badge.textContent = "AI agent · unconfirmed";
    return badge;
  };
  const updateRendered = (a, f) => {
    const claim = f.claim.length > 220 ? f.claim.slice(0, 217) + "..." : f.claim;
    a.textContent = "(revised) " + claim;
    const row = a.closest("tr, li");
    if (!row) return;
    const pill = row.querySelector(".pill");
    if (pill) { pill.className = "pill l-" + f.lane; pill.textContent = f.lane; }
    if (f.provenance === "agent" && !row.querySelector(".agent-provenance")) a.parentElement.append(agentBadge());
    if (row.tagName === "TR") row.className = "row-" + f.lane;
  };
  const es = new EventSource(live.dataset.stream);
  es.addEventListener("finding", ev => {
    const f = JSON.parse(ev.data);
    if (known.has(f.id) && !f.revised) return;
    if (f.revised && !shown.has(f.id)) {
      const a = rendered(f.id);
      if (a) { updateRendered(a, f); return; }
    }
    if (!feed) return;
    known.add(f.id);
    const li = shown.get(f.id) || document.createElement("li");
    li.replaceChildren();
    const pill = document.createElement("span");
    pill.className = "pill l-" + f.lane;
    pill.textContent = f.lane;
    const a = document.createElement("a");
    a.href = "/findings/" + encodeURIComponent(f.id);
    a.textContent = (f.revised ? "(revised) " : "") + f.rule + ": " + f.claim;
    li.append(pill);
    if (f.provenance === "agent") li.append(agentBadge());
    li.append(a);
    if (!shown.has(f.id)) { shown.set(f.id, li); feed.prepend(li); }
    while (shown.size > 50) {
      const oldest = feed.lastElementChild;
      const oldestEntry = Array.from(shown.entries()).find(([, element]) => element === oldest);
      if (oldestEntry) { shown.delete(oldestEntry[0]); if (!initial.has(oldestEntry[0])) known.delete(oldestEntry[0]); }
      oldest.remove();
    }
    if (section) section.hidden = false;
  });
  const activity = document.getElementById("agent-activity");
  for (const name of ["agent_run", "hypothesis", "session", "tool_call", "agent_finding"]) {
    es.addEventListener(name, ev => {
      if (!activity) return;
      const item = JSON.parse(ev.data);
      const li = document.createElement("li");
      li.textContent = (name === "agent_finding" ? "AI agent · unconfirmed" : name.replaceAll("_", " ")) + ": " +
        [item.id, item.session, item.name, item.purpose, item.state || item.status, item.confidence,
         item.statement || item.claim, item.reason, item.tool_calls === undefined ? "" : item.tool_calls + " calls"]
          .filter(value => value !== undefined && value !== null && value !== "").join(" · ");
      activity.prepend(li);
      while (activity.children.length > 50) activity.lastElementChild.remove();
    });
  }
  es.addEventListener("end", () => es.close());
  es.addEventListener("state", ev => {
    const s = JSON.parse(ev.data);
    if (state) { state.textContent = s.state; state.className = "state s-" + s.state; }
    for (const [lane, count] of Object.entries(s.lanes || {})) {
      const cell = document.querySelector('[data-lane-count="' + lane + '"]');
      if (cell) cell.textContent = String(count);
    }
  });
})();
