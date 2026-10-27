// Live hunt view: subscribe to the server-sent event stream and append new findings.
// All telemetry-derived text is inserted with textContent (never innerHTML).
(function () {
  const live = document.getElementById("live");
  if (!live || !window.EventSource) return;
  const state = document.getElementById("live-state");
  if (state && !["planned", "running"].includes(state.textContent.trim())) return;
  const feed = document.getElementById("feed");
  const section = document.getElementById("newfeed");
  const known = new Set(Array.from(document.querySelectorAll('a[href^="/findings/"]'))
    .map(a => a.getAttribute("href").split("/").pop()));
  const shown = new Map();   // id -> feed line, so a finding revised in place updates its line
  const es = new EventSource(live.dataset.stream);
  es.addEventListener("finding", ev => {
    const f = JSON.parse(ev.data);
    if (known.has(f.id) && !f.revised) return;
    known.add(f.id);
    const li = shown.get(f.id) || document.createElement("li");
    li.replaceChildren();
    const pill = document.createElement("span");
    pill.className = "pill l-" + f.lane;
    pill.textContent = f.lane;
    const a = document.createElement("a");
    a.href = "/findings/" + encodeURIComponent(f.id);
    a.textContent = (f.revised ? " (revised) " : " ") + f.rule + ": " + f.claim;
    li.append(pill, a);
    if (!shown.has(f.id)) { shown.set(f.id, li); feed.prepend(li); }
    section.hidden = false;
  });
  es.addEventListener("state", ev => {
    const s = JSON.parse(ev.data);
    if (state) { state.textContent = s.state; state.className = "state s-" + s.state; }
    if (!["planned", "running"].includes(s.state)) es.close();
  });
})();
