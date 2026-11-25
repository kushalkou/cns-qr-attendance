async function load() {
  const d = await api("/api/faculty/overview");
  const el = document.getElementById("courses");
  if (!d.courses.length) { el.innerHTML = '<p class="muted">No courses assigned.</p>'; return; }
  el.innerHTML = d.courses.map((c) => `
    <section class="card">
      <div class="session-head">
        <div><h2>${esc(c.code)} · ${esc(c.name)}</h2><p class="muted">${c.enrolled} students enrolled</p></div>
        <div class="row">
          <button class="primary" data-start="${c.id}">Start session</button>
          <button data-def="${c.id}">Defaulters</button>
        </div>
      </div>
      <table><thead><tr><th>Session</th><th>Started</th><th>Present</th><th>Status</th><th></th></tr></thead><tbody>
      ${c.sessions.map((s) => `
        <tr>
          <td class="mono">${esc(s.id)}</td><td>${esc(s.started)}</td><td>${s.n}</td>
          <td>${s.closed_at ? '<span class="pill">signed</span>' : '<span class="pill live">live</span>'}</td>
          <td>${s.closed_at
            ? `<a href="/api/sessions/${esc(s.id)}/report" download>report</a> · <a href="/faculty/session/${esc(s.id)}">view</a>`
            : `<a href="/faculty/session/${esc(s.id)}">open</a>`}</td>
        </tr>`).join("") || '<tr><td colspan="5" class="muted">No sessions yet</td></tr>'}
      </tbody></table>
    </section>`).join("");
}

document.addEventListener("click", async (ev) => {
  const start = ev.target.closest("[data-start]");
  const def = ev.target.closest("[data-def]");
  if (start) {
    try {
      const r = await api("/api/sessions", { method: "POST", body: { course_id: Number(start.dataset.start) } });
      location.href = `/faculty/session/${r.session_id}`;
    } catch (e) { toast(e.message, "err"); }
  }
  if (def) {
    const d = await api(`/api/courses/${def.dataset.def}/defaulters`);
    document.getElementById("def-card").classList.remove("hidden");
    document.getElementById("def-title").textContent = `Attendance · ${d.course} (defaulter < ${d.threshold}%)`;
    document.querySelector("#def-table tbody").innerHTML = d.students.map((s) => `
      <tr class="${s.defaulter ? "bad" : ""}"><td class="mono">${esc(s.usn)}</td><td>${esc(s.name)}</td>
      <td>${s.present} / ${s.total}</td><td>${s.pct}%</td></tr>`).join("");
    document.getElementById("def-card").scrollIntoView({ behavior: "smooth" });
  }
});

load();
