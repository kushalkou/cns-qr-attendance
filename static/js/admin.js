async function loadUsers() {
  const d = await api("/api/admin/users");
  document.querySelector("#users tbody").innerHTML = d.users.map((u) => `
    <tr>
      <td class="mono">${esc(u.username)}</td><td>${esc(u.name)}</td><td><span class="pill">${esc(u.role)}</span></td>
      <td class="mono small">${u.device_fp ? esc(u.device_fp) : '<span class="muted">-</span>'}</td>
      <td>
        ${u.device_fp ? `<button data-reset="${u.id}">Reset device</button>` : ""}
        ${u.locked ? `<button data-unlock="${u.id}">Unlock</button>` : ""}
      </td>
    </tr>`).join("");
}

async function loadEvents() {
  const d = await api("/api/admin/events");
  document.querySelector("#events tbody").innerHTML = d.events.map((e) => `
    <tr class="${/rejected|failed|denied|blocked|locked/.test(e.kind) ? "bad" : ""}">
      <td class="small">${esc(e.time)}</td><td class="mono small">${esc(e.kind)}</td>
      <td class="mono small">${esc(e.username || "")}</td><td class="mono small">${esc(e.ip || "")}</td>
      <td class="small">${esc(e.detail)}</td>
    </tr>`).join("");
}

document.getElementById("verify-btn").addEventListener("click", async () => {
  const r = await api("/api/admin/verify-chain");
  const out = document.getElementById("verify-result");
  out.innerHTML = r.ok
    ? `<div class="result ok"><b>&#10003; Chain intact</b><br>${r.records} records · head <span class="mono small">${esc(r.head.slice(0, 32))}…</span></div>`
    : `<div class="result err"><b>&#10007; TAMPERING DETECTED</b><ul>${r.problems.map((p) =>
        `<li>Record #${p.id}: ${esc(p.problem)}</li>`).join("")}</ul></div>`;
  loadEvents();
});

document.addEventListener("click", async (ev) => {
  const reset = ev.target.closest("[data-reset]");
  const unlock = ev.target.closest("[data-unlock]");
  try {
    if (reset && confirm("Unbind this student's device? They can then register a new phone.")) {
      await api(`/api/admin/users/${reset.dataset.reset}/reset-device`, { method: "POST" });
      toast("Device reset", "ok"); loadUsers(); loadEvents();
    }
    if (unlock) {
      await api(`/api/admin/users/${unlock.dataset.unlock}/unlock`, { method: "POST" });
      toast("Unlocked", "ok"); loadUsers();
    }
  } catch (e) { toast(e.message, "err"); }
});

document.getElementById("fac-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = Object.fromEntries(new FormData(ev.target));
  try { await api("/api/admin/faculty", { method: "POST", body: f }); toast("Faculty created", "ok"); ev.target.reset(); loadUsers(); }
  catch (e) { toast(e.message, "err"); }
});

loadUsers();
loadEvents();
setInterval(loadEvents, 5000);
