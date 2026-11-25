const sid = document.getElementById("sid").dataset.sid;
const period = Number(document.getElementById("sid").dataset.period);
let lastToken = null;
let timer = null;

async function tick() {
  let d;
  try { d = await api(`/api/sessions/${sid}/live`); } catch (e) { toast(e.message, "err"); return; }
  document.getElementById("course").textContent = d.course;
  document.getElementById("count").textContent = d.present.length;
  document.getElementById("enrolled").textContent = d.enrolled;

  if (d.closed) {
    clearInterval(timer);
    document.getElementById("qr").innerHTML = '<p class="big muted">Session closed</p>';
    document.getElementById("close-btn").classList.add("hidden");
    document.getElementById("token-text").textContent = "";
    showReport();
  } else {
    if (d.token !== lastToken) {
      document.getElementById("qr").innerHTML = d.qr_svg; // our own server-generated SVG
      document.getElementById("token-text").textContent = d.token;
      lastToken = d.token;
    }
    document.getElementById("bar-fill").style.width = `${(100 * d.expires_in) / period}%`;
  }

  document.getElementById("present").innerHTML = d.present.map((p) => `
    <li><b>${esc(p.name)}</b> <span class="mono small">${esc(p.username)}</span>
    ${p.method === "manual" ? `<span class="pill warn" title="${esc(p.note)}">manual</span>` : ""}
    <span class="muted small">${esc(p.time.split(", ")[1])} · #${p.id} ${esc(p.hash.slice(0, 10))}…</span></li>`).join("")
    || '<li class="muted">Nobody yet</li>';

  document.getElementById("rejected").innerHTML = d.rejected.map((r) => `
    <li><span class="mono small">${esc(r.username || "?")}</span> ${esc(r.detail)}
    <span class="muted small">${esc(r.time.split(", ")[1])}</span></li>`).join("")
    || '<li class="muted">None</li>';
}

async function showReport() {
  try {
    const r = await api(`/api/sessions/${sid}/report`);
    document.getElementById("report-card").classList.remove("hidden");
    document.getElementById("sig").textContent = r.signature;
    document.getElementById("head").textContent = `#${r.report.chain_head_id} ${r.report.chain_head}`;
  } catch (_) {}
}

document.getElementById("close-btn").addEventListener("click", async () => {
  if (!confirm("Close the session and sign the report? No more scans will be accepted.")) return;
  try { await api(`/api/sessions/${sid}/close`, { method: "POST" }); toast("Report signed", "ok"); tick(); }
  catch (e) { toast(e.message, "err"); }
});

document.getElementById("manual-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  try {
    await api(`/api/sessions/${sid}/manual`, { method: "POST", body: { usn: f.get("usn"), reason: f.get("reason") } });
    toast("Marked present (logged as manual override)", "ok");
    ev.target.reset();
    tick();
  } catch (e) { toast(e.message, "err"); }
});

tick();
timer = setInterval(tick, 1000);
