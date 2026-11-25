let me = null;
let keyPair = null;
let scanner = null;

async function refreshDevice() {
  const status = document.getElementById("device-status");
  const bindBtn = document.getElementById("bind-btn");
  me = await api("/api/me");
  if (!Device.supported()) {
    status.innerHTML = '<span class="err">This browser has no WebCrypto. Open the site over HTTPS.</span>';
    return;
  }
  keyPair = await Device.getKey(me.id);
  const localFp = keyPair ? await Device.fingerprint(keyPair) : null;

  if (!me.device_fp) {
    status.textContent = "No phone registered yet. Register this one to start scanning.";
    bindBtn.classList.remove("hidden");
  } else if (localFp === me.device_fp) {
    status.innerHTML = `<span class="ok">&#10003; This phone is your registered device</span> <span class="mono small">${esc(me.device_fp)}</span>`;
    bindBtn.classList.add("hidden");
  } else {
    status.innerHTML = `<span class="err">Your account is bound to a different device (<span class="mono">${esc(me.device_fp)}</span>). Scans from this browser will be rejected. Ask the admin to reset it if you changed phones.</span>`;
    bindBtn.classList.add("hidden");
  }
}

document.getElementById("bind-btn").addEventListener("click", async () => {
  try {
    keyPair = keyPair || (await Device.create(me.id));
    await api("/api/device/register", { method: "POST", body: { pubkey: await Device.publicKeyB64(keyPair) } });
    toast("Device registered", "ok");
    refreshDevice();
  } catch (e) { toast(e.message, "err"); }
});

async function submitToken(token) {
  const out = document.getElementById("scan-result");
  if (!keyPair) { out.innerHTML = '<p class="err">Register this phone first.</p>'; return; }
  try {
    const payload = await Device.signScan(keyPair, token.trim(), me.id);
    const r = await api("/api/scan", { method: "POST", body: payload });
    out.innerHTML = `<div class="result ok"><b>&#10003; ${esc(r.message)}</b><br><span class="mono small">record #${r.record_id} · ${esc(r.hash.slice(0, 24))}…</span></div>`;
    loadAttendance();
  } catch (e) {
    out.innerHTML = `<div class="result err"><b>&#10007; Rejected</b><br>${esc(e.message)}</div>`;
  }
}

document.getElementById("scan-btn").addEventListener("click", async () => {
  const btn = document.getElementById("scan-btn");
  if (scanner) { await scanner.stop().catch(() => {}); scanner = null; btn.textContent = "Scan class QR"; return; }
  scanner = new Html5Qrcode("reader");
  btn.textContent = "Stop camera";
  try {
    await scanner.start({ facingMode: "environment" }, { fps: 10, qrbox: 250 }, async (text) => {
      await scanner.stop().catch(() => {});
      scanner = null;
      btn.textContent = "Scan class QR";
      submitToken(text);
    });
  } catch (e) {
    scanner = null;
    btn.textContent = "Scan class QR";
    toast("Camera unavailable: " + e, "err");
  }
});

document.getElementById("scan-file").addEventListener("change", async (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  try {
    const text = await new Html5Qrcode("reader").scanFile(f, false);
    submitToken(text);
  } catch (e) { toast("No QR found in image", "err"); }
  ev.target.value = "";
});

document.getElementById("manual-btn").addEventListener("click", () => {
  submitToken(document.getElementById("manual-token").value);
});

async function loadAttendance() {
  const d = await api("/api/me/attendance");
  document.querySelector("#att-table tbody").innerHTML = d.courses.map((c) => `
    <tr class="${c.defaulter ? "bad" : ""}">
      <td>${esc(c.code)} <span class="muted small">${esc(c.name)}</span></td>
      <td>${c.present} / ${c.total}</td>
      <td>${c.pct}%</td>
    </tr>`).join("") || '<tr><td colspan="3" class="muted">Not enrolled in any course</td></tr>';
  document.getElementById("threshold").textContent = `Below ${d.threshold}% = defaulter (highlighted).`;
}

refreshDevice().catch((e) => toast(e.message, "err"));
loadAttendance();
