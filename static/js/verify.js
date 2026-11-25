api("/api/pubkey").then((d) => (document.getElementById("pub").textContent = d.public_key));

document.getElementById("file").addEventListener("change", async (ev) => {
  const out = document.getElementById("out");
  const f = ev.target.files[0];
  if (!f) return;
  try {
    const doc = JSON.parse(await f.text());
    const r = await api("/api/verify-report", { method: "POST", body: { report: doc.report, signature: doc.signature } });
    const rep = doc.report || {};
    out.innerHTML = r.valid
      ? `<div class="result ok"><b>&#10003; Signature VALID</b><br>
           ${esc(rep.course?.code)} · session ${esc(rep.session_id)} · closed ${esc(rep.closed_at)}<br>
           ${rep.counts?.present} present, ${rep.counts?.absent} absent · signed by this server's key</div>`
      : `<div class="result err"><b>&#10007; Signature INVALID</b><br>This report was modified after signing, or was not issued by this system.</div>`;
  } catch (e) {
    out.innerHTML = `<div class="result err">Could not read file: ${esc(e.message)}</div>`;
  }
});
