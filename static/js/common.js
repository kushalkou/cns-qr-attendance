// Shared helpers. All dynamic text goes through esc() before touching innerHTML (XSS defence).
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (res.status === 401) { location.href = "/login"; throw new Error("Not logged in"); }
  if (!res.ok) throw new Error(data.reason || data.detail || `HTTP ${res.status}`);
  return data;
}

function toast(msg, kind = "") {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "show " + kind;
  clearTimeout(t._h);
  t._h = setTimeout(() => (t.className = ""), 3500);
}
