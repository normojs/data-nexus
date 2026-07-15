//! Self-contained Admin status page served at `GET /admin`.
//!
//! Fetches existing JSON Admin APIs from the browser; no separate UI package.

pub const ADMIN_DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Data Nexus Admin</title>
  <style>
    :root {
      --bg: #0f1419;
      --panel: #1a2332;
      --border: #2d3a4d;
      --text: #e7ecf3;
      --muted: #8b9bb4;
      --accent: #3d9cf0;
      --ok: #3ecf8e;
      --warn: #f0b429;
      --err: #f07178;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --sans: "Segoe UI", system-ui, -apple-system, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      background: radial-gradient(1200px 600px at 10% -10%, #1b2a44 0%, var(--bg) 55%);
      color: var(--text);
      min-height: 100vh;
    }
    header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 20px 24px;
      border-bottom: 1px solid var(--border);
      background: rgba(15, 20, 25, 0.85);
      backdrop-filter: blur(8px);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    header h1 {
      margin: 0;
      font-size: 1.15rem;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    header .meta { color: var(--muted); font-size: 0.85rem; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    button, .btn {
      background: var(--panel);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 12px;
      font-size: 0.85rem;
      cursor: pointer;
    }
    button.primary { background: var(--accent); border-color: transparent; color: #041018; font-weight: 600; }
    button:hover { filter: brightness(1.08); }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    main {
      padding: 20px 24px 40px;
      display: grid;
      gap: 16px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px 16px;
      min-height: 120px;
    }
    .card h2 {
      margin: 0 0 10px;
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .stat {
      font-size: 1.8rem;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    th, td {
      text-align: left;
      padding: 8px 6px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 500; }
    code, .mono { font-family: var(--mono); font-size: 0.8rem; }
    .pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      background: #243247;
      color: var(--text);
      font-size: 0.75rem;
    }
    .pill.ok { background: rgba(62, 207, 142, 0.15); color: var(--ok); }
    .pill.err { background: rgba(240, 113, 120, 0.15); color: var(--err); }
    .status-line {
      font-size: 0.85rem;
      color: var(--muted);
      min-height: 1.2em;
    }
    .status-line.error { color: var(--err); }
    .status-line.ok { color: var(--ok); }
    pre {
      margin: 0;
      max-height: 240px;
      overflow: auto;
      background: #0c1118;
      border-radius: 8px;
      padding: 10px;
      font-family: var(--mono);
      font-size: 0.75rem;
      white-space: pre-wrap;
      word-break: break-word;
    }
    a { color: var(--accent); }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Data Nexus Admin</h1>
      <div class="meta" id="version">loading…</div>
    </div>
    <div class="actions">
      <button type="button" id="btn-refresh">Refresh</button>
      <button type="button" class="primary" id="btn-reload">POST /admin/reload</button>
      <a class="btn" href="/metrics" target="_blank" rel="noreferrer">/metrics</a>
    </div>
  </header>
  <main>
    <div class="status-line" id="status"></div>
    <div class="grid">
      <section class="card"><h2>Listeners</h2><div class="stat" id="n-listeners">—</div></section>
      <section class="card"><h2>Services</h2><div class="stat" id="n-services">—</div></section>
      <section class="card"><h2>Endpoints</h2><div class="stat" id="n-endpoints">—</div></section>
      <section class="card"><h2>Sessions</h2><div class="stat" id="n-sessions">—</div></section>
    </div>
    <section class="card">
      <h2>Listeners</h2>
      <div id="tbl-listeners"></div>
    </section>
    <section class="card">
      <h2>Services</h2>
      <div id="tbl-services"></div>
    </section>
    <section class="card">
      <h2>Endpoints</h2>
      <div id="tbl-endpoints"></div>
    </section>
    <section class="card">
      <h2>Pools</h2>
      <div id="tbl-pools"></div>
    </section>
    <section class="card">
      <h2>Sessions</h2>
      <div id="tbl-sessions"></div>
    </section>
    <section class="card">
      <h2>Reload result</h2>
      <pre id="reload-out">—</pre>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const statusEl = $("status");

    function setStatus(msg, kind) {
      statusEl.textContent = msg || "";
      statusEl.className = "status-line" + (kind ? " " + kind : "");
    }

    async function getJson(path) {
      const res = await fetch(path, { headers: { Accept: "application/json" } });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(path + " → " + res.status + " " + text.slice(0, 200));
      }
      return res.json();
    }

    function esc(v) {
      return String(v ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
    }

    function table(headers, rows) {
      if (!rows.length) return "<p class='meta'>empty</p>";
      const head = headers.map((h) => "<th>" + esc(h) + "</th>").join("");
      const body = rows
        .map((r) => "<tr>" + r.map((c) => "<td>" + c + "</td>").join("") + "</tr>")
        .join("");
      return "<table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>";
    }

    async function loadAll() {
      setStatus("Loading…");
      try {
        const [versionText, listeners, services, endpoints, pools, sessions] = await Promise.all([
          fetch("/version").then((r) => r.text()),
          getJson("/admin/listeners"),
          getJson("/admin/services"),
          getJson("/admin/endpoints"),
          getJson("/admin/pools").catch(() => []),
          getJson("/admin/sessions").catch(() => []),
        ]);
        $("version").textContent = versionText.trim() || "Data Nexus";
        $("n-listeners").textContent = listeners.length;
        $("n-services").textContent = services.length;
        $("n-endpoints").textContent = endpoints.length;
        $("n-sessions").textContent = sessions.length;

        $("tbl-listeners").innerHTML = table(
          ["name", "listen_addr", "protocol", "service", "auth_policy"],
          listeners.map((x) => [
            "<span class='mono'>" + esc(x.name) + "</span>",
            "<span class='mono'>" + esc(x.listen_addr) + "</span>",
            "<span class='pill'>" + esc(x.protocol) + "</span>",
            esc(x.service),
            esc(x.auth_policy || "—"),
          ])
        );

        $("tbl-services").innerHTML = table(
          ["name", "backend_protocol", "endpoints", "route_policy", "translation_policy"],
          services.map((x) => [
            "<span class='mono'>" + esc(x.name) + "</span>",
            "<span class='pill'>" + esc(x.backend_protocol) + "</span>",
            esc((x.endpoints || []).join(", ")),
            esc(x.route_policy || "—"),
            esc(x.translation_policy || "—"),
          ])
        );

        $("tbl-endpoints").innerHTML = table(
          ["name", "protocol", "address", "database", "role", "weight"],
          endpoints.map((x) => [
            "<span class='mono'>" + esc(x.name) + "</span>",
            "<span class='pill'>" + esc(x.protocol) + "</span>",
            "<span class='mono'>" + esc(x.address) + "</span>",
            esc(x.database || "—"),
            esc(x.role || "—"),
            esc(x.weight),
          ])
        );

        $("tbl-pools").innerHTML = table(
          ["name", "capacity", "active", "idle", "endpoints"],
          (pools || []).map((x) => [
            "<span class='mono'>" + esc(x.name) + "</span>",
            esc(x.capacity),
            esc(x.active ?? x.in_use ?? "—"),
            esc(x.idle ?? "—"),
            esc(
              Array.isArray(x.endpoints)
                ? x.endpoints.map((e) => e.name || e.address || e).join(", ")
                : "—"
            ),
          ])
        );

        $("tbl-sessions").innerHTML = table(
          ["listener", "frontend", "backend", "user", "database", "endpoint"],
          (sessions || []).map((x) => [
            esc(x.listener || x.listener_name || "—"),
            esc(x.frontend_protocol || "—"),
            esc(x.backend_protocol || "—"),
            esc(x.user || "—"),
            esc(x.database || "—"),
            esc(x.endpoint || x.backend_endpoint || "—"),
          ])
        );

        setStatus("Updated " + new Date().toLocaleTimeString(), "ok");
      } catch (err) {
        setStatus(String(err.message || err), "error");
      }
    }

    async function doReload() {
      const btn = $("btn-reload");
      btn.disabled = true;
      setStatus("Reloading config…");
      try {
        const res = await fetch("/admin/reload", { method: "POST" });
        const text = await res.text();
        let body;
        try { body = JSON.parse(text); } catch { body = text; }
        $("reload-out").textContent = typeof body === "string" ? body : JSON.stringify(body, null, 2);
        if (!res.ok) throw new Error("reload failed: " + res.status);
        setStatus("Reload OK", "ok");
        await loadAll();
      } catch (err) {
        setStatus(String(err.message || err), "error");
      } finally {
        btn.disabled = false;
      }
    }

    $("btn-refresh").addEventListener("click", loadAll);
    $("btn-reload").addEventListener("click", doReload);
    loadAll();
    setInterval(loadAll, 15000);
  </script>
</body>
</html>
"##;
