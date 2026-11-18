// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

(function () {
  "use strict";

  const I18N = {
    id: {
      "a11y.skip": "Lewati ke konten utama",
      "status.connecting": "Menghubungkan...",
      "status.live": "WebSocket Aktif",
      "status.polling": "Mode Polling",
      "btn.theme": "Tema",
      "btn.logout": "Keluar",
      "btn.refresh": "Muat Ulang",
      "btn.run": "Jalankan",
      "nav.dashboard": "Dashboard Real-Time",
      "nav.topology": "Topologi Interaktif",
      "nav.wizards": "Wizard Konfigurasi",
      "nav.terminal": "Terminal CLI",
      "nav.config": "Skema Konfigurasi",
      "login.title": "Masuk ke DaiWeb — DaijiOS",
      "login.subtitle": "Autentikasi RBAC & proteksi brute-force aktif.",
      "login.user": "Nama Pengguna",
      "login.pass": "Kata Sandi / Secret",
      "login.totp": "Kode 2FA TOTP (Opsional)",
      "login.submit": "Masuk Konsol",
      "kpi.cpu": "Beban CPU",
      "kpi.ram": "Memori RAM",
      "kpi.traffic": "Trafik Rx / Tx",
      "kpi.sessions": "Sesi Pelanggan",
      "kpi.alarms": "Alarm Aktif",
      "dash.chart_title": "Grafik Trafik & CPU Real-Time (WebSocket)",
      "dash.alarms_title": "Alarm & Log Peristiwa Terbaru",
      "tbl.time": "Waktu",
      "tbl.level": "Level",
      "tbl.message": "Pesan",
      "topo.title": "Topologi Jaringan & Perangkat Interaktif",
      "topo.inspector": "Inspektor Node Terpilih",
      "topo.hint": "Klik simpul pada topologi untuk melihat detail interface, IP, status WAN, atau VPN peer.",
      "wiz.title": "Wizard Konfigurasi Cepat (Dry-Run & Commit Transaksional)",
      "wiz.preview": "Pratinjau Diff (Dry-Run)",
      "wiz.apply": "Terapkan & Commit",
      "term.title": "Terminal CLI Orisinal DaijiOS (WebSocket)",
      "term.tip": "Ketik '?' untuk bantuan, Tab untuk pelengkapan",
      "term.input_label": "Baris perintah DaijiOS",
      "cfg.title": "Penjelajah Skema SSoT (x-daiji-ui)"
    },
    en: {
      "a11y.skip": "Skip to main content",
      "status.connecting": "Connecting...",
      "status.live": "WebSocket Live",
      "status.polling": "Polling Fallback",
      "btn.theme": "Theme",
      "btn.logout": "Sign Out",
      "btn.refresh": "Refresh",
      "btn.run": "Execute",
      "nav.dashboard": "Real-Time Dashboard",
      "nav.topology": "Interactive Topology",
      "nav.wizards": "Setup Wizards",
      "nav.terminal": "CLI Terminal",
      "nav.config": "Config Schema",
      "login.title": "Sign in to DaiWeb — DaijiOS",
      "login.subtitle": "Least-privilege RBAC & brute-force guard enabled.",
      "login.user": "Username",
      "login.pass": "Password / Secret",
      "login.totp": "2FA TOTP Code (Optional)",
      "login.submit": "Open Console",
      "kpi.cpu": "CPU Load",
      "kpi.ram": "RAM Usage",
      "kpi.traffic": "Traffic Rx / Tx",
      "kpi.sessions": "Subscriber Sessions",
      "kpi.alarms": "Active Alarms",
      "dash.chart_title": "Real-Time Traffic & CPU Chart (WebSocket)",
      "dash.alarms_title": "Alarms & Recent Event Logs",
      "tbl.time": "Time",
      "tbl.level": "Level",
      "tbl.message": "Message",
      "topo.title": "Interactive Network & Device Topology",
      "topo.inspector": "Selected Node Inspector",
      "topo.hint": "Click a node on the topology canvas to inspect interface, IP, WAN status, or VPN peer details.",
      "wiz.title": "Guided Setup Wizards (Dry-Run & Transactional Commit)",
      "wiz.preview": "Preview Diff (Dry-Run)",
      "wiz.apply": "Apply & Commit",
      "term.title": "DaijiOS Original CLI Terminal (WebSocket)",
      "term.tip": "Type '?' for help, press Tab for auto-completion",
      "term.input_label": "DaijiOS command line",
      "cfg.title": "SSoT Configuration Schema Explorer (x-daiji-ui)"
    }
  };

  const WIZARD_DEFS = {
    wan: [
      { id: "interface", label: "WAN Interface", type: "text", val: "eth1" },
      { id: "address", label: "IPv4 CIDR", type: "text", val: "203.0.113.2/30" },
      { id: "gateway", label: "Default Gateway", type: "text", val: "203.0.113.1" },
      { id: "nat", label: "Enable Masquerade NAT", type: "checkbox", val: true }
    ],
    lan: [
      { id: "bridge", label: "LAN Bridge Name", type: "text", val: "br-lan" },
      { id: "cidr", label: "LAN Gateway CIDR", type: "text", val: "192.168.88.1/24" },
      { id: "dhcp_pool", label: "DHCP Pool Range", type: "text", val: "192.168.88.100-192.168.88.240" }
    ],
    pppoe: [
      { id: "server_name", label: "Service Name", type: "text", val: "daiji-fiber" },
      { id: "interface", label: "Access Interface", type: "text", val: "eth2" },
      { id: "pool_cidr", label: "Subscriber Pool CIDR", type: "text", val: "100.64.0.0/20" },
      { id: "mtu", label: "PPP MTU", type: "number", val: 1492 }
    ],
    vpn: [
      { id: "wg_name", label: "WireGuard Interface", type: "text", val: "wg0" },
      { id: "listen_port", label: "Listen UDP Port", type: "number", val: 51820 },
      { id: "tunnel_cidr", label: "Tunnel Address CIDR", type: "text", val: "10.99.0.1/24" }
    ],
    firewall: [
      { id: "rule_name", label: "Rule Name", type: "text", val: "allow-https-mgmt" },
      { id: "action", label: "Action (accept/drop)", type: "text", val: "accept" },
      { id: "protocol", label: "Protocol (tcp/udp)", type: "text", val: "tcp" },
      { id: "dst_port", label: "Destination Port", type: "number", val: 443 }
    ]
  };

  let state = {
    lang: "id",
    theme: "daiji-dark",
    activeWizard: "wan",
    wsTelemetry: null,
    wsCLI: null,
    history: [],
    histIdx: -1,
    samples: []
  };

  function $(id) {
    return document.getElementById(id);
  }

  function applyLang(lang) {
    state.lang = lang;
    document.documentElement.lang = lang;
    const dict = I18N[lang] || I18N.id;
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const k = el.getAttribute("data-i18n");
      if (dict[k]) el.textContent = dict[k];
    });
  }

  function applyTheme(theme) {
    let eff = theme;
    if (theme === "system") {
      eff = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "daiji-light" : "daiji-dark";
    }
    state.theme = eff;
    document.documentElement.setAttribute("data-theme", eff);
  }

  function switchView(viewName) {
    document.querySelectorAll(".nav-btn").forEach((btn) => {
      const active = btn.getAttribute("data-view") === viewName;
      btn.setAttribute("aria-selected", String(active));
    });
    ["dashboard", "topology", "wizards", "terminal", "config"].forEach((v) => {
      const panel = $("view-" + v);
      if (panel) panel.classList.toggle("hidden", v !== viewName);
    });
    if (viewName === "topology") loadTopology();
    if (viewName === "config") loadSchemaUI();
    if (viewName === "terminal") connectCLIWS();
  }

  function renderWizardFields(kind) {
    state.activeWizard = kind;
    document.querySelectorAll("[data-wizard]").forEach((b) => {
      b.classList.toggle("btn-primary", b.getAttribute("data-wizard") === kind);
    });
    const host = $("wizard-fields");
    host.innerHTML = "";
    (WIZARD_DEFS[kind] || []).forEach((f) => {
      const wrap = document.createElement("div");
      wrap.className = "field";
      const lbl = document.createElement("label");
      lbl.setAttribute("for", "wiz-" + f.id);
      lbl.textContent = f.label;
      const inp = document.createElement("input");
      inp.id = "wiz-" + f.id;
      inp.name = f.id;
      if (f.type === "checkbox") {
        inp.type = "checkbox";
        inp.checked = Boolean(f.val);
      } else {
        inp.className = "input";
        inp.type = f.type;
        inp.value = String(f.val);
      }
      wrap.appendChild(lbl);
      wrap.appendChild(inp);
      host.appendChild(wrap);
    });
  }

  async function apiFetch(url, opts) {
    const res = await fetch(url, Object.assign({ credentials: "same-origin" }, opts || {}));
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
    return data;
  }

  function renderTelemetry(snap) {
    $("kpi-cpu").textContent = Number(snap.cpu_percent || 0).toFixed(1) + "%";
    $("kpi-ram").textContent = (snap.mem_used_mb || 0) + " / " + (snap.mem_total_mb || 0) + " MB";
    $("kpi-traffic").textContent = Number(snap.rx_mbps || 0).toFixed(1) + " / " + Number(snap.tx_mbps || 0).toFixed(1) + " Mbps";
    $("kpi-sessions").textContent = String(snap.active_sessions || 0);
    $("kpi-alarms").textContent = String((snap.alarms || []).length);
    $("dash-uptime").textContent = "up " + (snap.uptime_sec || 0) + "s";
    if (snap.hostname) $("topbar-host").textContent = snap.hostname + " — DaijiOS";

    state.samples.push(Number(snap.cpu_percent || 0));
    if (state.samples.length > 30) state.samples.shift();
    drawSparkline(state.samples);

    const tbody = $("logs-tbody");
    tbody.innerHTML = "";
    (snap.events || []).slice(0, 8).forEach((ev) => {
      const tr = document.createElement("tr");
      [ev.time || "-", ev.level || "info", ev.message || ""].forEach((txt) => {
        const td = document.createElement("td");
        td.textContent = txt;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  }

  function drawSparkline(pts) {
    const svg = $("traffic-sparkline");
    if (!svg || pts.length === 0) return;
    const w = 420;
    const h = 110;
    const step = pts.length > 1 ? w / (pts.length - 1) : w;
    const coords = pts.map((v, i) => {
      const clamped = Math.max(0, Math.min(100, v));
      const x = (i * step).toFixed(1);
      const y = (h - 10 - (clamped / 100) * (h - 20)).toFixed(1);
      return x + "," + y;
    }).join(" ");
    svg.innerHTML = `<polyline fill="none" stroke="var(--daiji-accent)" stroke-width="2.5" points="${coords}" />`;
  }

  async function loadTopology() {
    try {
      const topo = await apiFetch("/api/v1/topology");
      const svg = $("topology-svg");
      svg.innerHTML = "";
      const nodes = topo.nodes || [];
      const edges = topo.edges || [];
      const pos = {};
      nodes.forEach((n, idx) => {
        const col = idx === 0 ? 360 : (90 + ((idx - 1) % 4) * 180);
        const row = idx === 0 ? 70 : (200 + Math.floor((idx - 1) / 4) * 100);
        pos[n.id] = { x: col, y: row, node: n };
      });
      edges.forEach((e) => {
        const a = pos[e.from];
        const b = pos[e.to];
        if (!a || !b) return;
        const ln = document.createElementNS("http://www.w3.org/2000/svg", "line");
        ln.setAttribute("x1", a.x); ln.setAttribute("y1", a.y);
        ln.setAttribute("x2", b.x); ln.setAttribute("y2", b.y);
        ln.setAttribute("stroke", "var(--daiji-border)");
        ln.setAttribute("stroke-width", "2");
        svg.appendChild(ln);
      });
      nodes.forEach((n) => {
        const p = pos[n.id];
        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        g.setAttribute("tabindex", "0");
        g.setAttribute("role", "button");
        g.setAttribute("aria-label", n.label + " (" + n.kind + ")");
        const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rect.setAttribute("x", p.x - 68); rect.setAttribute("y", p.y - 22);
        rect.setAttribute("width", "136"); rect.setAttribute("height", "44");
        rect.setAttribute("rx", "6");
        rect.setAttribute("fill", "var(--daiji-bg-surface)");
        rect.setAttribute("stroke", n.up === false ? "var(--daiji-danger)" : "var(--daiji-accent)");
        rect.setAttribute("stroke-width", "2");
        const txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
        txt.setAttribute("x", p.x); txt.setAttribute("y", p.y + 4);
        txt.setAttribute("text-anchor", "middle");
        txt.setAttribute("fill", "var(--daiji-text-primary)");
        txt.setAttribute("font-size", "12");
        txt.textContent = n.label;
        const inspect = () => { $("topo-detail").textContent = JSON.stringify(n, null, 2); };
        g.addEventListener("click", inspect);
        g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); inspect(); } });
        g.appendChild(rect);
        g.appendChild(txt);
        svg.appendChild(g);
      });
    } catch (err) {
      $("topo-detail").textContent = err.message;
    }
  }

  async function loadSchemaUI() {
    try {
      const fields = await apiFetch("/api/v1/ui-schema");
      const tbody = $("schema-tbody");
      tbody.innerHTML = "";
      (fields || []).slice(0, 60).forEach((f) => {
        const tr = document.createElement("tr");
        [f.path, f.group, f.widget, f.impact || "-", f.rbac || "default"].forEach((txt) => {
          const td = document.createElement("td");
          td.textContent = txt;
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
    } catch (err) {
      $("schema-tbody").innerHTML = `<tr><td colspan="5">${err.message}</td></tr>`;
    }
  }

  function connectTelemetryWS() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const badge = $("ws-status");
    try {
      const ws = new WebSocket(proto + "//" + location.host + "/ws/telemetry");
      state.wsTelemetry = ws;
      ws.onopen = () => { badge.textContent = I18N[state.lang]["status.live"]; badge.className = "badge ok"; };
      ws.onmessage = (ev) => { try { renderTelemetry(JSON.parse(ev.data)); } catch (_) {} };
      ws.onerror = ws.onclose = () => {
        badge.textContent = I18N[state.lang]["status.polling"];
        badge.className = "badge";
      };
    } catch (_) {}
  }

  function connectCLIWS() {
    if (state.wsCLI && state.wsCLI.readyState <= 1) return;
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(proto + "//" + location.host + "/ws/cli");
    state.wsCLI = ws;
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.prompt) $("term-prompt").textContent = msg.prompt;
        const out = $("term-output");
        if (msg.output) out.textContent += msg.output + "\n";
        if (msg.error) out.textContent += "ERROR: " + msg.error + "\n";
        out.scrollTop = out.scrollHeight;
      } catch (_) {}
    };
  }

  async function submitWizard(preview) {
    const payload = { wizard: state.activeWizard, preview: preview, commit: !preview, values: {} };
    (WIZARD_DEFS[state.activeWizard] || []).forEach((f) => {
      const el = $("wiz-" + f.id);
      if (!el) return;
      payload.values[f.id] = f.type === "checkbox" ? el.checked : (f.type === "number" ? Number(el.value) : el.value);
    });
    try {
      const res = await apiFetch("/api/v1/wizards/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      $("wizard-output").textContent = JSON.stringify(res, null, 2);
    } catch (err) {
      $("wizard-output").textContent = "ERROR: " + err.message;
    }
  }

  async function enterConsole() {
    $("login-panel").classList.add("hidden");
    $("app-views").classList.remove("hidden");
    $("logout-btn").classList.remove("hidden");
    const snap = await apiFetch("/api/v1/telemetry/snapshot");
    renderTelemetry(snap);
    if (snap.theme) applyTheme(snap.theme);
    connectTelemetryWS();
  }

  document.addEventListener("DOMContentLoaded", () => {
    renderWizardFields("wan");

    $("mobile-nav-toggle").addEventListener("click", () => {
      const open = $("sidebar-nav").classList.toggle("open");
      $("mobile-nav-toggle").setAttribute("aria-expanded", String(open));
    });

    $("lang-toggle").addEventListener("click", () => applyLang(state.lang === "id" ? "en" : "id"));
    $("theme-toggle").addEventListener("click", () => applyTheme(state.theme === "daiji-dark" ? "daiji-light" : "daiji-dark"));

    document.querySelectorAll(".nav-btn").forEach((b) => {
      b.addEventListener("click", () => switchView(b.getAttribute("data-view")));
    });

    document.querySelectorAll("[data-wizard]").forEach((b) => {
      b.addEventListener("click", () => renderWizardFields(b.getAttribute("data-wizard")));
    });

    $("wiz-preview-btn").addEventListener("click", () => submitWizard(true));
    $("wizard-form").addEventListener("submit", (e) => { e.preventDefault(); submitWizard(false); });
    $("refresh-snapshot-btn").addEventListener("click", async () => renderTelemetry(await apiFetch("/api/v1/telemetry/snapshot")));
    $("topo-reload-btn").addEventListener("click", loadTopology);
    $("cfg-reload-btn").addEventListener("click", loadSchemaUI);

    $("login-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("login-error").textContent = "";
      try {
        await apiFetch("/api/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: $("login-user").value,
            password: $("login-pass").value,
            totp: $("login-totp").value
          })
        });
        await enterConsole();
      } catch (err) {
        $("login-error").textContent = err.message;
      }
    });

    $("logout-btn").addEventListener("click", async () => {
      await apiFetch("/api/v1/auth/logout", { method: "POST" }).catch(() => {});
      location.reload();
    });

    const runTerm = () => {
      const val = $("term-input").value;
      if (!val.trim() || !state.wsCLI) return;
      state.history.push(val);
      state.histIdx = state.history.length;
      $("term-output").textContent += $("term-prompt").textContent + " " + val + "\n";
      state.wsCLI.send(JSON.stringify({ type: "exec", cmd: val }));
      $("term-input").value = "";
    };
    $("term-send-btn").addEventListener("click", runTerm);
    $("term-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); runTerm(); }
      if (e.key === "Tab" && state.wsCLI) {
        e.preventDefault();
        state.wsCLI.send(JSON.stringify({ type: "complete", prefix: $("term-input").value }));
      }
      if (e.key === "ArrowUp" && state.histIdx > 0) {
        state.histIdx--;
        $("term-input").value = state.history[state.histIdx];
      }
    });

    // Resume existing HttpOnly cookie session seamlessly if authenticated.
    apiFetch("/api/v1/telemetry/snapshot").then(() => enterConsole()).catch(() => {});
  });
})();
