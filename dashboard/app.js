// podgate dashboard: a read-only view of GET /api/overview and POST /api/explain.
// No dependencies. Every string that came from the API is inserted as a text node, never parsed
// as HTML, and no style or handler is set as an attribute, so the page runs under a CSP
// with no 'unsafe-inline'.

const REFRESH_MS = 5000;
const MAX_APP_PAGES = 20;
const PAGE_ORDER = ["summary", "apps", "services", "certificates", "explain"];

const view = document.getElementById("view");
const statusLine = document.getElementById("status");
const pauseButton = document.getElementById("pause");
const tabs = document.getElementById("tabs");

let overview = null;
let paused = false;
let loading = false;
let current = null;

// ---------------------------------------------------------------- building blocks

/** Builds an element. Children are strings (text nodes) or nodes; attributes are plain values. */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "on") {
      for (const [type, handler] of Object.entries(value)) node.addEventListener(type, handler);
    } else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** Replaces the content of `root` with `nodes`, skipping the nulls a conditional leaves. */
function fill(root, ...nodes) {
  root.replaceChildren(...nodes.flat(Infinity).filter((node) => node !== null && node !== undefined && node !== false));
}

function code(text) {
  return el("code", {}, text);
}

function tag(text, cls) {
  return el("span", { class: cls }, text);
}

function table(headers, rows, empty) {
  if (rows.length === 0) return el("p", { class: "empty" }, empty);
  return el(
    "table",
    {},
    el("thead", {}, el("tr", {}, headers.map((header) => el("th", {}, header)))),
    el("tbody", {}, rows.map((cells) => el("tr", {}, cells.map((cell) => el("td", {}, cell))))),
  );
}

function card(label, value, cls) {
  return el(
    "div",
    { class: "card" },
    el("div", { class: "label" }, label),
    el("div", { class: cls ? `value ${cls}` : "value" }, value),
  );
}

function definitions(pairs) {
  return el(
    "dl",
    {},
    pairs
      .filter(([, value]) => value !== undefined && value !== null && value !== "")
      .flatMap(([name, value]) => [el("dt", {}, name), el("dd", {}, value)]),
  );
}

/** An array from a field that is a count in the stub of an app too large to show. */
function list(value) {
  return Array.isArray(value) ? value : [];
}

function compact(value) {
  return JSON.stringify(value);
}

function count(n) {
  return Number(n ?? 0).toLocaleString();
}

function bytes(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = Number(n ?? 0);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
}

function date(seconds) {
  return new Date(seconds * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function daysLeft(seconds) {
  return Math.floor((seconds * 1000 - Date.now()) / 86_400_000);
}

function recent(r) {
  if (!r) return "";
  const errors = r.errors_5xx > 0 ? tag(`${count(r.errors_5xx)} 5xx`, "bad") : "0 5xx";
  return el("span", {}, `${count(r.requests)} requests, `, errors, ` in ${r.window_secs} s`);
}

// ---------------------------------------------------------------- data

async function getJson(url, init) {
  const response = await fetch(url, { cache: "no-store", credentials: "same-origin", ...init });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status, body };
}

async function fetchOverview() {
  const first = await getJson("/api/overview?limit=500");
  if (first.status !== 200) {
    throw new Error(`${first.status} ${first.body?.error ?? "unexpected answer"}`);
  }
  const document_ = first.body;
  let page = document_.apps;
  for (let n = 0; n < MAX_APP_PAGES && page?.truncated && page.next; n += 1) {
    const more = await getJson(
      `/api/overview?section=apps&limit=500&after=${encodeURIComponent(page.next)}`,
    );
    if (more.status !== 200) break;
    document_.apps.items.push(...more.body.apps.items);
    document_.apps.truncated = more.body.apps.truncated;
    document_.apps.next = more.body.apps.next;
    page = more.body.apps;
  }
  return document_;
}

async function refresh() {
  if (loading) return;
  loading = true;
  try {
    overview = await fetchOverview();
    statusLine.className = "";
    statusLine.textContent = `updated ${new Date().toLocaleTimeString()}`;
    current?.update();
  } catch (error) {
    statusLine.className = "bad";
    statusLine.textContent = `error: ${error.message}`;
  } finally {
    loading = false;
  }
}

const appItems = () => overview?.apps?.items ?? [];

// ---------------------------------------------------------------- pages

function serverClass(server) {
  if (server.ejected_for_ms !== undefined || server.healthy === false) return "bad";
  return server.available ? "good" : "warn";
}

function serverState(server) {
  if (server.ejected_for_ms !== undefined) return tag(`ejected ${count(server.ejected_for_ms)} ms`, "bad");
  if (server.healthy === false) return tag("unhealthy", "bad");
  return tag(server.available ? "available" : "unavailable", serverClass(server));
}

const summaryPage = {
  mount(root) {
    this.box = el("div", {});
    root.append(this.box);
  },
  update() {
    if (!overview?.summary) return;
    const s = overview.summary;
    const servers = s.servers;
    const note = (list) => (list?.truncated ? el("p", { class: "empty" }, "The list is cut short; the node has more than this.") : null);
    fill(this.box,
      el(
        "div",
        { class: "cards" },
        card("Snapshot version", s.version),
        card("Applied", date(s.applied_at), "small"),
        card("Writer", s.writer ?? "none", "small"),
        card("Boot id", s.boot_id, "small"),
        card("Tenants", count(s.tenants)),
        card("Apps", count(s.apps)),
        card("Routers", count(s.routers)),
        card("Services", count(s.services)),
        card("Servers healthy", count(servers.healthy), "good"),
        card("Servers unhealthy", count(servers.unhealthy), servers.unhealthy ? "bad" : ""),
        card("Servers ejected", count(servers.ejected), servers.ejected ? "warn" : ""),
      ),
      el("h2", {}, "Entry points"),
      table(
        ["Name", "Protocol", "Address", "PROXY protocol", "Forwarded headers trusted from"],
        (overview.entry_points ?? []).map((point) => [
          point.name,
          point.protocol,
          point.address ?? "",
          point.proxy_protocol ? "yes" : "no",
          point.forwarded_headers,
        ]),
        "No entry points.",
      ),
      el("h2", {}, "Tenants"),
      table(
        ["Tenant", "Weight", "Apps", "In flight", "Buffered"],
        (overview.tenants?.items ?? []).map((tenant) => [
          tenant.id,
          count(tenant.weight),
          count(tenant.apps),
          `${count(tenant.inflight)} of ${count(tenant.budget.max_inflight)}`,
          `${bytes(tenant.buffer_bytes)} of ${bytes(tenant.budget.max_buffer_bytes)}`,
        ]),
        "No tenants in this snapshot.",
      ),
      note(overview.tenants),
      s.metrics_addr ? el("p", { class: "muted" }, "Metrics are served on ", code(s.metrics_addr), ".") : null,
    );
  },
};

function matchesSearch(app, needle) {
  if (!needle) return true;
  const haystack = [
    app.id,
    app.tenant,
    ...(app.hosts ?? []),
    ...list(app.routers).map((router) => router.name),
    ...list(app.services).map((service) => service.name),
  ];
  return haystack.some((text) => text.toLowerCase().includes(needle));
}

function appBody(app) {
  if (app.too_large) {
    return el(
      "div",
      { class: "body" },
      el("p", { class: "empty" }, `Too large to show in full: ${app.routers} routers, ${app.revisions} revisions, ${app.services} services, ${app.middlewares} middlewares. Ask the admin API for it alone.`),
    );
  }
  return el(
    "div",
    { class: "body" },
    definitions([
      ["Declared by", app.declared_by],
      ["TLS", `${app.tls.mode}, ${app.tls.challenge} challenge${app.tls.client_auth ? ", client certificates required" : ""}`],
      ["Domain fronting", app.allow_domain_fronting ? "allowed" : "refused"],
      ["Scale to zero", app.scale_to_zero ? code(compact(app.scale_to_zero)) : null],
      ["Canary", app.canary ? code(compact(app.canary)) : null],
      ["Hosts", (app.hosts ?? []).join(", ")],
      ["Recent", recent(app.recent)],
    ]),
    el("h3", {}, "Revisions"),
    table(
      ["Revision", "State", "Weight", "Effective weight", "In flight", "Recent"],
      app.revisions.map((revision) => [
        revision.id,
        tag(revision.state, revision.state === "serving" ? "good" : "muted"),
        count(revision.weight),
        count(revision.effective_weight),
        count(revision.inflight),
        recent(revision.recent),
      ]),
      "No revisions.",
    ),
    el("h3", {}, "Routers"),
    table(
      ["Router", "Entry points", "Priority", "Matcher", "Middleware chain", "Service"],
      app.routers.map((router) => [
        el("span", {}, router.name, el("div", { class: "muted" }, router.declared_by)),
        router.entry_points ? router.entry_points.join(", ") : "all HTTP",
        count(router.priority),
        code(compact(router.match)),
        router.chain.length ? router.chain.join(" > ") : "none",
        router.service,
      ]),
      "No routers.",
    ),
    el("h3", {}, "Middlewares"),
    table(
      ["Name", "Type", "Configuration"],
      app.middlewares.map((middleware) => [
        middleware.name,
        middleware.type,
        middleware.config === undefined ? "" : code(compact(middleware.config)),
      ]),
      "No middlewares.",
    ),
  );
}

const appsPage = {
  search: "",
  tenant: "",
  open: new Set(),
  tenantKey: null,
  mount(root) {
    this.searchBox = el("input", {
      type: "search",
      placeholder: "Search app, host, router or service",
      "aria-label": "Search apps",
      value: this.search,
      on: {
        input: (event) => {
          this.search = event.target.value.trim().toLowerCase();
          this.update();
        },
      },
    });
    this.tenantSelect = el("select", {
      "aria-label": "Filter by tenant",
      on: {
        change: (event) => {
          this.tenant = event.target.value;
          this.update();
        },
      },
    });
    this.tenantKey = null;
    this.list = el("div", {});
    root.append(el("div", { class: "controls" }, this.searchBox, this.tenantSelect), this.list);
  },
  update() {
    if (!overview) return;
    const tenants = [...new Set(appItems().map((app) => app.tenant))].sort();
    const key = tenants.join("\n");
    if (key !== this.tenantKey) {
      this.tenantKey = key;
      fill(this.tenantSelect,
        el("option", { value: "" }, "All tenants"),
        ...tenants.map((tenant) => el("option", { value: tenant, selected: tenant === this.tenant }, tenant)),
      );
      if (!tenants.includes(this.tenant)) this.tenant = "";
    }
    const shown = appItems().filter(
      (app) => (!this.tenant || app.tenant === this.tenant) && matchesSearch(app, this.search),
    );
    fill(this.list,
      el("p", { class: "muted" }, `${count(shown.length)} of ${count(overview.apps?.total ?? appItems().length)} apps`),
      ...shown.map((app) => {
        const details = el(
          "details",
          {
            class: "app",
            open: this.open.has(app.id),
            on: {
              toggle: (event) => {
                if (event.target.open) this.open.add(app.id);
                else this.open.delete(app.id);
              },
            },
          },
          el(
            "summary",
            {},
            el("span", { class: "app-id" }, app.id),
            el("span", { class: "pill" }, app.tenant),
            el("span", { class: "muted" }, (app.hosts ?? []).slice(0, 3).join(", ")),
            app.recent ? el("span", { class: "muted" }, recent(app.recent)) : null,
          ),
          this.open.has(app.id) ? appBody(app) : null,
        );
        // The body is built when the app is opened, so a big fleet stays cheap to render.
        details.addEventListener("toggle", () => {
          if (details.open && !details.querySelector(".body")) details.append(appBody(app));
        });
        return details;
      }),
    );
  },
};

function serviceRows(filterText, onlyProblems) {
  const rows = [];
  const needle = filterText.toLowerCase();
  for (const app of [...appItems()].sort((a, b) => a.id.localeCompare(b.id))) {
    for (const service of list(app.services)) {
      const servers = service.servers.length ? service.servers : [null];
      for (const server of servers) {
        if (onlyProblems && server && server.available && server.healthy !== false) continue;
        if (onlyProblems && !server) continue;
        const text = [app.id, app.tenant, service.name, server?.url ?? ""].join(" ").toLowerCase();
        if (needle && !text.includes(needle)) continue;
        rows.push([
          app.id,
          service.name,
          service.revision ?? "all",
          service.algorithm ? `${service.type}, ${service.algorithm}` : service.type,
          server ? server.url : tag("no servers", "muted"),
          server ? serverState(server) : "",
          server ? count(server.active) : "",
          server ? count(server.weight) : "",
          service.health_check ? "active" : "",
        ]);
      }
    }
  }
  return rows;
}

const servicesPage = {
  filter: "",
  problems: false,
  mount(root) {
    this.box = el("div", {});
    const input = el("input", {
      type: "search",
      placeholder: "Search app, service or server",
      "aria-label": "Search services",
      value: this.filter,
      on: {
        input: (event) => {
          this.filter = event.target.value.trim();
          this.update();
        },
      },
    });
    const only = el("input", {
      type: "checkbox",
      checked: this.problems,
      on: {
        change: (event) => {
          this.problems = event.target.checked;
          this.update();
        },
      },
    });
    root.append(el("div", { class: "controls" }, input, el("label", {}, only, " only servers that are not available")), this.box);
  },
  update() {
    if (!overview) return;
    fill(this.box,
      table(
        ["App", "Service", "Revision", "Type", "Server", "State", "In flight", "Weight", "Health check"],
        serviceRows(this.filter, this.problems),
        "No servers match.",
      ),
    );
  },
};

const certificatesPage = {
  mount(root) {
    this.box = el("div", {});
    root.append(this.box);
  },
  update() {
    if (!overview) return;
    const certs = [...(overview.certificates?.items ?? [])].sort(
      (a, b) => (a.not_after ?? Infinity) - (b.not_after ?? Infinity),
    );
    fill(this.box,
      el("h2", {}, "Certificates, soonest expiry first"),
      table(
        ["Hosts", "Issuer", "Expires", "Days left", "Source"],
        certs.map((cert) => {
          const left = cert.not_after === undefined ? null : daysLeft(cert.not_after);
          const cls = left === null ? "muted" : left < 0 ? "bad" : left < 14 ? "warn" : "good";
          return [
            el("span", {}, cert.hosts.join(", "), cert.default ? tag(" (default)", "muted") : null),
            cert.issuer ?? "",
            cert.not_after === undefined ? "" : date(cert.not_after),
            left === null ? "" : tag(String(left), cls),
            cert.source,
          ];
        }),
        "No certificates in this snapshot.",
      ),
      overview.certificates?.truncated ? el("p", { class: "empty" }, "The list is cut short; the node has more than this.") : null,
    );
  },
};

function explanationNodes(answer) {
  return [
    el("h2", {}, `Matched router ${answer.matched.router}`),
    definitions([
      ["App", answer.app],
      ["Tenant", answer.tenant],
      ["Declared by", answer.declared_by],
      ["Request", `${answer.method} ${answer.host}${answer.path}`],
      ["Entry point", answer.entry_point],
      ["Reachable on", answer.reachable_on.join(", ")],
      ["Host pattern", answer.matched.pattern ? `${answer.matched.pattern} (${answer.matched.kind})` : answer.matched.kind],
      ["Priority", count(answer.matched.priority)],
      ["Service", answer.service],
      ["Snapshot version", answer.version],
      ["Canary", answer.canary ? code(compact(answer.canary)) : null],
      ["Entry point redirect", answer.entry_redirect ? code(compact(answer.entry_redirect)) : null],
    ]),
    el("h3", {}, "Routers that match, best first"),
    el("ol", {}, answer.considered.map((name) => el("li", {}, name))),
    answer.near_misses?.length
      ? [
          el("h3", {}, "Near misses"),
          table(
            ["App", "Router", "Failed on"],
            answer.near_misses.map((miss) => [miss.app, miss.router, miss.failed.join("; ")]),
            "",
          ),
        ]
      : null,
    el("h3", {}, "Revisions"),
    table(
      ["Revision", "State", "Weight", "Effective weight", "Servers"],
      answer.revisions.map((revision) => [
        revision.id,
        revision.state,
        count(revision.weight),
        count(revision.effective_weight),
        revision.servers.length
          ? revision.servers.map((server) => el("div", {}, server.url, " ", serverState(server)))
          : tag("none", "muted"),
      ]),
      "No revisions.",
    ),
    el("h3", {}, "Pipeline, in order"),
    el(
      "ol",
      { class: "pipeline" },
      answer.pipeline.map((stage) => {
        const { stage: name, ...rest } = stage;
        return el("li", {}, el("strong", {}, name), Object.keys(rest).length ? [" ", code(compact(rest))] : null);
      }),
    ),
  ];
}

function missNodes(miss) {
  return [
    el("h2", {}, "No router matches"),
    definitions([
      ["Nearest wildcard", miss.nearest_wildcard ? code(miss.nearest_wildcard) : "none"],
      ["Would match on", miss.routed_on?.length ? miss.routed_on.join(", ") : null],
    ]),
    miss.near_misses?.length
      ? [
          el("h3", {}, "Near misses"),
          table(
            ["App", "Router", "Failed on"],
            miss.near_misses.map((near) => [near.app, near.router, near.failed.join("; ")]),
            "",
          ),
        ]
      : null,
  ];
}

const explainPage = {
  result: null,
  mount(root) {
    const url = el("input", { type: "text", name: "url", required: true, placeholder: "absolute URL, scheme://host/path?query", autocomplete: "off", spellcheck: "false" });
    const method = el("select", { name: "method" }, ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].map((m) => el("option", { value: m }, m)));
    const entry = el("input", { type: "text", name: "entry_point", placeholder: "any", autocomplete: "off" });
    const client = el("input", { type: "text", name: "client_ip", placeholder: "none", autocomplete: "off" });
    this.out = el("div", {});
    const form = el(
      "form",
      { class: "explain" },
      el("label", { class: "wide" }, "URL", url),
      el("label", {}, "Method", method),
      el("label", {}, "Entry point", entry),
      el("label", {}, "Client address", client),
      el("button", { type: "submit" }, "Explain"),
    );
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const body = { url: url.value.trim(), method: method.value };
      if (entry.value.trim()) body.entry_point = entry.value.trim();
      if (client.value.trim()) body.client_ip = client.value.trim();
      fill(this.out, el("p", { class: "muted" }, "Asking"));
      try {
        const answer = await getJson("/api/explain", {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify(body),
        });
        this.show(answer);
      } catch (error) {
        this.show({ status: 0, body: { error: error.message } });
      }
    });
    root.append(el("p", { class: "muted" }, "Ask the live routing table where a request goes. Nothing is sent to an app."), form, this.out);
    if (this.result) this.show(this.result);
  },
  show(answer) {
    this.result = answer;
    if (answer.status === 200) fill(this.out, ...explanationNodes(answer.body));
    else if (answer.status === 404 && answer.body?.error === "not found") fill(this.out, ...missNodes(answer.body));
    else fill(this.out, el("p", { class: "error" }, `${answer.status || "failed"}: ${answer.body?.error ?? "unexpected answer"}`));
  },
  update() {},
};

const PAGES = {
  summary: summaryPage,
  apps: appsPage,
  services: servicesPage,
  certificates: certificatesPage,
  explain: explainPage,
};

// ---------------------------------------------------------------- shell

function route() {
  const name = location.hash.slice(1);
  const page = PAGE_ORDER.includes(name) ? name : "summary";
  for (const link of tabs.querySelectorAll("a")) {
    if (link.dataset.page === page) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  current = PAGES[page];
  view.replaceChildren();
  current.mount(view);
  current.update();
}

pauseButton.addEventListener("click", () => {
  paused = !paused;
  pauseButton.textContent = paused ? "Resume" : "Pause";
  if (paused) {
    statusLine.className = "warn";
    statusLine.textContent = "paused";
  } else {
    refresh();
  }
});

window.addEventListener("hashchange", route);
setInterval(() => {
  if (!paused) refresh();
}, REFRESH_MS);
route();
refresh();
