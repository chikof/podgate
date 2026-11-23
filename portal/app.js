// podgate developer portal: a read-only view of GET /api/catalog and the OpenAPI documents behind
// it. No dependencies. Every string that came from the API was written by a tenant, so it is
// inserted as a text node, never parsed as HTML, and no style or handler is set as an attribute:
// the page runs under a CSP with no 'unsafe-inline'.

const MAX_PAGES = 20;
const METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

const view = document.getElementById("view");
const statusLine = document.getElementById("status");
const form = document.getElementById("search");
const box = document.getElementById("q");

// ---------------------------------------------------------------- building blocks

/** Builds an element. Children are strings (text nodes) or nodes; attributes are plain values. */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function fill(...nodes) {
  view.replaceChildren(...nodes.flat(Infinity).filter((node) => node !== null && node !== undefined && node !== false));
}

function say(text) {
  statusLine.textContent = text;
}

/** The address of one entry's page. */
function pageOf(entry) {
  return "#api/" + encodeURIComponent(entry.id) + "/" + encodeURIComponent(entry.version);
}

/** The address of one entry's document. */
function documentOf(entry) {
  return (
    "/api/catalog/" +
    encodeURIComponent(entry.tenant) +
    "/" +
    encodeURIComponent(entry.id) +
    "/" +
    encodeURIComponent(entry.version) +
    "/openapi"
  );
}

class Refused extends Error {}

async function getJson(path) {
  const response = await fetch(path, { headers: { accept: "application/json" }, credentials: "same-origin" });
  if (response.status === 401) {
    throw new Refused("Your login does not name a tenant. Sign in through your organisation's login, then reload.");
  }
  if (!response.ok) throw new Refused("The portal could not answer (" + response.status + ").");
  return response.json();
}

function lifecycle(entry) {
  const text = entry.lifecycle === "deprecated" && entry.sunset ? "deprecated, ends " + entry.sunset : entry.lifecycle;
  return el("span", { class: entry.lifecycle === "deprecated" ? "badge deprecated" : "badge" }, text);
}

function describe(entry) {
  if (!entry.description) return null;
  return el("p", {}, entry.description + (entry.description_cut ? "\u2026" : ""));
}

function successor(entry) {
  if (!entry.successor) return null;
  return el(
    "p",
    {},
    "Replaced by ",
    el("a", { href: pageOf(entry.successor) }, entry.successor.id + " " + entry.successor.version),
    ".",
  );
}

function hosts(entry) {
  if (!entry.hosts || entry.hosts.length === 0) return null;
  const more = entry.hosts_more ? " and " + entry.hosts_more + " more" : "";
  return el("p", { class: "muted" }, "Served at ", entry.hosts.map((host, at) => [at ? ", " : "", el("code", {}, host)]), more);
}

// ---------------------------------------------------------------- the list

async function showList(search) {
  say("loading");
  const query = search ? "?q=" + encodeURIComponent(search) : "";
  const page = await getJson("/api/catalog" + query);
  const cards = page.items.map((entry) =>
    el(
      "div",
      { class: "card" },
      el("h2", {}, el("a", { href: pageOf(entry) }, entry.title || entry.id), el("span", { class: "badge" }, entry.version), lifecycle(entry)),
      describe(entry),
      hosts(entry),
      successor(entry),
    ),
  );
  fill(
    el("p", { class: "muted" }, page.total + (page.total === 1 ? " API" : " APIs")),
    cards.length ? cards : el("p", { class: "empty" }, search ? "No API matches." : "Your tenant has published no API yet."),
    page.truncated ? el("p", { class: "muted" }, "More APIs match. Narrow the search.") : null,
  );
  say("");
}

// ---------------------------------------------------------------- one API

/** Finds one entry by asking for its id and following `next`. */
async function findEntry(id, version) {
  let after = "";
  for (let pages = 0; pages < MAX_PAGES; pages += 1) {
    const page = await getJson("/api/catalog?limit=100&q=" + encodeURIComponent(id) + after);
    const found = page.items.find((entry) => entry.id === id && entry.version === version);
    if (found) return found;
    if (!page.next) return null;
    after = "&after=" + encodeURIComponent(page.next);
  }
  return null;
}

function operations(doc) {
  const rows = [];
  for (const [path, item] of Object.entries(doc.paths || {})) {
    for (const method of METHODS) {
      const operation = item[method];
      if (!operation || typeof operation !== "object") continue;
      const names = (operation.parameters || []).map((parameter) => parameter.name).filter((name) => typeof name === "string");
      rows.push(
        el(
          "div",
          { class: "op" },
          el("span", { class: "method" }, method),
          el("code", {}, path),
          operation.summary ? " " + operation.summary : null,
          operation.deprecated === true ? el("span", { class: "badge deprecated" }, "deprecated") : null,
          names.length ? el("div", { class: "muted" }, "Parameters: " + names.join(", ")) : null,
        ),
      );
    }
  }
  return rows;
}

function schemes(doc) {
  const found = (doc.components && doc.components.securitySchemes) || {};
  const names = Object.keys(found);
  if (names.length === 0) return null;
  return [
    el("h3", {}, "Authentication"),
    names.map((name) => el("p", {}, el("code", {}, name), " " + (found[name].type || ""), found[name].scheme ? " (" + found[name].scheme + ")" : "")),
  ];
}

async function showApi(id, version) {
  say("loading");
  const entry = await findEntry(id, version);
  if (!entry) {
    fill(el("p", { class: "empty" }, "No such API."), el("p", {}, el("a", { href: "#" }, "Back to the list")));
    say("");
    return;
  }
  const head = [
    el("h2", {}, entry.title || entry.id, el("span", { class: "badge" }, entry.version), lifecycle(entry)),
    describe(entry),
    hosts(entry),
    successor(entry),
  ];
  if (!entry.openapi) {
    fill(head, el("p", { class: "muted" }, "This API has no published description."));
    say("");
    return;
  }
  const doc = await getJson(documentOf(entry));
  fill(
    head,
    el("p", {}, el("a", { href: documentOf(entry) }, "OpenAPI description (JSON)"), " " + entry.openapi.dialect + ", " + entry.openapi.operations + " operations"),
    el("h3", {}, "Operations"),
    operations(doc),
    schemes(doc),
    el("p", {}, el("a", { href: "#" }, "Back to the list")),
  );
  say("");
}

// ---------------------------------------------------------------- routing

async function route() {
  const hash = location.hash.replace(/^#/, "");
  try {
    if (hash.startsWith("api/")) {
      const parts = hash.split("/");
      if (parts.length === 3) {
        await showApi(decodeURIComponent(parts[1]), decodeURIComponent(parts[2]));
        return;
      }
    }
    await showList(hash.startsWith("search/") ? decodeURIComponent(hash.slice(7)) : "");
  } catch (error) {
    fill(el("p", { class: "error" }, error instanceof Refused ? error.message : "The portal could not load this page."));
    say("");
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = box.value.trim();
  location.hash = text ? "search/" + encodeURIComponent(text) : "";
});
window.addEventListener("hashchange", route);
route();
