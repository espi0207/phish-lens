// La parte de la página: leer el correo, analizarlo y pintar el resultado.
//
// Todo lo que viene del correo se mete como texto (textContent), nunca como HTML: el HTML de
// un correo de phishing no debe interpretarse aquí bajo ningún concepto.

import { analyze, analyzeLink } from "./analyze.js";
import { parseMessage } from "./mail.js";
import { enrich } from "./online.js";
import { canFollowShorteners, getSettings, hasShortenerPermission, requestShortenerPermission, saveSettings } from "./settings.js";

const MAX_SIZE = 15 * 1024 * 1024;
const SEVERITY_LABEL = { alta: "Alta", media: "Media", baja: "Baja", info: "Info", ok: "Bien" };
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== "") {
      node.append(child instanceof Node ? child : String(child));
    }
  }
  return node;
}

function showError(text) {
  $("error").textContent = text;
  $("error").hidden = !text;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatDate(date) {
  return date.toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "medium" });
}

function renderVerdict(result) {
  const card = $("verdict");
  card.className = `card verdict ${result.verdict.level}`;
  $("verdict-label").textContent = result.verdict.text;
  $("verdict-subject").textContent = result.subject ? `«${result.subject}»` : "(sin asunto)";
  $("gauge-fill").style.width = `${result.score}%`;
  $("verdict-score").textContent =
    `Puntuación de riesgo: ${result.score} de 100` +
    (result.verdict.level === "limpio" ? ". Que no salga nada no garantiza que sea seguro." : "");
}

function renderFindings(findings) {
  $("findings").replaceChildren(
    ...findings.map((f) =>
      el(
        "li",
        { class: `finding ${f.severity}` },
        el("span", { class: `pill ${f.severity}` }, SEVERITY_LABEL[f.severity]),
        el("div", {}, el("strong", {}, f.title), el("p", {}, f.detail)),
      ),
    ),
  );
  if (!findings.length) $("findings").append(el("li", { class: "muted" }, "Nada que destacar."));
}

function renderSender(result) {
  const rows = [
    ["Nombre visible", result.from.name || "(ninguno)"],
    ["Dirección", result.from.address || "(vacía)"],
    ["Responder a", result.replyTo.address],
    ["Return-Path", result.returnPath.address],
    ["Para", result.to.map((a) => a.address).join(", ")],
    ["Fecha", result.date ? formatDate(result.date) : ""],
  ].filter(([, value]) => value);
  $("sender").replaceChildren(...rows.flatMap(([key, value]) => [el("dt", {}, key), el("dd", {}, value)]));

  const badge = (name, value) => {
    const state = value === "pass" ? "ok" : value === "fail" ? "alta" : value ? "media" : "info";
    return el("span", { class: `badge ${state}` }, `${name}: ${value ?? "sin datos"}`);
  };
  $("auth").replaceChildren(badge("SPF", result.auth.spf), badge("DKIM", result.auth.dkim), badge("DMARC", result.auth.dmarc));
}

function renderHops(hops) {
  if (!hops.length) {
    $("hops").replaceChildren(el("li", { class: "muted" }, "El correo no trae cabeceras Received."));
    return;
  }
  $("hops").replaceChildren(
    ...hops.map((hop, i) => {
      const previous = hops[i - 1]?.date;
      const delay = hop.date && previous ? Math.round((hop.date - previous) / 1000) : null;
      return el(
        "li",
        {},
        el("strong", {}, hop.from || "(desconocido)"),
        hop.ip ? el("span", { class: "mono" }, ` [${hop.ip}]`) : null,
        el(
          "span",
          { class: "muted small block" },
          hop.by ? `recibido por ${hop.by}` : "",
          hop.date ? ` · ${formatDate(hop.date)}` : "",
          delay !== null ? ` · ${delay < 0 ? "¡antes que el anterior!" : `+${delay} s`}` : "",
        ),
      );
    }),
  );
}

function renderLinks(links) {
  if (!links.length) {
    $("links").replaceChildren(el("p", { class: "muted" }, "No tiene enlaces."));
    return;
  }
  const rows = links.map((link) =>
    el(
      "tr",
      {},
      el("td", {}, link.text || el("span", { class: "muted" }, "(la propia URL)")),
      el("td", { class: "mono break" }, link.shown),
      el(
        "td",
        {},
        link.problems.length
          ? link.problems.map((p) => el("span", { class: "pill alta" }, p))
          : el("span", { class: "pill ok" }, "sin problemas"),
      ),
    ),
  );
  $("links").replaceChildren(
    el(
      "div",
      { class: "table-wrap" },
      el(
        "table",
        {},
        el("thead", {}, el("tr", {}, el("th", {}, "Texto que se ve"), el("th", {}, "Adónde lleva de verdad"), el("th", {}, ""))),
        el("tbody", {}, rows),
      ),
    ),
  );
}

function renderAttachments(attachments) {
  if (!attachments.length) {
    $("attachments").replaceChildren(el("p", { class: "muted" }, "No tiene adjuntos."));
    return;
  }
  $("attachments").replaceChildren(
    el(
      "ul",
      { class: "attachments" },
      attachments.map((a) =>
        el(
          "li",
          {},
          el("span", { class: "mono" }, a.name),
          el("span", { class: "muted small" }, ` ${a.contentType}, ${formatSize(a.size)} `),
          a.problems.map((p) => el("span", { class: `pill ${p === "comprimido" ? "baja" : "alta"}` }, p)),
        ),
      ),
    ),
  );
}

function show(input) {
  showError("");
  let result;
  try {
    const message = parseMessage(input);
    if (!message.headers.list.length) {
      showError("Eso no parece un correo: no encuentro ninguna cabecera (From, Subject, Received...).");
      return;
    }
    result = analyze(message);
  } catch (err) {
    showError(`No he podido leer el correo: ${err.message}`);
    return;
  }
  renderVerdict(result);
  renderFindings(result.findings);
  renderSender(result);
  renderHops(result.hops);
  renderLinks(result.links);
  renderAttachments(result.attachments);
  showResult(true);
  addOnline(result, (r) => {
    renderVerdict(r);
    renderFindings(r.findings);
  });
}

/** Un enlace suelto: el mismo resultado, sin las partes que solo tienen sentido en un correo. */
function showLink(href) {
  showError("");
  const result = analyzeLink(href);
  if (!result) {
    showError("Eso no parece un enlace. Tiene que empezar por http:// o https://");
    return;
  }
  renderVerdict({ ...result, subject: null });
  $("verdict-subject").textContent = result.link.shown;
  renderFindings(result.findings);
  renderLinks([result.link]);
  showResult(false);
  addOnline(result, (r) => {
    renderVerdict({ ...r, subject: null });
    $("verdict-subject").textContent = r.link.shown;
    renderFindings(r.findings);
  });
}

let onlineTicket = 0;

function setStatus(text) {
  $("online-status").textContent = text;
  $("online-status").hidden = !text;
}

/** En modo completo, añade lo que solo se sabe con red y vuelve a pintar el veredicto. */
async function addOnline(result, rerender) {
  const ticket = ++onlineTicket;
  const settings = await getSettings();
  if (settings.mode !== "completo") {
    setStatus("");
    return;
  }
  setStatus("Consultando dominios...");
  try {
    const shorteners = settings.shorteners && (await hasShortenerPermission());
    const enriched = await enrich(result, { shorteners });
    if (ticket !== onlineTicket) return;
    rerender(enriched);
    const { hosts, resolved } = enriched.online;
    const followed = resolved.length ? ` Acortadores seguidos: ${resolved.length}.` : "";
    setStatus(
      hosts.length
        ? `Consultados (RDAP y DNS de Cloudflare): ${hosts.join(", ")}.${followed}`
        : `Modo completo: no había dominios que consultar.${followed}`,
    );
  } catch {
    if (ticket === onlineTicket) setStatus("No he podido hacer las consultas de red. Lo de arriba es solo el análisis local.");
  }
}

function showResult(isMail) {
  for (const section of document.querySelectorAll(".mail-only")) section.hidden = !isMail;
  $("input").hidden = true;
  $("result").hidden = false;
  window.scrollTo({ top: 0 });
}

async function readFile(file) {
  if (file.size > MAX_SIZE) {
    showError(`El archivo ocupa ${formatSize(file.size)}; como mucho ${formatSize(MAX_SIZE)}.`);
    return;
  }
  show(new Uint8Array(await file.arrayBuffer()));
}

async function loadSample(name) {
  try {
    const response = await fetch(`samples/${name}.eml`);
    if (!response.ok) throw new Error(response.statusText);
    show(new Uint8Array(await response.arrayBuffer()));
    history.replaceState(null, "", `#ejemplo=${name}`);
  } catch {
    showError("No he podido cargar el ejemplo. Si has abierto el archivo directamente, sírvelo con un servidor (mira el README).");
  }
}

function reset() {
  onlineTicket++;
  setStatus("");
  $("result").hidden = true;
  $("input").hidden = false;
  $("raw").value = "";
  $("file").value = "";
  $("link").value = "";
  history.replaceState(null, "", location.pathname);
}

$("analyze").addEventListener("click", () => {
  const text = $("raw").value;
  if (!text.trim()) {
    showError("Pega el código fuente del correo o arrastra el archivo .eml.");
    return;
  }
  show(text);
});
$("file").addEventListener("change", (e) => e.target.files[0] && readFile(e.target.files[0]));
$("link-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const href = $("link").value.trim();
  if (!href) return;
  // Mucha gente pega el enlace sin el https:// delante (así sale en los SMS).
  showLink(/^[a-z][a-z0-9+.-]*:/i.test(href) ? href : `https://${href}`);
  history.replaceState(null, "", `#enlace=${encodeURIComponent($("link").value.trim())}`);
});
$("again").addEventListener("click", reset);

const PRIVACY = {
  privado: "Se analiza en tu navegador. El correo no se envía a ningún sitio.",
  completo: "El correo no se envía a ningún sitio: solo se consultan sus dominios (rdap.org y Cloudflare).",
};

async function initSettings() {
  const settings = await getSettings();
  const showMode = (mode) => {
    $("privacy").textContent = PRIVACY[mode];
    $("shorteners-row").hidden = mode !== "completo" || !canFollowShorteners();
  };
  for (const radio of document.querySelectorAll('input[name="mode"]')) {
    radio.checked = radio.value === settings.mode;
    radio.addEventListener("change", () => {
      showMode(radio.value);
      saveSettings({ mode: radio.value });
    });
  }
  $("shorteners").checked = settings.shorteners && (await hasShortenerPermission());
  $("shorteners").addEventListener("change", async (e) => {
    // El permiso se pide en el mismo clic: el navegador no lo admite de otra forma.
    const granted = e.target.checked ? await requestShortenerPermission() : false;
    e.target.checked = granted;
    saveSettings({ shorteners: granted });
  });
  showMode(settings.mode);
}
initSettings();
for (const button of document.querySelectorAll("[data-sample]")) {
  button.addEventListener("click", () => loadSample(button.dataset.sample));
}

const drop = $("drop");
for (const type of ["dragenter", "dragover"]) {
  drop.addEventListener(type, (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
}
for (const type of ["dragleave", "drop"]) drop.addEventListener(type, () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  const file = e.dataTransfer.files[0];
  if (file) readFile(file);
});

// Instalada en Chrome o Edge en el ordenador, un .eml abierto con "Abrir con > phish-lens"
// llega por aquí (lo declara file_handlers en el manifiesto).
if ("launchQueue" in window) {
  window.launchQueue.setConsumer(async ({ files }) => {
    if (files?.length) readFile(await files[0].getFile());
  });
}

// Chrome y Edge avisan cuando la página se puede instalar como una app: se ofrece con un botón.
let installPrompt = null;
window.addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault();
  installPrompt = event;
  $("install").hidden = false;
});
$("install").addEventListener("click", () => {
  $("install").hidden = true;
  installPrompt?.prompt();
  installPrompt = null;
});

// Para que funcione sin conexión y se pueda instalar.
if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost")) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}

// Lo que llega en la dirección: #ejemplo=fraude-ceo abre un ejemplo, #enlace=... comprueba
// un enlace (así lo abre el clic derecho de la extensión) y #correo=... es un correo que la
// extensión ha dejado guardado al pulsar "Ver el análisis completo" en Gmail.
const params = new URLSearchParams(location.hash.slice(1));
if (params.has("enlace")) {
  $("link").value = params.get("enlace");
  showLink(params.get("enlace"));
} else if (params.has("correo") && globalThis.chrome?.storage?.session) {
  const key = params.get("correo");
  chrome.storage.session.get(key).then((saved) => {
    if (saved[key]) show(saved[key]);
    else showError("Ese correo ya no está guardado: vuelve a abrirlo desde Gmail.");
  });
}

// #ejemplo=fraude-ceo abre directamente un ejemplo (útil para enseñárselo a alguien).
const sample = new URLSearchParams(location.hash.slice(1)).get("ejemplo");
if (sample && /^[a-z0-9-]+$/.test(sample)) loadSample(sample);
