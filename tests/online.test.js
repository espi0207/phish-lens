import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { analyze, analyzeLink } from "../js/analyze.js";
import { parseMessage } from "../js/mail.js";
import { checkAuthDns, dnsQuery, enrich, registrationDate, resolveShortener } from "../js/online.js";

const NOW = new Date("2026-10-07T12:00:00Z");
const DAY = 24 * 3600 * 1000;

function json(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body, url: "" };
}

/** Un fetch falso: cada ruta es [parte de la URL, respuesta]; la primera que coincide gana. */
function fakeFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method ?? "GET" });
    for (const [part, reply] of routes) {
      if (String(url).includes(part)) return typeof reply === "function" ? reply(url, init) : reply;
    }
    throw new Error(`sin ruta para ${url}`);
  };
  fn.calls = calls;
  return fn;
}

const txt = (...records) => json({ Status: 0, Answer: records.map((data) => ({ type: 16, data })) });
const a = (...ips) => json({ Status: 0, Answer: ips.map((data) => ({ type: 1, data })) });
const nxdomain = () => json({ Status: 3 });
const rdap = (daysAgo) => json({ events: [{ eventAction: "registration", eventDate: new Date(NOW - daysAgo * DAY).toISOString() }] });

const phishing = () => analyze(parseMessage(readFileSync(new URL("../samples/correos-paquete.eml", import.meta.url))), NOW);
const titles = (result) => result.findings.map((f) => `${f.severity}: ${f.title}`);

test("TXT en trozos entrecomillados se pega", async () => {
  const fetchFn = fakeFetch([["_dmarc", txt('"v=DMARC1;" "p=reject;" "pct=100;"')]]);
  const r = await dnsQuery("_dmarc.correos.es", "TXT", fetchFn);
  assert.deepEqual(r.answers, ['"v=DMARC1;" "p=reject;" "pct=100;"']);
});

test("RDAP: fecha de registro, y 404 es sin datos", async () => {
  assert.equal((await registrationDate("a.example", fakeFetch([["rdap.org", rdap(3)]]))).getTime(), NOW - 3 * DAY);
  assert.equal(await registrationDate("a.example", fakeFetch([["rdap.org", json({}, 404)]])), null);
  await assert.rejects(registrationDate("a.example", fakeFetch([["rdap.org", json({}, 500)]])));
});

test("SPF y DMARC: ausentes, contradicen la cabecera, +all y p=none", async () => {
  const none = { spf: null, dmarc: null };
  const empty = fakeFetch([["_dmarc", txt()], ["", txt()]]);
  const t = (await checkAuthDns("x.example", none, empty)).map((f) => f.title);
  assert.deepEqual(t, ["x.example no publica SPF", "x.example no publica DMARC"]);

  const lying = (await checkAuthDns("x.example", { spf: "pass", dmarc: "pass" }, empty)).map((f) => `${f.severity}: ${f.title}`);
  assert.deepEqual(lying, [
    "media: La cabecera dice SPF correcto, pero el dominio no publica SPF",
    "media: La cabecera dice DMARC correcto, pero el dominio no publica DMARC",
  ]);

  const weak = fakeFetch([["_dmarc", txt('"v=DMARC1; p=none"')], ["", txt('"v=spf1 +all"')]]);
  assert.deepEqual((await checkAuthDns("x.example", none, weak)).map((f) => f.severity), ["alta", "baja"]);

  const strict = fakeFetch([["_dmarc", txt('"v=DMARC1;" "p=reject;"')], ["", txt('"v=spf1 include:_spf.google.com -all"')]]);
  assert.deepEqual(await checkAuthDns("x.example", none, strict), []);
});

test("el dominio del remitente no existe", async () => {
  const [f] = await checkAuthDns("nada.example", { spf: null, dmarc: null }, fakeFetch([["", nxdomain()]]));
  assert.equal(f.severity, "media");
  assert.match(f.title, /no existe/);
});

test("enrich: dominio recién registrado y en lista negra empeoran el veredicto", async () => {
  const fetchFn = fakeFetch([
    ["rdap.org", rdap(3)],
    ["security.cloudflare-dns.com", a("0.0.0.0")],
    ["", txt()],
  ]);
  const base = phishing();
  const r = await enrich(base, { fetch: fetchFn, now: NOW, cache: new Map() });
  assert.ok(titles(r).includes("alta: Dominio registrado hace 3 días: correos-envios.example"));
  assert.ok(titles(r).includes("alta: Dominio en una lista negra: correos-envios.example"));
  assert.ok(r.score >= base.score);
  assert.equal(r.verdict.level, "peligro");
  assert.notEqual(r, base);
  assert.equal(base.findings.length, phishing().findings.length, "no modifica el resultado original");
});

test("enrich: si la red falla sale 'no se pudo comprobar', nunca bueno ni malo", async () => {
  const fetchFn = fakeFetch([["", () => { throw new Error("sin red"); }]]);
  const base = phishing();
  const r = await enrich(base, { fetch: fetchFn, now: NOW, cache: new Map() });
  const info = r.findings.filter((f) => f.severity === "info" && /No se pudo comprobar/.test(f.title));
  assert.equal(info.length, 3);
  assert.equal(r.score, base.score);
});

test("enrich: dominios de marcas, correo gratuito e IPs no se consultan", async () => {
  const fetchFn = fakeFetch([["", () => { throw new Error("no debería consultarse"); }]]);
  const r = await enrich(
    analyze(parseMessage("From: PayPal <x@paypal.com>\nContent-Type: text/html\n\n<a href=\"http://203.0.113.5/x\">a</a><a href=\"https://www.google.com\">b</a>"), NOW),
    { fetch: fetchFn, now: NOW, cache: new Map() },
  );
  assert.deepEqual(r.online.domains, []);
  assert.equal(fetchFn.calls.length, 0);
});

test("acortador: se sigue con HEAD y el destino se analiza", async () => {
  const fetchFn = fakeFetch([
    ["bit.ly", (url, init) => ({ ok: true, status: 200, url: "https://paypa1.example/login", method: init.method })],
    ["rdap.org", json({}, 404)],
    ["", txt()],
  ]);
  assert.equal(await resolveShortener("https://bit.ly/x", fetchFn), "https://paypa1.example/login");
  assert.equal(fetchFn.calls[0].method, "HEAD");

  const link = analyzeLink("https://bit.ly/3xYz7Ab");
  const r = await enrich(link, { fetch: fetchFn, now: NOW, shorteners: true, cache: new Map() });
  const f = r.findings.find((x) => /lleva a/.test(x.title));
  assert.equal(f.severity, "alta");
  assert.match(f.title, /hxxps:\/\/paypa1\[\.\]example/);
  assert.equal(r.verdict.level, "peligro");
});

test("acortador: si HEAD no va se prueba con GET", async () => {
  const body = { cancel() { body.cancelled = true; } };
  const fetchFn = fakeFetch([["bit.ly", (url, init) => (init.method === "HEAD" ? { ok: false, status: 405, url } : { ok: true, status: 200, url: "https://destino.example/", body })]]);
  assert.equal(await resolveShortener("https://bit.ly/x", fetchFn), "https://destino.example/");
  assert.ok(body.cancelled);
});

test("acortador: sin permiso (shorteners:false) no se contacta con el acortador", async () => {
  const fetchFn = fakeFetch([["bit.ly", () => { throw new Error("no debería"); }], ["rdap.org", json({}, 404)], ["", txt()]]);
  await enrich(phishing(), { fetch: fetchFn, now: NOW, cache: new Map() });
  assert.ok(!fetchFn.calls.some((c) => c.url.includes("bit.ly")));
});

test("la red solo sale de js/online.js: el resto de ficheros no hace peticiones", () => {
  for (const dir of ["../js/", "../extension/"]) {
    const base = new URL(dir, import.meta.url);
    for (const name of readdirSync(base).filter((f) => f.endsWith(".js"))) {
      const code = readFileSync(new URL(name, base), "utf8");
      const calls = [...code.matchAll(/\bfetch\(([^)]*)\)/g)].map((m) => m[1]);
      if (name === "online.js") continue;
      // app.js solo carga los ejemplos que van con la propia página.
      for (const arg of calls) assert.match(arg, /^`samples\//, `${name}: fetch(${arg})`);
      assert.ok(!/XMLHttpRequest|WebSocket|sendBeacon|EventSource/.test(code), name);
    }
  }
});

test("enrich: un TLD sin RDAP (.es) se dice tal cual, y 'no existe' no sale dos veces", async () => {
  const fetchFn = fakeFetch([["rdap.org", json({}, 404)], ["security.cloudflare-dns.com", nxdomain()], ["", nxdomain()]]);
  const r = await enrich(phishing(), { fetch: fetchFn, now: NOW, cache: new Map() });
  assert.ok(r.findings.some((f) => /su registro no publica RDAP/.test(f.title)));
  assert.equal(r.findings.filter((f) => /no existe: correos-envios.example/.test(f.title)).length, 1);
});

test("la lista negra se consulta por el host completo, no solo por el dominio registrable", async () => {
  const fetchFn = fakeFetch([
    ["name=malware.testcategory.com", a("0.0.0.0")],
    ["rdap.org", rdap(2000)],
    ["", txt()],
  ]);
  const r = await enrich(analyzeLink("https://malware.testcategory.com/login"), { fetch: fetchFn, now: NOW, cache: new Map() });
  assert.ok(titles(r).includes("alta: Dominio en una lista negra: malware.testcategory.com"));
  assert.equal(r.verdict.level, "peligro");
  assert.deepEqual(r.online.domains, ["testcategory.com"]);
});

// Fallos encontrados en la revisión con Codex.

const authMail = (auth) =>
  analyze(parseMessage([
    "From: Tienda <billing@shop.example>",
    "To: ana@empresa.example",
    `Authentication-Results: mx.empresa.example; ${auth}`,
    "Subject: Factura",
    "",
    "Hola",
  ].join("\n")), NOW);

test("un DNS que falla (SERVFAIL) no se toma como «no publica SPF»", async () => {
  const fetchFn = fakeFetch([["dns", json({ Status: 2 })], ["rdap", json({}, 404)]]);
  const r = await enrich(authMail("spf=pass smtp.mailfrom=shop.example; dmarc=pass header.from=shop.example"), { fetch: fetchFn, now: NOW, cache: new Map() });
  assert.ok(!titles(r).some((t) => /no publica (SPF|DMARC)/.test(t)));
  assert.ok(titles(r).includes("info: No se pudo comprobar SPF y DMARC"));
});

test("el SPF se mira en el dominio del sobre (smtp.mailfrom), no en el del From", async () => {
  const fetchFn = fakeFetch([
    ["name=mailer.example&type=TXT", txt('"v=spf1 include:_spf.mailer.example -all"')],
    ["name=_dmarc", txt('"v=DMARC1; p=reject"')],
    ["name=shop.example&type=TXT", txt()],
  ]);
  const auth = { spf: "pass", dmarc: "pass", domains: { spf: "mailer.example", dmarc: "shop.example" } };
  const findings = await checkAuthDns("shop.example", auth, fetchFn);
  assert.deepEqual(findings, []);
});

test("lo que se guarda en caché no depende de lo que diga cada correo", async () => {
  const cache = new Map();
  const fetchFn = fakeFetch([["dns", txt()], ["rdap", json({}, 404)]]);
  await enrich(authMail("spf=none; dmarc=none"), { fetch: fetchFn, now: NOW, cache });
  const second = await enrich(authMail("spf=pass smtp.mailfrom=shop.example; dmarc=pass header.from=shop.example"), { fetch: fetchFn, now: NOW, cache });
  assert.ok(titles(second).includes("media: La cabecera dice SPF correcto, pero el dominio no publica SPF"));
});

test("muchos subdominios de un mismo sitio no disparan cien consultas", async () => {
  const links = Array.from({ length: 100 }, (_, i) => `<a href="https://s${i}.trampa.example/">x</a>`).join("");
  const result = analyze(parseMessage(["From: a@remite.example", "To: b@empresa.example", "Content-Type: text/html", "", links].join("\n")), NOW);
  const fetchFn = fakeFetch([["dns", txt()], ["rdap", json({}, 404)]]);
  await enrich(result, { fetch: fetchFn, now: NOW, cache: new Map() });
  assert.ok(fetchFn.calls.length <= 30, `${fetchFn.calls.length} consultas`);
});
