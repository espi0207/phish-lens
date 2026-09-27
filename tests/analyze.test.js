import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { analyze, analyzeLink, parseAuthResults, parseReceived } from "../js/analyze.js";
import { parseMessage } from "../js/mail.js";

const NOW = new Date("2026-09-27T12:00:00Z");
const sample = (name) => analyze(parseMessage(new Uint8Array(readFileSync(new URL(`../samples/${name}.eml`, import.meta.url)))), NOW);
const titles = (result) => result.findings.map((f) => `${f.severity}: ${f.title}`);

function mail(headers, body = "Hola") {
  return analyze(parseMessage(`${headers.join("\n")}\n\n${body}`), NOW);
}

test("ejemplo: paquete retenido de Correos", () => {
  const r = sample("correos-paquete");
  assert.equal(r.verdict.level, "peligro");
  const t = titles(r);
  assert.ok(t.includes("alta: DMARC ha fallado"));
  assert.ok(t.includes("alta: Se hace pasar por Correos"));
  assert.ok(t.includes("alta: El texto de un enlace no coincide con su destino"));
  assert.ok(t.includes("media: Enlace acortado"));
  assert.equal(r.links.length, 2); // el de bit.ly sale en el texto y en el HTML, pero cuenta una vez
});

test("ejemplo: fraude del CEO, que pasa SPF, DKIM y DMARC", () => {
  const r = sample("fraude-ceo");
  assert.equal(r.verdict.level, "peligro");
  assert.deepEqual([r.auth.spf, r.auth.dkim, r.auth.dmarc], ["pass", "pass", "pass"]);
  const lookalike = r.findings.find((f) => f.title === "El dominio del remitente imita a otro");
  assert.match(lookalike.detail, /empresa-ejemplo\.example/);
  assert.ok(r.findings.some((f) => f.severity === "ok" && /no quiere decir que ese dominio sea de fiar/.test(f.detail)));
});

test("ejemplo: factura con una página web disfrazada de PDF", () => {
  const r = sample("factura-adjunto");
  assert.equal(r.verdict.level, "peligro");
  assert.deepEqual(
    r.attachments.map((a) => [a.name, a.problems]),
    [["Factura_2026-0917.pdf.html", ["página web"]], ["Albaran_septiembre.zip", ["comprimido"]]],
  );
  assert.ok(titles(r).includes("alta: Adjunto con doble extensión: Factura_2026-0917.pdf.html"));
});

test("ejemplo: correo legítimo", () => {
  const r = sample("pedido-legitimo");
  assert.equal(r.verdict.level, "limpio");
  assert.equal(r.score, 0);
});

test("todos los ejemplos que enlaza la página existen", () => {
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const files = readdirSync(new URL("../samples/", import.meta.url));
  for (const [, name] of html.matchAll(/data-sample="([^"]+)"/g)) assert.ok(files.includes(`${name}.eml`), name);
});

test("nombre visible que es otra dirección", () => {
  const r = mail(['From: "soporte@paypal.com" <x@otro.example>']);
  assert.ok(titles(r).includes("alta: El nombre visible es otra dirección de correo"));
});

test("responder a un correo gratuito", () => {
  const r = mail(["From: Director <dg@empresa.example>", "Reply-To: director.urgente@gmail.com"]);
  assert.ok(titles(r).includes("alta: Las respuestas irían a otra dirección"));
});

test("trucos en los enlaces", () => {
  const html = [
    '<a href="https://www.bbva.es@login.evil.example/">Entrar</a>',
    '<a href="http://203.0.113.9/login">Acceder</a>',
    '<a href="javascript:alert(1)">Ver</a>',
    '<a href="https://xn--pypal-4ve.com/">PayPal</a>',
  ].join("");
  const r = analyze(parseMessage(`From: a@b.example\nContent-Type: text/html\n\n${html}`), NOW);
  const t = titles(r);
  assert.ok(t.includes("alta: Enlace con una @ para engañar"));
  assert.ok(t.includes("alta: Enlace a una dirección IP"));
  assert.ok(t.includes("alta: Enlace de tipo javascript:"));
  assert.ok(t.includes("alta: Un enlace lleva a un dominio que imita a otro"));
  assert.ok(r.links.some((l) => l.host === "pаypal.com")); // se enseña como lo vería la víctima
});

test("adjunto con el nombre dado la vuelta (U+202E)", () => {
  const raw = [
    "From: a@b.example",
    'Content-Type: multipart/mixed; boundary="B"',
    "",
    "--B",
    "Content-Type: application/octet-stream",
    'Content-Disposition: attachment; filename="Factura‮fdp.exe"',
    "",
    "x",
    "--B--",
  ].join("\n");
  const r = analyze(parseMessage(raw), NOW);
  assert.ok(titles(r).includes("alta: Adjunto con el nombre dado la vuelta"));
});

test("resultados de autenticación: vale el de arriba del todo", () => {
  const headers = parseMessage(
    [
      "Authentication-Results: mx.mio.example; spf=fail smtp.mailfrom=x@y.example; dkim=pass header.d=y.example; dmarc=fail header.from=y.example",
      "Authentication-Results: falso.example; spf=pass; dkim=pass; dmarc=pass", // puesto por el atacante
      "",
      "x",
    ].join("\n"),
  ).headers;
  const auth = parseAuthResults(headers);
  assert.deepEqual([auth.spf, auth.dkim, auth.dmarc], ["fail", "pass", "fail"]);
});

test("Received: del primer salto al último", () => {
  const hops = parseReceived([
    "from b.example ([192.0.2.2]) by c.example; Fri, 25 Sep 2026 10:00:10 +0200",
    "from a.example (a.example [192.0.2.1]) by b.example; Fri, 25 Sep 2026 10:00:00 +0200 (CEST)",
  ]);
  assert.deepEqual(hops.map((h) => [h.from, h.ip]), [["a.example", "192.0.2.1"], ["b.example", "192.0.2.2"]]);
  assert.equal(hops[1].date - hops[0].date, 10_000);
});

test("un correo normal sin nada raro no se marca", () => {
  const r = mail(["From: Ana <ana@amigos.example>", "To: yo@casa.example", "Subject: ¿Cenamos el sábado?"], "Hola, ¿te va bien a las 9?");
  assert.equal(r.verdict.level, "limpio");
});

test("nada de innerHTML ni parecidos en todo el proyecto", () => {
  // El HTML de un correo de phishing nunca debe interpretarse en la página.
  const files = readdirSync(new URL("../js/", import.meta.url)).filter((f) => f.endsWith(".js"));
  assert.ok(files.length >= 5);
  for (const file of files) {
    const code = readFileSync(new URL(`../js/${file}`, import.meta.url), "utf8");
    assert.doesNotMatch(code, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/, file);
  }
});

test("un enlace suelto: una sola señal grave ya es peligro", () => {
  const check = (url) => analyzeLink(url);
  assert.equal(check("https://www.bbva.es/personas.html").verdict.level, "limpio");
  for (const url of [
    "https://correos-es.info/paquete?id=123", // el nombre de una marca en otro dominio
    "https://xn--pypal-4ve.com/signin", // punycode que imita a paypal
    "http://192.168.10.5/correos/pago", // una IP
    "https://www.google.com@evil.example/", // el truco de la @
  ]) {
    assert.equal(check(url).verdict.level, "peligro", url);
  }
  assert.equal(check("https://bit.ly/3xYz").verdict.level, "sospechoso"); // no se sabe adónde lleva
  const http = check("http://example.com");
  assert.equal(http.verdict.level, "limpio");
  assert.deepEqual(http.findings.map((f) => f.title), ["Sin HTTPS"]);
  assert.equal(check("hola"), null);
});
