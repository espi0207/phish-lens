import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeEntities, linksFromHtml, linksFromText } from "../js/links.js";
import { decodeHeaderValue, parseAddress, parseAddressList, parseMessage, parseParams } from "../js/mail.js";

test("palabras codificadas de RFC 2047", () => {
  assert.equal(decodeHeaderValue("=?utf-8?Q?Espa=C3=B1a?="), "España");
  assert.equal(decodeHeaderValue("=?ISO-8859-1?Q?Informaci=F3n_urgente?="), "Información urgente");
  assert.equal(decodeHeaderValue("=?UTF-8?B?w5Fvw7Fv?="), "Ñoño");
  // Entre dos palabras codificadas seguidas, el espacio no cuenta.
  assert.equal(decodeHeaderValue("=?UTF-8?Q?Hola?= =?UTF-8?Q?_mundo?="), "Hola mundo");
});

test("cabeceras en UTF-8 sin codificar (RFC 6532)", () => {
  const msg = parseMessage("Subject: Café con ñ\n\ncuerpo");
  assert.equal(msg.headers.get("subject"), "Café con ñ");
});

test("cabeceras partidas en varias líneas", () => {
  const msg = parseMessage("Subject: una cabecera\n  muy larga\nFrom: a@b.example\n\nx");
  assert.equal(msg.headers.get("subject"), "una cabecera muy larga");
  assert.equal(msg.headers.get("FROM"), "a@b.example"); // sin distinguir mayúsculas
});

test("parámetros MIME, también los de RFC 2231", () => {
  assert.deepEqual(parseParams('text/plain; charset="iso-8859-1"; format=flowed'), {
    value: "text/plain",
    params: { charset: "iso-8859-1", format: "flowed" },
  });
  assert.equal(parseParams("attachment; filename*=UTF-8''factura%20mayo%20%E2%82%AC.pdf").params.filename, "factura mayo €.pdf");
  assert.equal(parseParams(`application/pdf; name*0*=UTF-8''Factura%20; name*1="de mayo.pdf"`).params.name, "Factura de mayo.pdf");
});

test("multipart con texto, HTML y adjunto", () => {
  const raw = [
    "From: =?UTF-8?Q?Jos=C3=A9?= <jose@ejemplo.example>",
    'Content-Type: multipart/mixed; boundary="X"',
    "",
    "preámbulo que se ignora",
    "--X",
    "Content-Type: multipart/alternative; boundary=ALT",
    "",
    "--ALT",
    "Content-Type: text/plain; charset=iso-8859-1",
    "Content-Transfer-Encoding: quoted-printable",
    "",
    "Hola, se=F1or, esta l=",
    "=EDnea sigue",
    "--ALT",
    "Content-Type: text/html; charset=utf-8",
    "Content-Transfer-Encoding: base64",
    "",
    Buffer.from('<a href="https://x.example">clic</a>').toString("base64"),
    "--ALT--",
    "--X",
    'Content-Type: application/octet-stream; name="x.bin"',
    'Content-Disposition: attachment; filename="factura.pdf.exe"',
    "Content-Transfer-Encoding: base64",
    "",
    "TVqQAAMAAAAEAAAA",
    "--X--",
    "",
  ].join("\r\n");
  const msg = parseMessage(raw);
  assert.equal(msg.headers.get("from"), "José <jose@ejemplo.example>");
  assert.equal(msg.text, "Hola, señor, esta línea sigue");
  assert.equal(msg.html, '<a href="https://x.example">clic</a>');
  assert.deepEqual(msg.attachments, [{ filename: "factura.pdf.exe", contentType: "application/octet-stream", size: 12 }]);
});

test("un correo con multiparts anidados sin fin no cuelga la página", () => {
  const nested = Array.from({ length: 50 }, (_, i) => `Content-Type: multipart/mixed; boundary=b${i}\n\n--b${i}\n`).join("");
  assert.doesNotThrow(() => parseMessage(`From: a@b.example\n${nested}texto`));
});

test("direcciones", () => {
  assert.deepEqual(parseAddress('"Soporte PayPal" <Avisos@Ejemplo.COM>'), {
    name: "Soporte PayPal",
    address: "avisos@ejemplo.com",
    domain: "ejemplo.com",
  });
  assert.equal(parseAddress("solo@direccion.example").address, "solo@direccion.example");
  assert.deepEqual(
    parseAddressList('Ana <a@x.example>, "Ruiz, Juan" <b@y.example>').map((a) => a.address),
    ["a@x.example", "b@y.example"],
  );
});

test("enlaces del HTML, sin interpretarlo", () => {
  const html = `<p>Hola</p><A HREF='https://a.example/?x=1&amp;y=2'>Ver <b>factura</b> &raquo;</A>
    <a href="#arriba">arriba</a><a href="mailto:x@y.example">escríbenos</a><a href=http://sin-comillas.example>otro</a>`;
  assert.deepEqual(linksFromHtml(html), [
    { href: "https://a.example/?x=1&y=2", text: "Ver factura »" },
    { href: "http://sin-comillas.example", text: "otro" },
  ]);
  assert.deepEqual(linksFromText("Entra en https://b.example/ruta. Gracias"), [{ href: "https://b.example/ruta", text: "" }]);
});

test("entidades HTML", () => {
  assert.equal(decodeEntities("aqu&iacute; &Ntilde; &euro; &#8364; &#x20AC; &nada;"), "aquí Ñ € € € &nada;");
});
