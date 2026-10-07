import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { decodePng } from "../scripts/png.mjs";
import { analyze } from "../js/analyze.js";
import { parseMessage } from "../js/mail.js";
import { applyQr, scanQr } from "../js/qr.js";

const NOW = new Date("2026-10-07T12:00:00Z");
const read = (path) => readFileSync(new URL(path, import.meta.url));
const titles = (result) => result.findings.map((f) => `${f.severity}: ${f.title}`);

const module = { exports: {} };
new Function("module", "exports", read("../js/vendor/jsQR.js").toString("utf8"))(module, module.exports);
const jsQR = module.exports;

async function decode({ data }) {
  const { width, height, data: pixels } = decodePng(data);
  return jsQR(pixels, width, height)?.data ?? null;
}

const fromFile = (name) => ({ data: new Uint8Array(read(`fixtures/${name}`)), contentType: "image/png" });

test("jsQR es el original: su hash no ha cambiado", () => {
  const text = read("../js/vendor/jsQR.js").toString("utf8").replace(/\r\n/g, "\n");
  assert.equal(createHash("sha256").update(text).digest("hex"), "bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859");
  assert.ok(!/\beval\(|new Function|XMLHttpRequest|fetch\(|WebSocket/.test(text));
});

test("lee el QR de un PNG de paleta y de uno RGB, y no inventa uno en una imagen sin QR", async () => {
  assert.equal(await decode(fromFile("qr-phish.png")), "https://paypa1.example/verificar?id=4417");
  assert.equal(await decode(fromFile("qr-clean.png")), "https://www.correos.es/seguimiento");
  assert.equal(await decode(fromFile("sin-qr.png")), null);
});

test("el lector de PNG rechaza lo que no es un PNG", () => {
  assert.throws(() => decodePng(Buffer.from("no soy un png")), /no es un PNG/);
});

test("ejemplo: QR de PayPal falso dentro de una imagen incrustada", async () => {
  const message = parseMessage(new Uint8Array(read("../samples/qr-paypal.eml")));
  assert.equal(message.images.length, 1);
  const base = analyze(message, NOW);
  assert.equal(base.verdict.level, "limpio", "sin mirar el QR no se ve nada raro");
  const scan = await scanQr(message, decode);
  assert.equal(scan.codes.length, 1);
  assert.equal(scan.onlyImage, true);

  const r = applyQr(base, scan);
  assert.equal(r.verdict.level, "peligro");
  assert.ok(titles(r).some((t) => /^alta: El código QR de verificacion\.png lleva a hxxps:\/\/paypa1\[\.\]example/.test(t)));
  assert.ok(r.links.some((l) => l.text === "(código QR de verificacion.png)" && l.host === "paypa1.example"));
  assert.ok(r.score > base.score);
  assert.equal(base.findings.length, 3, "el resultado original no cambia");
});

test("un QR a un sitio legítimo en un correo que es solo la imagen sale como mínimo 'media'", async () => {
  const png = read("fixtures/qr-clean.png").toString("base64");
  const message = parseMessage(
    `From: Correos <a@correos.es>\nContent-Type: text/html\n\n<img src="data:image/png;base64,${png}">`,
  );
  const scan = await scanQr(message, decode);
  assert.deepEqual(scan.codes, [{ source: "imagen del correo", text: "https://www.correos.es/seguimiento" }]);
  const r = applyQr(analyze(message, NOW), scan);
  assert.ok(titles(r).some((t) => /^media: El código QR de imagen del correo/.test(t)));
});

test("sin QR no cambia nada, y una imagen ilegible no tumba el análisis", async () => {
  const message = parseMessage(
    `From: a@b.example\nContent-Type: text/html\n\n<img src="data:image/png;base64,${read("fixtures/sin-qr.png").toString("base64")}"><img src="data:image/png;base64,AAAA">`,
  );
  const scan = await scanQr(message, decode);
  assert.deepEqual(scan.codes, []);
  const base = analyze(message, NOW);
  assert.equal(applyQr(base, scan), base);
});

test("un QR que no es un enlace web se cuenta aparte", () => {
  const base = analyze(parseMessage("From: a@b.example\n\nhola"), NOW);
  const r = applyQr(base, { codes: [{ source: "x.png", text: "WIFI:T:WPA;S:red;P:clave;;" }, { source: "y.png", text: "javascript:alert(1)" }], onlyImage: false });
  assert.ok(titles(r).includes("baja: El código QR de x.png no es un enlace web"));
  assert.ok(titles(r).includes("alta: El código QR de y.png no es un enlace web"));
});

test("mail.js guarda solo las imágenes, con tope", () => {
  const png = read("fixtures/sin-qr.png").toString("base64");
  const part = (n) => `--b\nContent-Type: image/png; name="${n}.png"\nContent-Transfer-Encoding: base64\n\n${png}\n`;
  const raw = `Content-Type: multipart/mixed; boundary=b\n\n${Array.from({ length: 12 }, (_, i) => part(i)).join("")}--b\nContent-Type: application/pdf; name="x.pdf"\nContent-Transfer-Encoding: base64\n\nJVBERg==\n--b--\n`;
  const m = parseMessage(raw);
  assert.equal(m.attachments.length, 13);
  assert.equal(m.images.length, 10);
  assert.ok(m.images.every((i) => i.data instanceof Uint8Array && i.contentType === "image/png"));
});
