import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

import { csvCell, summarize, toCsv, toMarkdown } from "../js/batch.js";
import { analyzeDirectory } from "../scripts/analyze-folder.mjs";

const samples = fileURLToPath(new URL("../samples/", import.meta.url));
const cli = fileURLToPath(new URL("../scripts/analyze-folder.mjs", import.meta.url));

let dir;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "phish-lens-batch-"));
  mkdirSync(join(dir, "sub", "mas"), { recursive: true });
  copyFileSync(join(samples, "correos-paquete.eml"), join(dir, "a.eml"));
  copyFileSync(join(samples, "pedido-legitimo.eml"), join(dir, "sub", "b.EML"));
  copyFileSync(join(samples, "factura-adjunto.eml"), join(dir, "sub", "mas", "c.eml"));
  writeFileSync(join(dir, "roto.eml"), Buffer.from([0, 255, 1, 2, 3, 0, 9, 9]));
  writeFileSync(join(dir, "notas.txt"), "no es un eml");
});
after(() => rmSync(dir, { recursive: true, force: true }));

test("recorre subcarpetas, ignora lo que no es .eml y un correo roto no tumba el lote", async () => {
  const items = await analyzeDirectory(dir);
  assert.deepEqual(items.map((i) => i.name), ["a.eml", "roto.eml", "sub/b.EML", "sub/mas/c.eml"]);
  const s = summarize(items);
  assert.equal(s.total, 4);
  assert.equal(s.analyzed, 3);
  assert.deepEqual(s.errors.map((e) => e.name), ["roto.eml"]);
  assert.deepEqual(s.levels, { peligro: 2, sospechoso: 0, limpio: 1 });
});

test("resumen: filas de más a menos arriesgado, hallazgos repetidos y adjuntos peligrosos", async () => {
  const s = summarize(await analyzeDirectory(samples, { qr: false }));
  assert.equal(s.analyzed, s.total);
  const scores = s.rows.map((r) => r.score);
  assert.deepEqual(scores, [...scores].sort((a, b) => b - a));
  assert.equal(s.rows.at(-1).name, "pedido-legitimo.eml");
  const dmarc = s.findings.find((f) => f.title === "DMARC ha fallado");
  assert.ok(dmarc.count >= 3 && dmarc.severity === "alta");
  assert.ok(s.attachments.some((a) => a.name === "Factura_2026-0917.pdf.html" && a.mail === "factura-adjunto.eml"));
  assert.ok(!s.attachments.some((a) => a.problems.includes("comprimido") && a.problems.length === 1), "un zip solo no es peligroso");
});

test("CSV: comillas, saltos de línea y protección contra fórmulas de Excel", () => {
  assert.equal(csvCell('hola, "mundo"'), '"hola, ""mundo"""');
  assert.equal(csvCell("línea\nsegunda"), '"línea\nsegunda"');
  assert.equal(csvCell("=HYPERLINK(\"http://x\")"), "\"'=HYPERLINK(\"\"http://x\"\")\"");
  for (const bad of ["+1", "-2", "@x", "\tx"]) assert.ok(csvCell(bad).startsWith("'"), bad);
  const csv = toCsv(summarize([{ name: "x.eml", result: fakeResult({ subject: "=cmd|' /C calc'!A0" }) }]));
  const [header, row] = csv.trimEnd().split("\n");
  assert.equal(header.split(",").length, 10);
  assert.ok(row.includes(",'=cmd|"));
});

test("Markdown: las barras verticales no rompen la tabla", () => {
  const md = toMarkdown(summarize([{ name: "x.eml", result: fakeResult({ subject: "a | b" }) }]));
  assert.match(md, /a \\\| b/);
  assert.match(md, /Analizados: 1 de 1/);
});

test("la línea de comandos: salida 1 si hay peligro, 0 si no, 2 si se usa mal", () => {
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
  const bad = run(dir);
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /Analizados 3 de 4: 2 en peligro, 0 sospechosos, 1 limpios/);
  assert.match(bad.stdout, /sin leer: roto\.eml/);

  const clean = mkdtempSync(join(tmpdir(), "phish-lens-clean-"));
  copyFileSync(join(samples, "pedido-legitimo.eml"), join(clean, "ok.eml"));
  assert.equal(run(clean).status, 0);
  rmSync(clean, { recursive: true, force: true });

  assert.equal(run().status, 2);
  assert.equal(run(join(dir, "no-existe")).status, 2);
  assert.equal(run(dir, "--rarisima").status, 2);

  const out = join(dir, "informe.csv");
  assert.equal(run(dir, "--csv", "--out", out).status, 1);
  assert.match(readFileSync(out, "utf8"), /^archivo,veredicto,/);
  assert.equal(JSON.parse(run(dir, "--json").stdout).levels.peligro, 2);
});

test("por defecto la línea de comandos no hace peticiones de red", () => {
  const code = readFileSync(cli, "utf8");
  assert.ok(!/\bfetch\(/.test(code));
  assert.match(code, /if \(completo\) result = await enrich/);
});

function fakeResult({ subject }) {
  return {
    verdict: { level: "limpio" }, score: 0, subject, from: { address: "a@b.example", domain: "b.example" },
    findings: [], attachments: [], links: [],
  };
}
