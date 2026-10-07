#!/usr/bin/env node
// Analiza todos los .eml de una carpeta (y sus subcarpetas) y saca un resumen para un SOC.
//
//   node scripts/analyze-folder.mjs <carpeta> [--json | --csv | --md] [--out fichero]
//        [--completo] [--acortadores] [--sin-qr]
//
// Por defecto es todo en local. --completo hace las consultas de red del modo completo (edad del
// dominio, SPF y DMARC por DNS, lista negra) solo con los dominios, y --acortadores además sigue los
// acortadores, lo que contacta con la web de destino. Los QR se leen en PNG (los demás formatos
// necesitan el navegador). Código de salida: 0 todo bien, 1 si hay algún correo en peligro, 2 si
// el uso es incorrecto.

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";

import { analyze } from "../js/analyze.js";
import { summarize, toCsv, toMarkdown } from "../js/batch.js";
import { parseMessage } from "../js/mail.js";
import { enrich } from "../js/online.js";
import { applyQr, scanQr } from "../js/qr.js";
import { decodePng } from "./png.mjs";

const MAX_SIZE = 15 * 1024 * 1024;
const CONCURRENCY = 4;

function loadJsQr() {
  const code = readFileSync(new URL("../js/vendor/jsQR.js", import.meta.url), "utf8");
  const module = { exports: {} };
  runInNewContext(`(function (module, exports) {${code}\n})(module, module.exports)`, { module });
  return module.exports;
}

async function decodeNode(jsQR, { data, contentType }) {
  if (contentType !== "image/png") return null;
  const { width, height, data: pixels } = decodePng(data);
  return jsQR(pixels, width, height)?.data ?? null;
}

export function findEml(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...findEml(path));
    else if (entry.isFile() && /\.eml$/i.test(entry.name)) found.push(path);
  }
  return found.sort();
}

async function analyzeFile(path, name, { completo, acortadores, qr, jsQR }) {
  try {
    if (statSync(path).size > MAX_SIZE) return { name, error: "más de 15 MB" };
    const message = parseMessage(new Uint8Array(readFileSync(path)));
    if (!message.headers.list.length) return { name, error: "no parece un correo (sin cabeceras)" };
    let result = analyze(message);
    if (qr) result = applyQr(result, await scanQr(message, (image) => decodeNode(jsQR, image)));
    if (completo) result = await enrich(result, { shorteners: acortadores });
    return { name, result };
  } catch (err) {
    return { name, error: err.message };
  }
}

/** Analiza los .eml de una carpeta, de CONCURRENCY en CONCURRENCY. Devuelve la lista para `summarize`. */
export async function analyzeDirectory(dir, options = {}) {
  const opts = { completo: false, acortadores: false, qr: true, ...options };
  if (opts.qr) opts.jsQR = loadJsQr();
  const files = findEml(dir);
  const items = new Array(files.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, files.length) }, async () => {
      while (next < files.length) {
        const i = next++;
        items[i] = await analyzeFile(files[i], relative(dir, files[i]).replaceAll("\\", "/"), opts);
      }
    }),
  );
  return items;
}

function parseArgs(argv) {
  const args = { format: "text", out: null, dir: null, completo: false, acortadores: false, qr: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json" || a === "--csv" || a === "--md") args.format = a.slice(2);
    else if (a === "--out") args.out = argv[++i];
    else if (a === "--completo") args.completo = true;
    else if (a === "--acortadores") args.acortadores = args.completo = true;
    else if (a === "--sin-qr") args.qr = false;
    else if (a.startsWith("--")) throw new Error(`opción desconocida: ${a}`);
    else if (!args.dir) args.dir = a;
    else throw new Error("solo se admite una carpeta");
  }
  if (!args.dir) throw new Error("falta la carpeta");
  return args;
}

function plainText(summary) {
  const { levels } = summary;
  const lines = [
    `Analizados ${summary.analyzed} de ${summary.total}: ${levels.peligro} en peligro, ${levels.sospechoso} sospechosos, ${levels.limpio} limpios.`,
  ];
  for (const e of summary.errors) lines.push(`  sin leer: ${e.name} (${e.error})`);
  for (const r of summary.rows.filter((row) => row.verdict !== "limpio")) {
    lines.push(`  [${r.verdict.toUpperCase()} ${r.score}] ${r.name}  ${r.from}  «${r.subject}»`);
  }
  return lines.join("\n") + "\n";
}

export async function main(argv, stdout = process.stdout, stderr = process.stderr) {
  let args;
  try {
    args = parseArgs(argv);
    if (!statSync(args.dir).isDirectory()) throw new Error(`${args.dir} no es una carpeta`);
  } catch (err) {
    stderr.write(`${err.message}\nUso: node scripts/analyze-folder.mjs <carpeta> [--json|--csv|--md] [--out fichero] [--completo] [--acortadores] [--sin-qr]\n`);
    return 2;
  }
  const items = await analyzeDirectory(args.dir, args);
  const summary = summarize(items);
  const text =
    args.format === "json" ? JSON.stringify(summary, null, 2) + "\n"
    : args.format === "csv" ? toCsv(summary)
    : args.format === "md" ? toMarkdown(summary)
    : plainText(summary);
  if (args.out) writeFileSync(args.out, text);
  else stdout.write(text);
  return summary.levels.peligro > 0 ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
