// Monta la extensión para Chrome y Edge en dist/extension/ y la comprime en
// dist/phish-lens-extension.zip (lo que se sube a la tienda o se adjunta en Releases).
//
// La extensión es la misma página (index.html, css/, js/) más lo suyo (extension/), con la
// misma estructura de carpetas, así que los import relativos funcionan igual en los dos
// sitios. La versión sale de package.json.
//
// Uso: node scripts/build-extension.mjs [carpeta de salida]

import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// Lo que no hace falta en la extensión: el service worker y el manifiesto son de la versión web.
const FILES = ["index.html", "css", "js", "icons", "samples", "manifest.webmanifest", "extension"];
const SKIP = new Set(["extension/manifest.json"]);

export function build(out = join(ROOT, "dist")) {
  const dir = join(out, "extension");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  for (const name of FILES) {
    cpSync(join(ROOT, name), join(dir, name), {
      recursive: true,
      filter: (src) => !SKIP.has(relative(ROOT, src).split("\\").join("/")),
    });
  }
  const manifest = JSON.parse(readFileSync(join(ROOT, "extension/manifest.json"), "utf8"));
  manifest.version = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");

  const zip = join(out, "phish-lens-extension.zip");
  writeFileSync(zip, makeZip(dir));
  return { dir, zip, manifest };
}

function listFiles(dir, base = dir) {
  return readdirSync(dir)
    .sort()
    .flatMap((name) => {
      const path = join(dir, name);
      return statSync(path).isDirectory() ? listFiles(path, base) : [relative(base, path).split("\\").join("/")];
    });
}

// Un .zip hecho a mano: cabecera local + datos por archivo, y al final el directorio central.
// Así no hace falta ninguna dependencia (formato: PKWARE APPNOTE, sección 4.3).

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

export function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function makeZip(dir) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const name of listFiles(dir)) {
    const data = readFileSync(join(dir, name));
    const packed = deflateRawSync(data, { level: 9 });
    const nameBytes = Buffer.from(name, "utf8");
    const fields = (header) => {
      header.writeUInt16LE(20, 4); // versión necesaria: 2.0
      header.writeUInt16LE(0x0800, 6); // nombres en UTF-8
      header.writeUInt16LE(8, 8); // deflate
      header.writeUInt32LE(0x00210000, 10); // hora y fecha fijas (1980-01-01): el zip sale siempre igual
      header.writeUInt32LE(crc32(data), 14);
      header.writeUInt32LE(packed.length, 18);
      header.writeUInt32LE(data.length, 22);
      header.writeUInt16LE(nameBytes.length, 26);
    };
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    fields(local);
    locals.push(local, nameBytes, packed);

    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4); // hecho con la versión 2.0
    local.copy(entry, 6, 4, 30); // mismos campos que la cabecera local, dos bytes más adelante
    entry.writeUInt32LE(offset, 42);
    central.push(entry, nameBytes);
    offset += local.length + nameBytes.length + packed.length;
  }
  const centralSize = central.reduce((sum, b) => sum + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(central.length / 2, 8);
  end.writeUInt16LE(central.length / 2, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...central, end]);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { dir, zip, manifest } = build(process.argv[2]);
  console.log(`phish-lens ${manifest.version}: ${listFiles(dir).length} archivos en ${relative(process.cwd(), dir)}`);
  console.log(`${relative(process.cwd(), zip)} (${(statSync(zip).size / 1024).toFixed(0)} KB)`);
}
