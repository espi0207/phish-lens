import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { inflateRawSync } from "node:zlib";

import { build, crc32 } from "../scripts/build-extension.mjs";

let out;
let result;
before(() => {
  out = mkdtempSync(join(tmpdir(), "phish-lens-"));
  result = build(out);
});
after(() => rmSync(out, { recursive: true, force: true }));

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

test("el manifiesto: versión de package.json y los permisos justos", () => {
  const { manifest, dir } = result;
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.version, pkg.version);
  assert.ok(manifest.description.length <= 132); // el límite de la Chrome Web Store
  // Nada de "leer todos tus datos en todas las webs": solo el menú del clic derecho y la
  // memoria de la sesión, y el script de Gmail solo en Gmail.
  assert.deepEqual(manifest.permissions, ["contextMenus", "storage"]);
  assert.equal(manifest.host_permissions, undefined);
  assert.deepEqual(manifest.content_scripts.map((c) => c.matches).flat(), ["https://mail.google.com/mail/*"]);
  const referenced = [
    manifest.background.service_worker,
    ...manifest.content_scripts.flatMap((c) => c.js),
    ...Object.values(manifest.icons),
    ...Object.values(manifest.action.default_icon),
  ];
  for (const file of referenced) assert.ok(existsSync(join(dir, file)), file);
});

test("los import de la parte de fondo existen dentro de la extensión", () => {
  const { dir, manifest } = result;
  const worker = join(dir, manifest.background.service_worker);
  for (const [, path] of readFileSync(worker, "utf8").matchAll(/from "(\.[^"]+)"/g)) {
    assert.ok(existsSync(join(worker, "..", path)), path);
  }
  // Y los de la página, que es la misma que la web.
  assert.ok(existsSync(join(dir, "index.html")) && existsSync(join(dir, "js/app.js")));
  assert.ok(!existsSync(join(dir, "sw.js"))); // el service worker es solo de la web
});

test("el .zip se abre y cada archivo está entero", () => {
  const zip = readFileSync(result.zip);
  const end = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = zip.readUInt16LE(end + 10);
  let pos = zip.readUInt32LE(end + 16);
  const names = [];
  for (let i = 0; i < count; i++) {
    assert.equal(zip.readUInt32LE(pos), 0x02014b50);
    const crc = zip.readUInt32LE(pos + 16);
    const size = zip.readUInt32LE(pos + 20);
    const nameLength = zip.readUInt16LE(pos + 28);
    const local = zip.readUInt32LE(pos + 42);
    const name = zip.toString("utf8", pos + 46, pos + 46 + nameLength);
    const start = local + 30 + zip.readUInt16LE(local + 26);
    const data = inflateRawSync(zip.subarray(start, start + size));
    assert.equal(crc32(data), crc, name);
    assert.deepEqual(data, readFileSync(join(result.dir, name)), name);
    names.push(name);
    pos += 46 + nameLength;
  }
  assert.ok(names.includes("manifest.json") && names.includes("extension/gmail.js"));
});

test("crc32 da lo mismo que el resto del mundo", () => {
  assert.equal(crc32(Buffer.from("123456789")), 0xcbf43926); // el valor de referencia del estándar
});

test("tampoco hay innerHTML en la extensión", () => {
  const dir = new URL("../extension/", import.meta.url);
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".js"))) {
    const code = readFileSync(new URL(file, dir), "utf8");
    assert.doesNotMatch(code, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/, file);
  }
});
