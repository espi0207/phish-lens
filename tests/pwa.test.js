import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const list = (dir, ext) => readdirSync(new URL(`../${dir}/`, import.meta.url)).filter((f) => f.endsWith(ext)).map((f) => `${dir}/${f}`);

test("el service worker guarda todo lo que hace falta sin conexión", () => {
  const sw = read("sw.js");
  const files = ["index.html", "manifest.webmanifest", ...list("js", ".js"), ...list("css", ".css"), ...list("samples", ".eml"), ...list("icons", "")];
  for (const file of files) assert.ok(sw.includes(`"${file}"`), file);
});

test("el manifiesto sirve para instalarla y para abrir los .eml", () => {
  const manifest = JSON.parse(read("manifest.webmanifest"));
  assert.equal(manifest.display, "standalone");
  const sizes = manifest.icons.map((i) => i.sizes);
  assert.ok(sizes.includes("192x192") && sizes.includes("512x512")); // lo que pide Chrome para instalar
  for (const icon of manifest.icons) assert.ok(read(icon.src).length > 0, icon.src);
  assert.deepEqual(manifest.file_handlers[0].accept, { "message/rfc822": [".eml"] });
  const html = read("index.html");
  assert.ok(html.includes('rel="manifest" href="manifest.webmanifest"'));
  assert.match(html, /manifest-src 'self'; worker-src 'self'/);
});
