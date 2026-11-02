import assert from "node:assert/strict";
import { test } from "node:test";

import { linksFromHtml } from "../js/links.js";

// Fallos encontrados en la revisión con Codex.

test("data-href no se confunde con href: cuenta el enlace al que se va de verdad", () => {
  const html = '<a data-href="https://paypal.com" href="https://paypa1.com">paypal.com</a>';
  assert.deepEqual(linksFromHtml(html), [{ href: "https://paypa1.com", text: "paypal.com" }]);
});

test("un > dentro de las comillas de otro atributo no corta la etiqueta", () => {
  const html = '<a title="1 > 0" href="https://paypa1.com">Entrar</a>';
  assert.deepEqual(linksFromHtml(html), [{ href: "https://paypa1.com", text: "Entrar" }]);
});

test("un enlace sin cerrar también cuenta", () => {
  assert.deepEqual(linksFromHtml('<p><a href="https://paypa1.com">Entrar<p>Gracias'), [
    { href: "https://paypa1.com", text: "Entrar Gracias" },
  ]);
  assert.deepEqual(linksFromHtml('<a href="https://a.example">uno<a href="https://b.example">dos</a>'), [
    { href: "https://a.example", text: "uno" },
    { href: "https://b.example", text: "dos" },
  ]);
});

test("si href sale dos veces, vale el primero (como en el navegador)", () => {
  assert.equal(linksFromHtml('<a href="https://a.example" href="https://b.example">x</a>')[0].href, "https://a.example");
});

test("muchas <a> sin cerrar se leen en tiempo lineal", () => {
  const start = performance.now();
  linksFromHtml("<a>".repeat(200_000));
  assert.ok(performance.now() - start < 500);
});
