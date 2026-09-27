import assert from "node:assert/strict";
import { test } from "node:test";

import {
  brandsMentioned,
  decodePunycodeLabel,
  defang,
  lookalikeReason,
  registrableDomain,
  skeleton,
  toUnicode,
} from "../js/domains.js";

test("punycode: los mismos resultados que el códec de Python", () => {
  // Vectores sacados con "texto".encode("punycode") en Python.
  assert.equal(decodePunycodeLabel("pypal-4ve"), "pаypal"); // con "а" cirílica
  assert.equal(decodePunycodeLabel("maana-pta"), "mañana");
  assert.equal(decodePunycodeLabel("mnchen-3ya"), "münchen");
  assert.equal(decodePunycodeLabel("80abap1arsf"), "сбербанк");
  assert.equal(decodePunycodeLabel("r8jz45g"), "例え");
  assert.equal(toUnicode("www.xn--maana-pta.es"), "www.mañana.es");
  assert.equal(toUnicode("xn--!!!.com"), "xn--!!!.com"); // si no es válido, se deja como está
});

test("el navegador y nosotros entendemos lo mismo", () => {
  // new URL() convierte a punycode; toUnicode lo deshace.
  assert.equal(toUnicode(new URL("https://pаypal.com/").hostname), "pаypal.com");
});

test("dominio registrado", () => {
  assert.equal(registrableDomain("login.cuenta.paypal.com"), "paypal.com");
  assert.equal(registrableDomain("www.bbc.co.uk"), "bbc.co.uk");
  assert.equal(registrableDomain("sede.agenciatributaria.gob.es"), "agenciatributaria.gob.es");
});

test("esqueleto de un dominio", () => {
  assert.equal(skeleton("paypa1"), "paypal");
  assert.equal(skeleton("rnicr0soft"), "microsoft");
  assert.equal(skeleton("pаypal"), "paypal");
});

test("dominios que imitan a otros", () => {
  const imitates = [
    "xn--pypal-4ve.com", // alfabetos mezclados
    "paypa1.com",
    "arnazon.es",
    "gooogle.com",
    "linkedln.com",
    "paypal.com.cuenta-segura.example", // la marca como subdominio de otro
    "correos-envios.example",
  ];
  for (const host of imitates) assert.ok(lookalikeReason(host), host);
});

test("dominios de verdad y palabras normales no saltan", () => {
  for (const host of ["paypal.com", "www.paypal.com", "bbva.es", "github.com", "finance.com", "correo.gob.es", "ample.com"]) {
    assert.equal(lookalikeReason(host), null, host);
  }
});

test("imitar el dominio de la propia empresa (fraude del CEO)", () => {
  assert.match(lookalikeReason("ernpresa-ejemplo.example", ["empresa-ejemplo.example"]), /casi igual/);
  assert.equal(lookalikeReason("empresa-ejemplo.example", ["empresa-ejemplo.example"]), null);
});

test("marcas en el nombre visible", () => {
  assert.deepEqual(brandsMentioned("Servicio de atención de PayPal"), ["paypal"]);
  assert.deepEqual(brandsMentioned("Agencia Tributaria - Devoluciones"), ["agenciatributaria"]);
  assert.deepEqual(brandsMentioned("ups, se me olvidó el adjunto"), []);
  assert.deepEqual(brandsMentioned("Envío UPS 1Z999"), ["ups"]);
});

test("defang", () => {
  assert.equal(defang("https://login.evil.example/x?a=b.c"), "hxxps://login[.]evil[.]example/x?a=b.c");
});
