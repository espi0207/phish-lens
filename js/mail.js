// Parser de correos en formato .eml (RFC 5322 + MIME), sin librerías.
//
// Trabaja sobre una "cadena de bytes" (cada carácter es un byte, 0-255) para no
// estropear nada antes de saber en qué juego de caracteres está cada parte. Las
// cabeceras se leen como UTF-8 y cada parte de texto con su charset.

const MAX_DEPTH = 10; // un multipart dentro de otro... sin límite, un correo malicioso podría colgar la página

export function bytesToBinary(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return out;
}

export function textToBinary(text) {
  return bytesToBinary(new TextEncoder().encode(text));
}

function binaryToBytes(binary) {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 0xff;
  return bytes;
}

export function decodeBytes(binary, charset = "utf-8") {
  let label = (charset || "utf-8").toLowerCase().trim();
  if (label === "us-ascii" || label === "ascii") label = "utf-8";
  try {
    return new TextDecoder(label).decode(binaryToBytes(binary));
  } catch {
    return new TextDecoder("utf-8").decode(binaryToBytes(binary)); // charset desconocido
  }
}

function decodeBase64(text) {
  const clean = text.replace(/[^A-Za-z0-9+/]/g, "");
  try {
    return atob(clean + "=".repeat((4 - (clean.length % 4)) % 4));
  } catch {
    return "";
  }
}

function decodeQuotedPrintable(text) {
  return text
    .replace(/=\r?\n/g, "") // saltos de línea "blandos"
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

// Palabras codificadas de RFC 2047: =?UTF-8?B?...?= o =?iso-8859-1?Q?...?=
const ENCODED_WORD = /=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g;

export function decodeHeaderValue(value) {
  // Primero, lo que venga sin codificar puede ser UTF-8 directamente (RFC 6532). Tiene
  // que ir antes que lo de RFC 2047: si no, una "ñ" ya descodificada se estropearía.
  const text = /[\x80-\xff]/.test(value) ? decodeBytes(value) : value;
  // Entre dos palabras codificadas seguidas, el espacio no cuenta (RFC 2047, sección 6.2).
  return text
    .replace(/(\?=)\s+(=\?)/g, "$1$2")
    .replace(ENCODED_WORD, (_, charset, encoding, encoded) => {
      const binary =
        encoding.toUpperCase() === "B" ? decodeBase64(encoded) : decodeQuotedPrintable(encoded.replace(/_/g, " "));
      return decodeBytes(binary, charset.split("*")[0]);
    });
}

function parseHeaders(block) {
  const headers = [];
  for (const line of block.split("\n")) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].raw += " " + line.trim(); // continuación de la anterior
    } else {
      const colon = line.indexOf(":");
      if (colon > 0) headers.push({ name: line.slice(0, colon).trim(), raw: line.slice(colon + 1).trim() });
    }
  }
  return headers.map((h) => ({ name: h.name, value: decodeHeaderValue(h.raw), raw: h.raw }));
}

/** "text/html; charset=utf-8; name*=UTF-8''factura%20mayo.pdf" -> { value, params } */
export function parseParams(header = "") {
  const [value, ...rest] = splitOutsideQuotes(header, ";");
  const params = {};
  const continued = {};
  for (const part of rest) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    let key = part.slice(0, eq).trim().toLowerCase();
    let val = part.slice(eq + 1).trim();
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1).replace(/\\(.)/g, "$1");
    // RFC 2231: name*=charset''texto%20codificado, y trozos name*0*=, name*1*=...
    const m = key.match(/^([^*]+)\*(\d+)?(\*)?$/);
    if (m) {
      const [, base, index = "0", encoded] = m;
      (continued[base] ??= []).push({ index: Number(index), val, encoded: encoded !== undefined || !m[2] });
      continue;
    }
    params[key] = decodeHeaderValue(val);
  }
  for (const [base, pieces] of Object.entries(continued)) {
    pieces.sort((a, b) => a.index - b.index);
    let charset = "utf-8";
    const text = pieces
      .map((p, i) => {
        let v = p.val;
        if (i === 0 && p.encoded && /^[^']*'[^']*'/.test(v)) {
          charset = v.split("'")[0] || "utf-8";
          v = v.slice(v.indexOf("'", v.indexOf("'") + 1) + 1);
        }
        return p.encoded ? v.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) : v;
      })
      .join("");
    params[base] = decodeBytes(text, charset);
  }
  return { value: value.trim().toLowerCase(), params };
}

function splitOutsideQuotes(text, sep) {
  const parts = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' && text[i - 1] !== "\\") quoted = !quoted;
    if (c === sep && !quoted) {
      parts.push(current);
      current = "";
    } else {
      current += c;
    }
  }
  parts.push(current);
  return parts;
}

class Headers {
  constructor(list) {
    this.list = list;
  }
  get(name) {
    return this.list.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? "";
  }
  getAll(name) {
    return this.list.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);
  }
}

function splitMessage(binary) {
  const text = binary.replace(/\r\n/g, "\n");
  const cut = text.indexOf("\n\n");
  return cut < 0 ? [text, ""] : [text.slice(0, cut), text.slice(cut + 2)];
}

// Las imágenes se guardan enteras (para buscar códigos QR); el resto de adjuntos, solo su tamaño.
const IMAGE_TYPES = /^image\/(png|jpe?g|gif|bmp|webp)$/;
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_IMAGES = 10;

function parsePart(binary, depth, out) {
  const [head, body] = splitMessage(binary);
  const headers = new Headers(parseHeaders(head));
  const type = parseParams(headers.get("content-type") || "text/plain");
  const disposition = parseParams(headers.get("content-disposition"));
  const encoding = headers.get("content-transfer-encoding").toLowerCase().trim();

  if (type.value.startsWith("multipart/") && type.params.boundary && depth < MAX_DEPTH) {
    const boundary = "--" + type.params.boundary;
    const chunks = body.split("\n" + boundary);
    // El primer trozo es el preámbulo (o empieza directamente por la frontera).
    const first = chunks[0].startsWith(boundary) ? chunks[0].slice(boundary.length) : null;
    const parts = first !== null ? [first, ...chunks.slice(1)] : chunks.slice(1);
    for (const chunk of parts) {
      if (chunk.startsWith("--")) break; // frontera final
      parsePart(chunk.replace(/^[ \t]*\n/, ""), depth + 1, out);
    }
    return;
  }

  let content = body;
  if (encoding === "base64") content = decodeBase64(body);
  else if (encoding === "quoted-printable") content = decodeQuotedPrintable(body);

  const filename = disposition.params.filename || type.params.name || "";
  const isAttachment = disposition.value === "attachment" || (filename && !type.value.startsWith("text/"));
  if (isAttachment || (!type.value.startsWith("text/") && !type.value.startsWith("message/"))) {
    out.attachments.push({ filename, contentType: type.value, size: content.length });
    if (IMAGE_TYPES.test(type.value) && content.length <= MAX_IMAGE_BYTES && out.images.length < MAX_IMAGES) {
      out.images.push({ filename, contentType: type.value, data: Uint8Array.from(content, (c) => c.charCodeAt(0)) });
    }
  } else if (type.value === "text/html") {
    out.html.push(decodeBytes(content, type.params.charset));
  } else if (type.value === "message/rfc822" && depth < MAX_DEPTH) {
    parsePart(content, depth + 1, out); // un correo reenviado como adjunto
  } else {
    out.text.push(decodeBytes(content, type.params.charset));
  }
}

/** Lee un correo completo. `input` es texto (pegado) o un Uint8Array (archivo). */
export function parseMessage(input) {
  const binary = typeof input === "string" ? textToBinary(input) : bytesToBinary(input);
  const [head] = splitMessage(binary);
  const headers = new Headers(parseHeaders(head));
  const out = { text: [], html: [], attachments: [], images: [] };
  parsePart(binary, 0, out);
  return { headers, text: out.text.join("\n"), html: out.html.join("\n"), attachments: out.attachments, images: out.images };
}

/** "Ana <a@x.es>, b@y.es" -> [{...}, {...}] */
export function parseAddressList(value) {
  return splitOutsideQuotes(value || "", ",")
    .map((part) => parseAddress(part.trim()))
    .filter((a) => a.address);
}

/** '"Soporte PayPal" <avisos@ejemplo.com>' -> { name: "Soporte PayPal", address: "avisos@ejemplo.com" } */
export function parseAddress(value) {
  if (!value) return { name: "", address: "", domain: "" };
  const angle = value.match(/<([^<>]*)>\s*$/);
  const address = (angle ? angle[1] : value.match(/[^\s<>"]+@[^\s<>"]+/)?.[0] ?? "").trim().toLowerCase();
  const name = angle ? value.slice(0, angle.index).trim().replace(/^"(.*)"$/, "$1").trim() : "";
  const domain = address.includes("@") ? address.split("@").pop() : "";
  return { name, address, domain };
}
