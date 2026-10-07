// Lector de PNG mínimo para Node (sin dependencias): lo usan las pruebas y el análisis por
// carpetas para buscar códigos QR. En el navegador se usa createImageBitmap, que ya sabe leerlos.
// Admite profundidades de 1 a 8 bits en gris, RGB, paleta, gris con alfa y RGBA, sin entrelazado.

import { inflateSync } from "node:zlib";

const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

/** Devuelve { width, height, data } con data en RGBA (Uint8ClampedArray), o lanza un Error. */
export function decodePng(bytes) {
  const buf = Buffer.from(bytes);
  if (buf.length < 8 || !buf.subarray(0, 8).equals(SIGNATURE)) throw new Error("no es un PNG");
  let header = null;
  let palette = null;
  const idat = [];
  for (let pos = 8; pos + 8 <= buf.length; ) {
    const length = buf.readUInt32BE(pos);
    const type = buf.toString("latin1", pos + 4, pos + 8);
    const body = buf.subarray(pos + 8, pos + 8 + length);
    if (type === "IHDR") {
      header = { width: body.readUInt32BE(0), height: body.readUInt32BE(4), depth: body[8], color: body[9], interlace: body[12] };
    } else if (type === "PLTE") palette = body;
    else if (type === "IDAT") idat.push(body);
    else if (type === "IEND") break;
    pos += 12 + length;
  }
  if (!header || !idat.length) throw new Error("PNG incompleto");
  const { width, height, depth, color, interlace } = header;
  if (interlace) throw new Error("PNG entrelazado: no soportado");
  if (!CHANNELS[color] || ![1, 2, 4, 8].includes(depth)) throw new Error("tipo de PNG no soportado");
  if (width * height > 25_000_000) throw new Error("imagen demasiado grande");

  const bitsPerPixel = CHANNELS[color] * depth;
  const bytesPerPixel = Math.max(1, bitsPerPixel >> 3);
  const stride = Math.ceil((width * bitsPerPixel) / 8);
  const raw = inflateSync(Buffer.concat(idat));
  if (raw.length < (stride + 1) * height) throw new Error("PNG truncado");

  const rows = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    const src = y * (stride + 1) + 1;
    const dst = y * stride;
    for (let x = 0; x < stride; x++) {
      const left = x >= bytesPerPixel ? rows[dst + x - bytesPerPixel] : 0;
      const up = y ? rows[dst - stride + x] : 0;
      const upLeft = y && x >= bytesPerPixel ? rows[dst - stride + x - bytesPerPixel] : 0;
      const predictor = [0, left, up, (left + up) >> 1, paeth(left, up, upLeft)][filter];
      if (predictor === undefined) throw new Error("filtro de PNG desconocido");
      rows[dst + x] = (raw[src + x] + predictor) & 255;
    }
  }

  const sample = (y, index) => {
    if (depth === 8) return rows[y * stride + index];
    const bit = index * depth;
    return (rows[y * stride + (bit >> 3)] >> (8 - depth - (bit & 7))) & ((1 << depth) - 1);
  };
  const scale = depth === 8 ? 1 : 255 / ((1 << depth) - 1);
  const data = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const out = (y * width + x) * 4;
      let r, g, b, a = 255;
      if (color === 3) {
        const i = sample(y, x) * 3;
        [r, g, b] = [palette?.[i] ?? 0, palette?.[i + 1] ?? 0, palette?.[i + 2] ?? 0];
      } else if (color === 0 || color === 4) {
        r = g = b = sample(y, x * CHANNELS[color]) * scale;
        if (color === 4) a = sample(y, x * 2 + 1);
      } else {
        [r, g, b] = [sample(y, x * CHANNELS[color]), sample(y, x * CHANNELS[color] + 1), sample(y, x * CHANNELS[color] + 2)];
        if (color === 6) a = sample(y, x * 4 + 3);
      }
      // Sobre fondo blanco: un QR con transparencia se lee como se vería en el correo.
      const white = 255 - a;
      data.set([(r * a + 255 * white) / 255, (g * a + 255 * white) / 255, (b * a + 255 * white) / 255, 255], out);
    }
  }
  return { width, height, data };
}
