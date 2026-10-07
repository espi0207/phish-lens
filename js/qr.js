// Códigos QR dentro del correo (quishing): el QR esquiva los filtros que miran los enlaces y se
// abre desde el móvil, donde cuesta más ver adónde lleva. Se buscan en las imágenes adjuntas o
// incrustadas, se decodifican en local con jsQR y el destino pasa por las mismas comprobaciones
// que cualquier enlace. Las imágenes remotas (<img src="https://...">) no se descargan: pedirlas
// avisaría a quien envía de que has abierto el correo.

import { analyzeLink, rerate } from "./analyze.js";
import { htmlToText } from "./links.js";

const MAX_SIDE = 2000;
const MAX_IMAGES = 10;
const MAX_BYTES = 5 * 1024 * 1024;
const DATA_IMAGE = /<img\b[^>]*?\bsrc\s*=\s*["']data:(image\/(?:png|jpe?g|gif|bmp|webp));base64,([A-Za-z0-9+/=\s]+)["']/gi;
const SHORT_BODY = 300; // un correo que es casi solo una imagen

let jsQrReady = null;

function loadJsQr() {
  if (globalThis.jsQR) return Promise.resolve(globalThis.jsQR);
  jsQrReady ??= new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = new URL("./vendor/jsQR.js", import.meta.url).href;
    script.onload = () => resolve(globalThis.jsQR);
    script.onerror = () => reject(new Error("no se pudo cargar jsQR"));
    document.head.append(script);
  });
  return jsQrReady;
}

/** Decodifica una imagen con lo que trae el navegador (createImageBitmap) y jsQR. Devuelve el texto del QR o null. */
export async function decodeInBrowser({ data, contentType }) {
  const bitmap = await createImageBitmap(new Blob([data], { type: contentType }));
  const scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
  const width = Math.max(1, Math.round(bitmap.width * scale));
  const height = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = new OffscreenCanvas(width, height);
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.fillStyle = "#fff"; // un QR con fondo transparente se lee sobre blanco
  context.fillRect(0, 0, width, height);
  context.drawImage(bitmap, 0, 0, width, height);
  bitmap.close?.();
  const jsQR = await loadJsQr();
  return jsQR(context.getImageData(0, 0, width, height).data, width, height, { inversionAttempts: "attemptBoth" })?.data ?? null;
}

function imagesOf(message) {
  const images = (message.images ?? []).map(({ filename, contentType, data }) => ({ source: filename || "imagen adjunta", contentType, data }));
  for (const [, contentType, base64] of message.html.matchAll(DATA_IMAGE)) {
    try {
      const data = Uint8Array.from(atob(base64.replace(/\s/g, "")), (c) => c.charCodeAt(0));
      if (data.length <= MAX_BYTES) images.push({ source: "imagen del correo", contentType: contentType.toLowerCase(), data });
    } catch {
      // base64 roto: se ignora esa imagen.
    }
  }
  return images.slice(0, MAX_IMAGES);
}

/**
 * Busca códigos QR en las imágenes del correo. `decode` recibe { data, contentType } y devuelve el
 * texto del QR o null; en el navegador es decodeInBrowser. Una imagen que no se puede leer se salta.
 */
export async function scanQr(message, decode = decodeInBrowser) {
  const codes = [];
  for (const image of imagesOf(message)) {
    try {
      const text = await decode(image);
      if (text) codes.push({ source: image.source, text });
    } catch {
      // Formato que el navegador no sabe abrir: no hay QR que leer.
    }
  }
  const bodyLength = `${message.text}\n${htmlToText(message.html)}`.replace(/\s+/g, " ").trim().length;
  return { codes, onlyImage: bodyLength < SHORT_BODY };
}

const WHY = "Los códigos QR esquivan los filtros que revisan los enlaces y se abren desde el móvil, donde cuesta más ver adónde llevan.";

/** Mete lo que se ha leído de los QR en el resultado del análisis: hallazgos, enlaces y veredicto. */
export function applyQr(result, { codes, onlyImage }) {
  if (!codes.length) return result;
  const findings = [...result.findings];
  const links = [...result.links];
  const has = (title) => findings.some((f) => f.title === title);
  const seen = new Set(links.map((l) => l.href));

  for (const { source, text } of codes) {
    let url = null;
    try {
      url = new URL(text.trim());
    } catch {
      // No es una dirección: se cuenta más abajo.
    }
    if (url && /^https?:$/.test(url.protocol)) {
      const check = analyzeLink(url.href);
      if (!check) continue;
      const level = check.verdict.level;
      let severity = level === "peligro" ? "alta" : level === "sospechoso" ? "media" : "baja";
      if (onlyImage && severity === "baja") severity = "media";
      const reasons = check.findings.filter((f) => f.severity !== "ok");
      findings.push({
        severity,
        title: `El código QR de ${source} lleva a ${check.link.shown}`,
        detail: `${WHY}${reasons.length ? ` Destino: ${reasons.map((f) => f.title).join("; ")}.` : ""}${onlyImage ? " Además, el correo es casi solo la imagen." : ""}`,
      });
      for (const f of reasons) if (!has(f.title)) findings.push(f);
      if (!seen.has(check.link.href)) {
        seen.add(check.link.href);
        links.push({ ...check.link, text: `(código QR de ${source})` });
      }
    } else {
      const dangerous = url && /^(javascript|data):$/.test(url.protocol);
      findings.push({
        severity: dangerous ? "alta" : "baja",
        title: `El código QR de ${source} no es un enlace web`,
        detail: `Contiene: ${text.length > 80 ? `${text.slice(0, 80)}...` : text}. ${dangerous ? "Ejecuta código al abrirlo." : "Puede ser un teléfono, un SMS o una red wifi."}`,
      });
    }
  }
  return { ...rerate({ ...result, findings, links }), qr: codes };
}
