// Las comprobaciones. Cada una añade hallazgos con una gravedad; con eso se calcula una
// puntuación y un veredicto. Ninguna es definitiva por sí sola: es la suma lo que cuenta.

import {
  brandLabel,
  brandsMentioned,
  BRANDS,
  defang,
  isBrandDomain,
  isIpAddress,
  lookalikeReason,
  registrableDomain,
  toUnicode,
} from "./domains.js";
import { htmlToText, linksFromHtml, linksFromText } from "./links.js";
import { parseAddress, parseAddressList } from "./mail.js";

export const WEIGHT = { alta: 30, media: 12, baja: 4, info: 0, ok: 0 };

const FREE_MAIL = new Set([
  "gmail.com", "googlemail.com", "hotmail.com", "hotmail.es", "outlook.com", "outlook.es", "live.com",
  "yahoo.com", "yahoo.es", "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com", "gmx.es",
  "aol.com", "mail.ru", "yandex.ru", "zoho.com",
]);
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "buff.ly", "shorturl.at",
  "rb.gy", "tiny.cc", "s.id", "t.ly", "goo.su",
]);
// Extensiones que se ejecutan al abrirlas, o que sirven para colar algo que sí se ejecuta.
const DANGEROUS = {
  ejecutable: ["exe", "scr", "com", "pif", "bat", "cmd", "msi", "cpl", "jar", "reg", "hta", "lnk", "xll"],
  script: ["js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1"],
  "página web": ["html", "htm", "shtml", "svg", "xhtml"],
  "documento con macros": ["docm", "xlsm", "pptm", "dotm", "xlam"],
  "imagen de disco": ["iso", "img", "vhd", "vhdx"],
  "bloc de OneNote": ["one"],
};
const ARCHIVES = ["zip", "rar", "7z", "gz", "tar", "cab", "ace"];
const DOCUMENT_LOOK = ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "mp3", "mp4"];

// Frases típicas: urgencia, amenazas y peticiones de datos. Se comparan sin tildes ni mayúsculas.
const PHRASES = [
  "verifique su cuenta", "verifica tu cuenta", "confirme sus datos", "confirma tus datos",
  "actualice sus datos", "actualiza tus datos", "cuenta ha sido suspendida", "cuenta ha sido bloqueada",
  "cuenta bloqueada", "acceso restringido", "actividad inusual", "actividad sospechosa", "urgente",
  "inmediatamente", "24 horas", "48 horas", "haga clic", "haz clic", "pulse aquí", "pulsa aquí",
  "introduzca su contraseña", "usuario y contraseña", "su contraseña", "datos bancarios", "tarjeta de crédito",
  "reembolso", "paquete retenido", "pago pendiente", "factura pendiente", "tasas de aduana", "no puedo hablar",
  "es confidencial", "multa pendiente", "multa pendent", "paquet retingut", "compte bloquejat",
  "verifiqui el seu compte", "confirmi les seves dades", "pagament pendent", "devolucio pendent", "devolucion pendiente",
  "verify your account", "confirm your identity", "account has been suspended",
  "unusual activity", "urgent", "immediately", "within 24 hours", "click here", "wire transfer", "gift card",
];

function normalize(text) {
  return text.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
}

function extension(name, fromEnd = 1) {
  const parts = name.toLowerCase().split(".");
  return parts.length > fromEnd ? parts[parts.length - fromEnd] : "";
}

/** Authentication-Results de arriba del todo: el que ha puesto tu proveedor al recibirlo.
 * Los de más abajo los puede haber escrito cualquiera, incluido el propio atacante. */
export function parseAuthResults(headers) {
  const result = { spf: null, dkim: null, dmarc: null, domains: {}, found: false };
  const header = headers.get("authentication-results");
  if (header) {
    result.found = true;
    const clean = header.replace(/\([^)]*\)/g, " ");
    for (const part of clean.split(";").slice(1)) {
      const m = part.trim().match(/^(spf|dkim|dmarc)\s*=\s*([a-z]+)(.*)$/i);
      if (!m) continue;
      const [, method, value, props] = m;
      const key = method.toLowerCase();
      // Puede haber varias firmas DKIM: con que una sea válida basta.
      if (result[key] === null || (key === "dkim" && value.toLowerCase() === "pass")) {
        result[key] = value.toLowerCase();
        const domain = props.match(/(?:header\.from|header\.d|header\.i|smtp\.mailfrom)=@?([^\s;]+)/i);
        if (domain) result.domains[key] = domain[1].toLowerCase().replace(/^.*@/, "");
      }
    }
  }
  const received = headers.get("received-spf");
  if (result.spf === null && received) {
    result.found = true;
    result.spf = received.trim().split(/\s/)[0].toLowerCase();
  }
  return result;
}

/** Los saltos de Received, del primero (el servidor que lo envió) al último (tu buzón). */
export function parseReceived(values) {
  return values
    .map((value) => {
      const semicolon = value.lastIndexOf(";");
      const date = semicolon >= 0 ? new Date(value.slice(semicolon + 1).replace(/\([^)]*\)/g, "").trim()) : null;
      return {
        from: value.match(/\bfrom\s+([^\s;()]+)/i)?.[1] ?? "",
        by: value.match(/\bby\s+([^\s;()]+)/i)?.[1] ?? "",
        ip: value.match(/\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,})\]/i)?.[1] ?? "",
        date: date && !isNaN(date) ? date : null,
      };
    })
    .reverse();
}

function checkAuthentication(auth, from, add) {
  if (!auth.found) {
    add("info", "El correo no trae resultados de SPF, DKIM ni DMARC",
      "Puede que solo hayas pegado parte de las cabeceras, o que tu proveedor no las añada.");
    return;
  }
  const { spf, dkim, dmarc } = auth;
  if (dmarc === "fail") {
    add("alta", "DMARC ha fallado",
      `El dominio ${from.domain || "del remitente"} publica una política que este correo no cumple: lo más probable es que alguien use ese dominio sin permiso.`);
  }
  if (spf === "fail") add("alta", "SPF ha fallado", "El servidor que lo envió no está autorizado a mandar correo de ese dominio.");
  else if (spf === "softfail") add("media", "SPF dudoso (softfail)", "El dominio dice que ese servidor probablemente no debería enviar su correo.");
  else if (spf === "none" || spf === "neutral") add("baja", `SPF: ${spf}`, "El dominio no dice qué servidores pueden enviar su correo.");
  if (dkim === "fail") add("media", "La firma DKIM no es válida", "El correo se ha modificado por el camino o la firma es falsa.");
  else if (dkim === "none" || dkim === null) add("baja", "Sin firma DKIM", "No hay forma de comprobar que el contenido no se ha cambiado.");

  if (spf === "pass" && (dkim === "pass" || dmarc === "pass") && dmarc !== "fail") {
    add("ok", `SPF${dkim === "pass" ? ", DKIM" : ""}${dmarc === "pass" ? " y DMARC" : ""} correctos`,
      `El correo viene de verdad de ${auth.domains.dmarc || auth.domains.dkim || from.domain}. Ojo: eso no quiere decir que ese dominio sea de fiar; un estafador con su propio dominio también pasa estas pruebas.`);
  }
}

function checkSender(from, replyTo, returnPath, recipientDomains, add) {
  if (!from.address) {
    add("media", "No se entiende quién lo envía", "La cabecera From está vacía o mal formada.");
    return;
  }
  const displayed = from.name.match(/[^\s<>"]+@[^\s<>"]+\.[a-z]{2,}/i)?.[0]?.toLowerCase();
  if (displayed && displayed !== from.address) {
    add("alta", "El nombre visible es otra dirección de correo",
      `Se muestra "${displayed}", pero la dirección real es ${from.address}. Es un truco para que en el móvil solo se vea la falsa.`);
  }
  for (const brand of brandsMentioned(from.name)) {
    if (!isBrandDomain(brand, from.domain)) {
      const official = BRANDS[brand];
      add("alta", `Se hace pasar por ${brandLabel(brand)}`,
        `El nombre dice "${from.name}", pero la dirección es ${from.address}. El correo de ${brandLabel(brand)} ` +
          `sale de ${official.length > 1 ? official.slice(0, -1).join(", ") + " o " + official.at(-1) : official[0]}.`);
    }
  }
  const lookalike = lookalikeReason(from.domain, recipientDomains);
  if (lookalike) add("alta", "El dominio del remitente imita a otro", lookalike);
  if (FREE_MAIL.has(registrableDomain(from.domain)) && brandsMentioned(from.name).length === 0) {
    add("info", "Escrito desde un correo gratuito", `${from.domain}: normal en particulares, raro en empresas y bancos.`);
  }
  if (replyTo.address && registrableDomain(replyTo.domain) !== registrableDomain(from.domain)) {
    const free = FREE_MAIL.has(registrableDomain(replyTo.domain));
    add(free ? "alta" : "media", "Las respuestas irían a otra dirección",
      `Si contestas, el mensaje va a ${replyTo.address} y no a ${from.address}${free ? ", que es un correo gratuito" : ""}.`);
  }
  if (returnPath.domain && registrableDomain(returnPath.domain) !== registrableDomain(from.domain)) {
    add("info", "El sobre del correo es de otro dominio",
      `Return-Path: ${returnPath.address}. Es normal si una empresa envía con un servicio externo (Mailchimp, SendGrid...).`);
  }
}

function checkLinks(links, recipientDomains, add) {
  const reported = new Set();
  const once = (key, ...args) => {
    if (!reported.has(key)) {
      reported.add(key);
      add(...args);
    }
  };
  const results = [];
  for (const { href, text } of links) {
    let url;
    try {
      url = new URL(href);
    } catch {
      continue;
    }
    const host = url.hostname.toLowerCase();
    const shown = defang(url.href);
    const problems = [];
    if (url.protocol === "javascript:" || url.protocol === "data:") {
      problems.push("ejecuta código o contiene una página entera");
      once(`proto:${url.protocol}`, "alta", `Enlace de tipo ${url.protocol}`, `Un enlace así no lleva a una web: ejecuta código o carga una página escondida dentro del propio correo.`);
    }
    if (!host) continue;
    if (url.username || url.password) {
      problems.push("truco de la @");
      once(`at:${host}`, "alta", "Enlace con una @ para engañar",
        `En ${shown} todo lo que va antes de la @ se ignora: el enlace lleva en realidad a ${toUnicode(host)}.`);
    }
    if (isIpAddress(host)) {
      problems.push("es una IP");
      once(`ip:${host}`, "alta", "Enlace a una dirección IP", `${shown}: las empresas de verdad usan su dominio, no una IP.`);
    }
    const lookalike = lookalikeReason(host, recipientDomains);
    if (lookalike) {
      problems.push("dominio que imita a otro");
      once(`look:${registrableDomain(host)}`, "alta", "Un enlace lleva a un dominio que imita a otro", lookalike);
    }
    const textDomain = text.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i)?.[1]?.toLowerCase();
    if (textDomain && registrableDomain(textDomain) !== registrableDomain(host)) {
      problems.push(`dice ${textDomain}`);
      once(`text:${textDomain}:${host}`, "alta", "El texto de un enlace no coincide con su destino",
        `Se lee "${text}" pero lleva a ${shown}.`);
    }
    if (SHORTENERS.has(registrableDomain(host)) || SHORTENERS.has(host)) {
      problems.push("acortador");
      once(`short:${host}`, "media", "Enlace acortado", `${shown} esconde el destino real detrás de un acortador.`);
    } else if (url.protocol === "http:") {
      problems.push("sin HTTPS");
    }
    results.push({ href, shown, text, host: toUnicode(host), problems });
  }
  return results;
}

function checkAttachments(attachments, add) {
  return attachments.map((att) => {
    const name = att.filename || "(sin nombre)";
    const problems = [];
    const ext = extension(name);
    const kind = Object.entries(DANGEROUS).find(([, list]) => list.includes(ext))?.[0];
    if (/[‪-‮⁦-⁩]/.test(name)) {
      problems.push("nombre dado la vuelta");
      add("alta", "Adjunto con el nombre dado la vuelta",
        `"${name}" usa un carácter invisible que invierte el texto para esconder la extensión real.`);
    }
    if (kind) {
      problems.push(kind);
      const double = DOCUMENT_LOOK.includes(extension(name, 2));
      add("alta", double ? `Adjunto con doble extensión: ${name}` : `Adjunto peligroso: ${name}`,
        double
          ? `Parece un .${extension(name, 2)}, pero en realidad es ${kind === "página web" ? "una" : "un"} ${kind} (.${ext}).`
          : `Es ${kind === "página web" ? "una" : "un"} ${kind} (.${ext}).` +
              (kind === "página web" ? " Suelen ser formularios de login falsos que funcionan sin conexión." : ""));
    } else if (ARCHIVES.includes(ext)) {
      problems.push("comprimido");
      add("baja", `Adjunto comprimido: ${name}`, "Un comprimido puede llevar dentro un ejecutable que el antivirus del correo no ve.");
    }
    return { ...att, name, problems };
  });
}

function checkContent(subject, body, add) {
  const text = normalize(`${subject}\n${body}`);
  const found = PHRASES.filter((p) => new RegExp(`\\b${normalize(p)}\\b`).test(text));
  const quoted = found.map((f) => `"${f}"`).join(", ");
  if (found.length >= 3) {
    // Tres o más a la vez (prisa + secreto + "no puedo hablar"...) es la receta de manual.
    add("alta", "Presiona como un estafador", `Junta varias frases típicas de phishing: ${quoted}.`);
  } else if (found.length === 2) {
    add("media", "Mete prisa o pide datos", `Frases típicas de phishing: ${quoted}.`);
  } else if (found.length === 1) {
    add("baja", "Alguna frase típica de phishing", `"${found[0]}"`);
  }
}

function checkHops(hops, add) {
  if (!hops.length) {
    add("info", "Sin cabeceras Received", "No se puede ver por qué servidores ha pasado (¿has pegado solo el cuerpo?).");
    return;
  }
  for (let i = 1; i < hops.length; i++) {
    const [a, b] = [hops[i - 1].date, hops[i].date];
    if (a && b && b - a < -5 * 60 * 1000) {
      add("baja", "Las fechas del recorrido no cuadran",
        "Un servidor dice haber recibido el correo antes que el anterior: alguna cabecera Received puede estar inventada.");
      return;
    }
  }
}

export function analyze(message, now = new Date()) {
  const findings = [];
  const add = (severity, title, detail) => findings.push({ severity, title, detail });

  const h = message.headers;
  const from = parseAddress(h.get("from"));
  const replyTo = parseAddress(h.get("reply-to"));
  const returnPath = parseAddress(h.get("return-path"));
  const to = parseAddressList([h.get("to"), h.get("cc"), h.get("delivered-to")].filter(Boolean).join(", "));
  const recipientDomains = [...new Set(to.map((a) => registrableDomain(a.domain)))].filter((d) => d && !FREE_MAIL.has(d));
  const subject = h.get("subject");
  const date = h.get("date") ? new Date(h.get("date")) : null;
  const auth = parseAuthResults(h);
  const hops = parseReceived(h.getAll("received"));
  const body = [message.text, htmlToText(message.html)].join("\n");
  // El mismo enlace suele venir en la parte de texto y en la HTML: se queda el que tenga texto visible.
  const byHref = new Map();
  for (const link of [...linksFromHtml(message.html), ...linksFromText(message.text)]) {
    if (!byHref.has(link.href) || (!byHref.get(link.href).text && link.text)) byHref.set(link.href, link);
  }
  const unique = [...byHref.values()];

  checkAuthentication(auth, from, add);
  checkSender(from, replyTo, returnPath, recipientDomains, add);
  const links = checkLinks(unique, recipientDomains, add);
  const attachments = checkAttachments(message.attachments, add);
  checkContent(subject, body, add);
  checkHops(hops, add);
  if (date && !isNaN(date) && date - now > 24 * 3600 * 1000) {
    add("baja", "La fecha del correo está en el futuro", "La cabecera Date la pone quien envía: puede ser cualquier cosa.");
  }

  const { score, verdict } = rate(findings, {
    peligro: "Muy probablemente es phishing",
    sospechoso: "Sospechoso: revísalo con cuidado",
    limpio: "No veo señales claras de phishing",
  });
  return {
    from, replyTo, returnPath, to, subject,
    date: date && !isNaN(date) ? date : null,
    auth, hops, links, attachments, findings, score, verdict,
  };
}

/** Ordena los hallazgos (los graves primero) y saca la puntuación y el veredicto. */
function rate(findings, texts, scale = 1) {
  const order = { alta: 0, media: 1, baja: 2, info: 3, ok: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const score = Math.min(100, Math.round(scale * findings.reduce((sum, f) => sum + WEIGHT[f.severity], 0)));
  const level = score >= 50 ? "peligro" : score >= 20 ? "sospechoso" : "limpio";
  return { score, verdict: { level, text: texts[level] } };
}

/**
 * Un enlace suelto, sin el correo alrededor: el del clic derecho de la extensión o el que
 * alguien pega en la página. Pasa por las mismas comprobaciones que los enlaces de un correo.
 */
export function analyzeLink(href) {
  const findings = [];
  const add = (severity, title, detail) => findings.push({ severity, title, detail });
  const [link] = checkLinks([{ href: String(href).trim(), text: "" }], [], add);
  if (!link) return null; // no es una URL
  if (link.problems.includes("sin HTTPS")) {
    add("baja", "Sin HTTPS", `${link.shown}: lo que escribas en esa página viaja sin cifrar.`);
  }
  // En un correo las señales se van sumando; en un enlace suelto, una sola grave (un dominio
  // que imita a otro, una IP...) ya basta. Con esta escala una "alta" llega a peligro (50) y
  // una "media" a sospechoso (20).
  const { score, verdict } = rate(
    findings,
    {
      peligro: "Muy probablemente es un enlace trampa",
      sospechoso: "Sospechoso: mejor no lo abras",
      limpio: "No veo señales claras de engaño",
    },
    5 / 3,
  );
  return { link, findings, score, verdict };
}
