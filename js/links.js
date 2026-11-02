// Sacar los enlaces del HTML de un correo sin llegar a mostrarlo nunca.
//
// Podría usar DOMParser, pero así el mismo código funciona en Node (para las pruebas) y
// no hay ninguna posibilidad de que el HTML del correo acabe interpretándose en la página.

// Las entidades con nombre que más salen en correos en español (el resto van en &#NNN;).
const ENTITIES = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", euro: "€", copy: "©", reg: "®",
  trade: "™", laquo: "«", raquo: "»", iexcl: "¡", iquest: "¿", ordm: "º", ordf: "ª", middot: "·",
  hellip: "…", mdash: "—", ndash: "–", lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”", bull: "•",
  aacute: "á", eacute: "é", iacute: "í", oacute: "ó", uacute: "ú", ntilde: "ñ", uuml: "ü", ccedil: "ç",
  Aacute: "Á", Eacute: "É", Iacute: "Í", Oacute: "Ó", Uacute: "Ú", Ntilde: "Ñ", Uuml: "Ü", Ccedil: "Ç",
  agrave: "à", egrave: "è", ograve: "ò",
};

export function decodeEntities(text) {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, code) => {
    if (code[0] === "#") {
      const n = code[1].toLowerCase() === "x" ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
      return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : whole;
    }
    return ENTITIES[code] ?? ENTITIES[code.toLowerCase()] ?? whole; // &Ntilde; distingue mayúsculas
  });
}

function stripTags(html) {
  return decodeEntities(html.replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
}

const PLAIN_URL = /\bhttps?:\/\/[^\s<>"'()]+/gi;
// Dónde empieza una <a> y dónde se acaba su texto: en el </a> o en la <a> siguiente (como
// hace el navegador con un enlace sin cerrar).
const A_START = /<a(?=[\s/>])/gi;
const A_END = /<\/a\s*>|<a(?=[\s/>])/gi;
// Un atributo: nombre y, si tiene, valor entre comillas dobles, simples o sin comillas.
const ATTR = /([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

/** Dónde se cierra la etiqueta que empieza en `from`: el primer > que no va entre comillas. */
function tagEnd(html, from) {
  let quote = "";
  for (let i = from; i < html.length; i++) {
    const c = html[i];
    if (quote) {
      if (c === quote) quote = "";
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === ">") {
      return i;
    }
  }
  return -1;
}

/** El valor del atributo href (el primero, como el navegador), o null. */
function hrefOf(attrs) {
  for (const [, name, dq, sq, bare] of attrs.matchAll(ATTR)) {
    if (name.toLowerCase() === "href") return dq ?? sq ?? bare ?? "";
  }
  return null;
}

/**
 * Enlaces de la parte HTML: [{ href, text }]
 *
 * De una sola pasada y leyendo los atributos de verdad. Antes era una expresión regular:
 * «\bhref» también encajaba con «data-href» (el atacante pone ahí el enlace bueno y en
 * href el malo), un «>» entre comillas cortaba la etiqueta, un enlace sin cerrar no
 * contaba y muchas <a> sin cerrar tardaban en proporción al cuadrado del tamaño.
 */
export function linksFromHtml(html) {
  const links = [];
  A_START.lastIndex = 0;
  let start;
  while ((start = A_START.exec(html))) {
    const close = tagEnd(html, start.index + 2);
    if (close < 0) break;
    A_END.lastIndex = close + 1;
    const end = A_END.exec(html);
    const innerEnd = end ? end.index : html.length;
    // La siguiente búsqueda sigue donde acaba esta: si acaba en otra <a>, esa es la siguiente.
    A_START.lastIndex = end && end[0][1] !== "/" ? end.index : end ? A_END.lastIndex : html.length;
    const raw = hrefOf(html.slice(start.index + 2, close));
    if (raw === null) continue;
    const href = decodeEntities(raw).trim();
    if (!href || href.startsWith("#") || href.toLowerCase().startsWith("mailto:")) continue;
    links.push({ href, text: stripTags(html.slice(close + 1, innerEnd)) });
  }
  return links;
}

/** URLs escritas tal cual en el texto plano. */
export function linksFromText(text) {
  return [...text.matchAll(PLAIN_URL)].map(([url]) => ({ href: url.replace(/[.,;:!?]+$/, ""), text: "" }));
}

/** Texto del HTML sin etiquetas, para buscar frases típicas de phishing. */
export function htmlToText(html) {
  return stripTags(html.replace(/<(style|script)\b[\s\S]*?<\/\1\s*>/gi, " "));
}
