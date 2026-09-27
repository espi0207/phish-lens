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

const A_TAG = /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi;
const HREF = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;
const PLAIN_URL = /\bhttps?:\/\/[^\s<>"'()]+/gi;

/** Enlaces de la parte HTML: [{ href, text }] */
export function linksFromHtml(html) {
  const links = [];
  for (const [, attrs, inner] of html.matchAll(A_TAG)) {
    const m = attrs.match(HREF);
    if (!m) continue;
    const href = decodeEntities(m[1] ?? m[2] ?? m[3]).trim();
    if (!href || href.startsWith("#") || href.toLowerCase().startsWith("mailto:")) continue;
    links.push({ href, text: stripTags(inner) });
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
