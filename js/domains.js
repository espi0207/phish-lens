// Todo lo relacionado con dominios: punycode, dominios que se parecen a otros y marcas.

// Punycode (RFC 3492). El navegador convierte "pаypal.com" (con una "а" cirílica) en
// "xn--pypal-4ve.com", pero no trae nada para volver a enseñarlo como lo vería la víctima.
const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta, points, first) {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / points);
  let k = 0;
  while (delta > ((BASE - T_MIN) * T_MAX) >> 1) {
    delta = Math.floor(delta / (BASE - T_MIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - T_MIN + 1) * delta) / (delta + SKEW));
}

function digitOf(code) {
  if (code >= 48 && code <= 57) return code - 22; // 0-9 -> 26-35
  if (code >= 65 && code <= 90) return code - 65; // A-Z
  if (code >= 97 && code <= 122) return code - 97; // a-z
  throw new Error("carácter no válido en punycode");
}

export function decodePunycodeLabel(input) {
  const output = [];
  const dash = input.lastIndexOf("-");
  for (let j = 0; j < Math.max(dash, 0); j++) output.push(input.charCodeAt(j));
  let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
  for (let pos = dash > 0 ? dash + 1 : 0; pos < input.length; ) {
    const oldI = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= input.length) throw new Error("punycode incompleto");
      const digit = digitOf(input.charCodeAt(pos++));
      i += digit * w;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldI, output.length + 1, oldI === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    if (n > 0x10ffff) throw new Error("punycode fuera de rango");
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** "xn--pypal-4ve.com" -> "pаypal.com". Lo que no sea punycode válido se deja como está. */
export function toUnicode(host) {
  return host
    .split(".")
    .map((label) => {
      if (!label.toLowerCase().startsWith("xn--")) return label;
      try {
        return decodePunycodeLabel(label.slice(4));
      } catch {
        return label;
      }
    })
    .join(".");
}

// Sufijos de dos partes habituales. Lo exacto sería la Public Suffix List, pero pesa
// mucho para esta página y con estos se cubren los casos que más se ven.
const TWO_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.es", "org.es", "gob.es", "nom.es", "edu.es",
  "com.mx", "gob.mx", "com.ar", "gob.ar", "com.br", "gov.br", "com.co", "com.pe", "cl.cl",
  "co.jp", "com.au", "co.nz", "co.in", "com.tr", "com.cn",
]);

/** El dominio "registrado": "login.cuenta.paypal.com" -> "paypal.com", "www.bbc.co.uk" -> "bbc.co.uk". */
export function registrableDomain(host) {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return TWO_PART_SUFFIXES.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

/** La parte que identifica a la organización: "paypal" en "paypal.com", "bbc" en "bbc.co.uk". */
export function mainLabel(host) {
  return registrableDomain(host).split(".")[0];
}

export function isIpAddress(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
}

// Caracteres que se confunden con letras latinas (una selección de la lista de
// "confusables" de Unicode) y trucos ASCII clásicos (0 por o, rn por m...).
const CONFUSABLES = {
  а: "a", е: "e", ё: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ї: "i", ј: "j",
  ѕ: "s", ԁ: "d", ԛ: "q", ԝ: "w", һ: "h", ӏ: "l", ɡ: "g", ı: "i",
  α: "a", ο: "o", ν: "v", ρ: "p", ι: "i", κ: "k", υ: "u", χ: "x", ε: "e", τ: "t",
  0: "o", 1: "l", 3: "e", 5: "s", "@": "a", "$": "s",
};

/** Una versión "normalizada" de una etiqueta: dos dominios con el mismo esqueleto se ven casi igual. */
export function skeleton(label) {
  const mapped = [...label.normalize("NFKC").toLowerCase()].map((c) => CONFUSABLES[c] ?? c).join("");
  return mapped.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d").replace(/-/g, "");
}

export function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 99; // solo interesan distancias pequeñas
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const row = [i];
    for (let j = 1; j <= b.length; j++) {
      row[j] = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = row;
  }
  return prev[b.length];
}

/** Mezcla de alfabetos en una etiqueta: latino con cirílico o griego. Nadie registra eso sin mala intención. */
export function mixedScripts(label) {
  const latin = /[a-z]/i.test(label);
  const cyrillic = /[Ѐ-ӿ]/.test(label);
  const greek = /[Ͱ-Ͽ]/.test(label);
  return (latin && (cyrillic || greek)) || (cyrillic && greek);
}

// Marcas que se suplantan a menudo (muchas españolas) y sus dominios de verdad.
export const BRANDS = {
  paypal: ["paypal.com", "paypal.es", "paypal.me"],
  amazon: ["amazon.com", "amazon.es", "amazon.co.uk", "amazonaws.com"],
  microsoft: ["microsoft.com", "outlook.com", "office.com", "live.com", "office365.com", "microsoftonline.com"],
  outlook: ["outlook.com", "live.com", "microsoft.com"],
  office365: ["office365.com", "office.com", "microsoft.com"],
  apple: ["apple.com", "icloud.com"],
  icloud: ["icloud.com", "apple.com"],
  google: ["google.com", "gmail.com", "google.es"],
  netflix: ["netflix.com"],
  facebook: ["facebook.com", "facebookmail.com", "meta.com"],
  instagram: ["instagram.com", "facebookmail.com"],
  whatsapp: ["whatsapp.com"],
  linkedin: ["linkedin.com"],
  dropbox: ["dropbox.com"],
  docusign: ["docusign.com", "docusign.net"],
  bbva: ["bbva.es", "bbva.com"],
  santander: ["bancosantander.es", "santander.com", "santander.es"],
  caixabank: ["caixabank.es", "caixabank.com"],
  sabadell: ["bancsabadell.com"],
  openbank: ["openbank.es"],
  bankinter: ["bankinter.com"],
  unicaja: ["unicajabanco.es"],
  correos: ["correos.es", "correos.com"],
  seur: ["seur.com"],
  dhl: ["dhl.com", "dhl.es"],
  mrw: ["mrw.es"],
  ups: ["ups.com"],
  movistar: ["movistar.es", "telefonica.es"],
  vodafone: ["vodafone.es", "vodafone.com"],
  iberdrola: ["iberdrola.es"],
  endesa: ["endesa.com", "endesaclientes.com"],
  agenciatributaria: ["agenciatributaria.es", "agenciatributaria.gob.es"],
  coinbase: ["coinbase.com"],
  binance: ["binance.com"],
};
// Nombres con los que aparecen en el nombre visible del remitente.
const BRAND_NAMES = {
  paypal: /\bpaypal\b/i,
  amazon: /\bamazon\b/i,
  microsoft: /\bmicrosoft\b/i,
  outlook: /\boutlook\b/i,
  office365: /\boffice ?365\b/i,
  apple: /\bapple\b/i,
  icloud: /\bicloud\b/i,
  google: /\bgoogle\b/i,
  netflix: /\bnetflix\b/i,
  facebook: /\bfacebook\b/i,
  instagram: /\binstagram\b/i,
  whatsapp: /\bwhatsapp\b/i,
  linkedin: /\blinkedin\b/i,
  dropbox: /\bdropbox\b/i,
  docusign: /\bdocusign\b/i,
  bbva: /\bbbva\b/i,
  santander: /\bsantander\b/i,
  caixabank: /\bcaixa ?bank\b/i,
  sabadell: /\bsabadell\b/i,
  openbank: /\bopenbank\b/i,
  bankinter: /\bbankinter\b/i,
  unicaja: /\bunicaja\b/i,
  correos: /\bcorreos\b/i,
  seur: /\bseur\b/i,
  dhl: /\bdhl\b/i,
  mrw: /\bmrw\b/i,
  ups: /\bUPS\b/, // solo en mayúsculas: "ups" en minúsculas es una interjección
  movistar: /\bmovistar\b/i,
  vodafone: /\bvodafone\b/i,
  iberdrola: /\biberdrola\b/i,
  endesa: /\bendesa\b/i,
  agenciatributaria: /\b(agencia tributaria|hacienda|aeat)\b/i,
  coinbase: /\bcoinbase\b/i,
  binance: /\bbinance\b/i,
};

const LABELS = {
  paypal: "PayPal", bbva: "BBVA", caixabank: "CaixaBank", agenciatributaria: "la Agencia Tributaria",
  dhl: "DHL", mrw: "MRW", ups: "UPS", icloud: "iCloud", linkedin: "LinkedIn", whatsapp: "WhatsApp",
  docusign: "DocuSign", office365: "Office 365", seur: "SEUR",
};

/** Cómo se escribe la marca: "PayPal", "BBVA", "Correos"... */
export function brandLabel(brand) {
  return LABELS[brand] ?? brand[0].toUpperCase() + brand.slice(1);
}

export function isBrandDomain(brand, host) {
  const reg = registrableDomain(host);
  return BRANDS[brand].includes(reg);
}

/** Marcas que se nombran en un texto (el nombre visible del remitente, por ejemplo). */
export function brandsMentioned(text) {
  return Object.keys(BRAND_NAMES).filter((brand) => BRAND_NAMES[brand].test(text));
}

// Palabras normales a una letra de una marca: "finance" no es un intento de parecer "binance".
const COMMON_WORDS = new Set(["finance", "correo", "correu", "amazing", "applet"]);

/**
 * ¿Este dominio intenta pasar por otro? Devuelve una explicación o null.
 * `targets` es una lista de dominios legítimos con los que compararlo (además de las marcas).
 */
export function lookalikeReason(host, targets = []) {
  const unicode = toUnicode(host.toLowerCase());
  const reg = registrableDomain(unicode);
  const label = reg.split(".")[0];

  if (mixedScripts(label)) {
    return `"${unicode}" mezcla letras latinas con otros alfabetos para parecer otro dominio`;
  }
  const candidates = [
    ...Object.entries(BRANDS).map(([brand, domains]) => ({ name: brand, domains })),
    ...targets.map((d) => ({ name: mainLabel(d), domains: [registrableDomain(d)] })),
  ];
  for (const { name, domains } of candidates) {
    if (domains.includes(reg)) return null; // es el de verdad
  }
  for (const { name, domains } of candidates) {
    const original = domains[0];
    if (label === name) continue; // mismo nombre con otra terminación: lo trata otra comprobación
    if (skeleton(label) === skeleton(name)) {
      return `"${unicode}" se escribe casi igual que ${original}`;
    }
    const limit = name.length >= 9 ? 2 : name.length >= 6 ? 1 : 0;
    if (limit && !COMMON_WORDS.has(label) && levenshtein(label, name) <= limit) {
      return `"${unicode}" se parece mucho a ${original} (cambia ${levenshtein(label, name)} letra(s))`;
    }
  }
  // La marca metida en un dominio que no es suyo: paypal.com.cuenta-segura.example,
  // correos-envios.example...
  const tokens = unicode.split(/[.-]/);
  for (const { name, domains } of candidates) {
    if (name.length >= 4 && tokens.includes(name) && !domains.includes(reg)) {
      return reg === unicode
        ? `"${unicode}" usa el nombre "${name}", pero no es ${domains[0]}`
        : `"${unicode}" usa el nombre "${name}", pero el dominio de verdad es ${reg}, no ${domains[0]}`;
    }
  }
  return null;
}

/** Enseñar una URL sin que se pueda pinchar por error: hxxps://ejemplo[.]com/... */
export function defang(url) {
  return url.replace(/^http/i, "hxxp").replace(/^(hxxps?:\/\/[^/]+)/i, (host) => host.replace(/\./g, "[.]"));
}
