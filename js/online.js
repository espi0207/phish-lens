// Las comprobaciones que necesitan red, solo en modo completo. Nunca se envía el correo: solo
// dominios (edad, DNS, lista negra) y, en la extensión, el acortador que se quiere seguir.
// Cada consulta que falla se cuenta como "no se pudo comprobar", nunca como bueno ni como malo.

import { analyzeLink, FREE_MAIL, isShortener, rerate } from "./analyze.js";
import { BRANDS, defang, isIpAddress, registrableDomain } from "./domains.js";

const DAY = 24 * 3600 * 1000;
const TIMEOUT = 6000;
const MAX_DOMAINS = 10;
const MAX_SHORTENERS = 5;
const DOH = "https://cloudflare-dns.com/dns-query";
const DOH_SECURITY = "https://security.cloudflare-dns.com/dns-query";
const RDAP = "https://rdap.org/domain/";
const RECORD = { A: 1, TXT: 16 };
const OFFICIAL = new Set(Object.values(BRANDS).flat());

const sharedCache = new Map();

async function request(fetchFn, url, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT);
  try {
    return await fetchFn(url, { credentials: "omit", ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function getJson(fetchFn, url, accept) {
  const response = await request(fetchFn, url, { headers: { accept } });
  if (!response.ok) throw Object.assign(new Error(`HTTP ${response.status}`), { status: response.status });
  return response.json();
}

/** Una consulta DNS por HTTPS. `status` 3 es que el dominio no existe. */
export async function dnsQuery(name, type, fetchFn, endpoint = DOH) {
  const json = await getJson(fetchFn, `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`, "application/dns-json");
  const answers = (json.Answer ?? []).filter((a) => a.type === RECORD[type]).map((a) => a.data);
  return { status: json.Status, answers };
}

/** Un TXT llega en trozos entrecomillados ("v=DMARC1;" "p=reject;"): se pegan. */
function joinTxt(data) {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
  return parts.length ? parts.join("") : data;
}

/** Cuándo se registró el dominio, o null si el registro no lo dice. */
export async function registrationDate(domain, fetchFn) {
  let json;
  try {
    json = await getJson(fetchFn, RDAP + domain, "application/rdap+json");
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
  const event = json.events?.find((e) => e.eventAction === "registration");
  const date = event ? new Date(event.eventDate) : null;
  return date && !isNaN(date) ? date : null;
}

function ageFinding(domain, registered, now) {
  const days = Math.floor((now - registered) / DAY);
  if (days < 0 || days >= 90) return null;
  const when = days === 0 ? "hace menos de un día" : days === 1 ? "hace 1 día" : `hace ${days} días`;
  const severity = days < 7 ? "alta" : days < 30 ? "media" : "baja";
  return {
    severity,
    title: `Dominio registrado ${when}: ${domain}`,
    detail: "Los dominios de phishing suelen tener pocos días de vida; las empresas de verdad llevan años con el suyo.",
  };
}

/** SPF y DMARC leídos del DNS, para no fiarse solo de lo que dice la cabecera del correo. */
export async function checkAuthDns(domain, auth, fetchFn) {
  const findings = [];
  const org = registrableDomain(domain);
  const [txt, dmarcExact] = await Promise.all([
    dnsQuery(domain, "TXT", fetchFn),
    dnsQuery(`_dmarc.${domain}`, "TXT", fetchFn),
  ]);
  if (txt.status === 3) {
    return [{
      severity: "media",
      title: `El dominio del remitente no existe: ${domain}`,
      detail: "No tiene registros en el DNS. Un remitente que no existe no puede recibir respuestas, y suele ser una dirección inventada.",
    }];
  }
  let dmarcTxt = dmarcExact;
  if (!dmarcExact.answers.some((t) => /^v=DMARC1/i.test(joinTxt(t))) && org !== domain) {
    dmarcTxt = await dnsQuery(`_dmarc.${org}`, "TXT", fetchFn);
  }
  const spf = txt.answers.map(joinTxt).find((t) => /^v=spf1\b/i.test(t));
  const dmarc = dmarcTxt.answers.map(joinTxt).find((t) => /^v=DMARC1\b/i.test(t));

  if (!spf) {
    findings.push(auth.spf === "pass"
      ? { severity: "media", title: "La cabecera dice SPF correcto, pero el dominio no publica SPF",
          detail: `En el DNS de ${domain} no hay registro SPF: esa línea de la cabecera no cuadra y puede estar falsificada.` }
      : { severity: "baja", title: `${domain} no publica SPF`,
          detail: "Sin SPF, cualquiera puede enviar correo diciendo ser de ese dominio sin que el receptor lo detecte." });
  } else if (/\s\+all\b/i.test(spf) || /\sall\s*$/i.test(spf)) {
    findings.push({ severity: "alta", title: `El SPF de ${domain} deja enviar a cualquiera`,
      detail: `Su registro (${spf}) termina en "+all": autoriza a todo el mundo a enviar en su nombre.` });
  } else if (/\s\?all\b/i.test(spf)) {
    findings.push({ severity: "baja", title: `El SPF de ${domain} no dice nada (?all)`,
      detail: "Publica SPF pero sin postura: no rechaza ni marca a los servidores no autorizados." });
  }

  if (!dmarc) {
    findings.push(auth.dmarc === "pass"
      ? { severity: "media", title: "La cabecera dice DMARC correcto, pero el dominio no publica DMARC",
          detail: `En el DNS de ${domain} no hay política DMARC: esa línea de la cabecera no cuadra y puede estar falsificada.` }
      : { severity: "baja", title: `${domain} no publica DMARC`,
          detail: "Sin DMARC, nadie le dice al receptor qué hacer con los correos que se hacen pasar por ese dominio." });
  } else if (/\bp\s*=\s*none\b/i.test(dmarc)) {
    findings.push({ severity: "baja", title: `El DMARC de ${domain} solo vigila (p=none)`,
      detail: "Aunque un correo falle la comprobación, la política no pide rechazarlo ni mandarlo a spam." });
  }
  return findings;
}

/** El resolutor de seguridad de Cloudflare contesta 0.0.0.0 a los dominios de malware y phishing. */
export async function checkBlocklist(domain, fetchFn) {
  const { status, answers } = await dnsQuery(domain, "A", fetchFn, DOH_SECURITY);
  if (answers.includes("0.0.0.0")) {
    return [{
      severity: "alta",
      title: `Dominio en una lista negra: ${domain}`,
      detail: "El DNS de seguridad de Cloudflare lo bloquea por malware o phishing conocido.",
    }];
  }
  if (status === 3) {
    return [{
      severity: "media",
      title: `El dominio no existe: ${domain}`,
      detail: "No resuelve en el DNS: o está mal escrito, o ya lo han retirado (algo habitual en campañas de phishing).",
    }];
  }
  return [];
}

/** Adónde acaba un enlace acortado, sin abrirlo en el navegador. Solo en la extensión (necesita permiso de host). */
export async function resolveShortener(href, fetchFn) {
  let response = await request(fetchFn, href, { method: "HEAD", redirect: "follow" });
  if (response.status >= 400) {
    // Algunos servidores no aceptan HEAD: se pide con GET y se descarta el cuerpo sin leerlo.
    response = await request(fetchFn, href, { method: "GET", redirect: "follow" });
    response.body?.cancel?.();
  }
  return response.url && response.url !== href ? response.url : null;
}

function asciiHost(host) {
  try {
    return new URL(`http://${host}`).hostname;
  } catch {
    return null;
  }
}

/** Los nombres a consultar: el host completo (las listas negras lo bloquean tal cual) y su dominio registrable (edad, SPF). */
function targets(result, extraHosts) {
  const recipients = new Set((result.to ?? []).map((a) => registrableDomain(a.domain)));
  const candidates = [result.from?.domain, ...(result.links ?? [result.link]).map((l) => l.host), ...extraHosts];
  const hosts = new Set();
  const domains = new Set();
  for (const host of candidates) {
    const ascii = host && asciiHost(host);
    if (!ascii || isIpAddress(ascii) || isShortener(ascii)) continue;
    const domain = registrableDomain(ascii);
    if (!domain || OFFICIAL.has(domain) || FREE_MAIL.has(domain) || recipients.has(domain)) continue;
    if (domains.size >= MAX_DOMAINS && !domains.has(domain)) continue;
    domains.add(domain);
    hosts.add(ascii);
  }
  return { domains: [...domains], hosts: [...hosts] };
}

function cached(cache, key, task) {
  if (!cache.has(key)) {
    const promise = task();
    cache.set(key, promise);
    promise.catch(() => cache.delete(key));
  }
  return cache.get(key);
}

/**
 * Añade a un resultado ya analizado lo que solo se sabe con red. Devuelve un resultado nuevo, con
 * `online` explicando qué se consultó y qué no se pudo. Opciones: `fetch`, `now`, `shorteners`
 * (seguir acortadores: pide permiso en la extensión) y `cache`.
 */
export async function enrich(result, { fetch: fetchFn = globalThis.fetch, now = new Date(), shorteners = false, cache = sharedCache } = {}) {
  const added = [];
  const failed = { age: new Set(), noRdap: new Set(), dns: new Set(), blocklist: new Set(), shortener: new Set() };
  const attempt = async (kind, key, task) => {
    try {
      return await task();
    } catch {
      failed[kind].add(key);
      return null;
    }
  };

  const links = result.links ?? [result.link];
  const resolved = [];
  if (shorteners) {
    const shortened = links.filter((l) => l.problems.includes("acortador")).slice(0, MAX_SHORTENERS);
    await Promise.all(shortened.map(async (link) => {
      const final = await attempt("shortener", link.shown, () => cached(cache, `short:${link.href}`, () => resolveShortener(link.href, fetchFn)));
      if (!final) return;
      const verdict = analyzeLink(final);
      const level = verdict?.verdict.level;
      resolved.push({ from: link.href, to: final });
      added.push({
        severity: level === "peligro" ? "alta" : level === "sospechoso" ? "media" : "info",
        title: `El enlace acortado lleva a ${defang(final)}`,
        detail: verdict?.findings.length
          ? `Al seguirlo: ${verdict.findings.filter((f) => f.severity !== "ok").map((f) => f.title).join("; ")}.`
          : "Destino final sin señales claras de engaño.",
      });
    }));
  }

  const { domains, hosts } = targets(result, resolved.map((r) => new URL(r.to).hostname));
  await Promise.all([
    ...hosts.map((host) =>
      attempt("blocklist", host, async () => {
        added.push(...(await cached(cache, `block:${host}`, () => checkBlocklist(host, fetchFn))));
      }),
    ),
    ...domains.map((domain) =>
      attempt("age", domain, async () => {
        const registered = await cached(cache, `age:${domain}`, () => registrationDate(domain, fetchFn));
        if (!registered) {
          failed.noRdap.add(domain);
          return;
        }
        const finding = ageFinding(domain, registered, now);
        if (finding) added.push(finding);
      }),
    ),
  ]);
  if (result.from?.domain) {
    const sender = registrableDomain(result.from.domain);
    if (!OFFICIAL.has(sender) && !FREE_MAIL.has(sender)) {
      await attempt("dns", result.from.domain, async () => {
        added.push(...(await cached(cache, `auth:${result.from.domain}`, () => checkAuthDns(result.from.domain, result.auth, fetchFn))));
      });
    }
  }

  const labels = {
    age: "la antigüedad del dominio",
    noRdap: "la antigüedad del dominio (su registro no publica RDAP; .es, por ejemplo, solo ofrece WHOIS)",
    dns: "SPF y DMARC",
    blocklist: "las listas negras",
    shortener: "adónde lleva el acortador",
  };
  for (const [kind, set] of Object.entries(failed)) {
    if (set.size) {
      added.push({
        severity: "info",
        title: `No se pudo comprobar ${labels[kind]}`,
        detail: `Sin respuesta para: ${[...set].join(", ")}. Que no salga nada no quiere decir que sea bueno.`,
      });
    }
  }

  // Si el DNS del remitente ya dijo que no existe, no se repite desde la lista negra.
  const missing = new Set(added.filter((f) => f.title.startsWith("El dominio del remitente no existe: ")).map((f) => f.title.split(": ")[1]));
  const findings = added.filter((f) => !(f.title.startsWith("El dominio no existe: ") && missing.has(f.title.split(": ")[1])));

  return { ...rerate({ ...result, findings: [...result.findings, ...findings] }), online: { domains, hosts, resolved, failed: Object.fromEntries(Object.entries(failed).map(([k, v]) => [k, [...v]])) } };
}
