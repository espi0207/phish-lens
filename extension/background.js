// La parte de la extensión que no se ve: el icono, el menú del clic derecho y el análisis
// de los correos que le pasa gmail.js. El análisis es el mismo código que el de la página
// (js/) y pasa dentro del navegador. Solo en modo completo, y solo si el usuario lo activa,
// se consultan los dominios por red (js/online.js); el correo nunca sale.

import { analyze } from "../js/analyze.js";
import { parseMessage } from "../js/mail.js";
import { enrich } from "../js/online.js";
import { getSettings, hasShortenerPermission } from "../js/settings.js";

const PAGE = "index.html";
const KEEP = 5; // correos de Gmail que se guardan (solo mientras el navegador está abierto)

export const linkPage = (url) => `${PAGE}#enlace=${encodeURIComponent(url)}`;
export const mailPage = (key) => `${PAGE}#correo=${encodeURIComponent(key)}`;

// El icono abre el analizador en una pestaña: arrastrar un .eml, pegar un correo o un enlace.
chrome.action.onClicked.addListener(() => chrome.tabs.create({ url: PAGE }));

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "enlace", title: "Comprobar este enlace con phish-lens", contexts: ["link"] });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== "enlace" || !info.linkUrl) return;
  // Una ventana pequeña, como un aviso, en vez de una pestaña más.
  chrome.windows.create({ url: linkPage(info.linkUrl), type: "popup", width: 620, height: 760 });
});

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return false;
  if (message?.type === "analizar" && typeof message.raw === "string") {
    summarize(message.raw).then(reply, () => reply(null));
    return true; // la respuesta llega más tarde
  }
  if (message?.type === "abrir" && /^correo-\d+$/.test(message.key ?? "")) {
    chrome.tabs.create({ url: mailPage(message.key) });
  }
  return false;
});

/** Analiza el correo en crudo y devuelve lo justo para el aviso que se pone en Gmail. */
export async function summarize(raw) {
  let result = analyze(parseMessage(raw));
  const settings = await getSettings();
  if (settings.mode === "completo") {
    try {
      result = await enrich(result, { shorteners: settings.shorteners && (await hasShortenerPermission()) });
    } catch {
      // Sin red, el aviso sale con el análisis local.
    }
  }
  const key = `correo-${Date.now()}`;
  try {
    // Se guarda para "Ver el análisis completo". storage.session vive en memoria y se borra
    // al cerrar el navegador; además solo se quedan los últimos.
    const saved = Object.keys(await chrome.storage.session.get(null)).filter((k) => k.startsWith("correo-")).sort();
    await chrome.storage.session.remove(saved.slice(0, Math.max(0, saved.length - KEEP + 1)));
    await chrome.storage.session.set({ [key]: raw });
  } catch {
    // Si no cabe, el aviso sale igual; solo falla el análisis completo.
  }
  return {
    key,
    verdict: result.verdict,
    score: result.score,
    findings: result.findings
      .filter((f) => f.severity === "alta" || f.severity === "media")
      .slice(0, 4)
      .map(({ severity, title }) => ({ severity, title })),
  };
}
