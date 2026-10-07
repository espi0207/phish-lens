// Los ajustes: modo privado (todo en local) o completo (consulta dominios por red), y si en
// la extensión se siguen los acortadores. En la extensión se guardan en chrome.storage.local,
// para que los vea también la parte de fondo; en la web, en localStorage.

const KEY = "phish-lens";
const DEFAULTS = { mode: "privado", shorteners: false };
const SHORTENER_ORIGINS = ["https://*/*", "http://*/*"];

function clean(raw) {
  return {
    mode: raw?.mode === "completo" ? "completo" : "privado",
    shorteners: raw?.shorteners === true,
  };
}

export async function getSettings() {
  try {
    if (globalThis.chrome?.storage?.local) {
      return clean((await chrome.storage.local.get(KEY))[KEY]);
    }
    return clean(JSON.parse(localStorage.getItem(KEY)));
  } catch {
    return { ...DEFAULTS };
  }
}

export async function saveSettings(patch) {
  const next = clean({ ...(await getSettings()), ...patch });
  try {
    if (globalThis.chrome?.storage?.local) await chrome.storage.local.set({ [KEY]: next });
    else localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    // Sin almacenamiento (ventana privada, por ejemplo): el ajuste dura lo que dure la página.
  }
  return next;
}

/** Seguir acortadores solo es posible en la extensión: en una web, CORS no deja ver adónde redirigen. */
export const canFollowShorteners = () => Boolean(globalThis.chrome?.permissions?.request);

export async function hasShortenerPermission() {
  try {
    return canFollowShorteners() && (await chrome.permissions.contains({ origins: SHORTENER_ORIGINS }));
  } catch {
    return false;
  }
}

/** Tiene que llamarse desde un clic: el navegador no deja pedir permisos de otra forma. */
export async function requestShortenerPermission() {
  try {
    return await chrome.permissions.request({ origins: SHORTENER_ORIGINS });
  } catch {
    return false;
  }
}
