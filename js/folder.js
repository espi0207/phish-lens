// Analizar una carpeta de .eml en la página: elegirla con el selector o arrastrarla. Todo en local
// y sin consultas de red (para eso está la línea de comandos con --completo). El resumen y los
// formatos de salida son los de batch.js.

import { analyze } from "./analyze.js";
import { parseMessage } from "./mail.js";
import { applyQr, scanQr } from "./qr.js";

export const MAX_FILES = 500;
export const MAX_SIZE = 15 * 1024 * 1024;

const isEml = (file) => /\.eml$/i.test(file.name);

/** Los ficheros de un selector de carpeta (input webkitdirectory), con la ruta dentro de la carpeta. */
export function emlFromInput(fileList) {
  return [...fileList].filter(isEml).map((file) => ({ name: file.webkitRelativePath?.split("/").slice(1).join("/") || file.name, file }));
}

async function readEntries(directory) {
  const reader = directory.createReader();
  const all = [];
  // readEntries devuelve los elementos de 100 en 100: hay que repetir hasta que venga vacío.
  for (let batch = await read(reader); batch.length; batch = await read(reader)) all.push(...batch);
  return all;
}
const read = (reader) => new Promise((resolve, reject) => reader.readEntries(resolve, reject));
const fileOf = (entry) => new Promise((resolve, reject) => entry.file(resolve, reject));

/** Los .eml de las carpetas soltadas en la página (FileSystemEntry de dataTransfer.items). */
export async function emlFromEntries(entries) {
  const found = [];
  const walk = async (entry, path) => {
    if (found.length >= MAX_FILES + 1) return;
    if (entry.isDirectory) {
      for (const child of await readEntries(entry)) await walk(child, `${path}${entry.name}/`);
    } else if (entry.isFile && /\.eml$/i.test(entry.name)) {
      found.push({ name: `${path}${entry.name}`, file: await fileOf(entry) });
    }
  };
  for (const entry of entries) await walk(entry, "");
  return found.map((f) => ({ ...f, name: f.name.split("/").slice(1).join("/") || f.name }));
}

/** Analiza los ficheros uno a uno, cediendo el turno al navegador entre uno y otro para que la página no se congele. */
export async function analyzeFiles(files, onProgress = () => {}) {
  const items = [];
  const list = files.slice(0, MAX_FILES);
  for (const [i, { name, file }] of list.entries()) {
    onProgress(i, list.length);
    await new Promise((resolve) => setTimeout(resolve));
    try {
      if (file.size > MAX_SIZE) throw new Error("más de 15 MB");
      const message = parseMessage(new Uint8Array(await file.arrayBuffer()));
      if (!message.headers.list.length) throw new Error("no parece un correo (sin cabeceras)");
      let result = analyze(message);
      try {
        result = applyQr(result, await scanQr(message));
      } catch {
        // Sin poder leer los QR, queda el análisis normal.
      }
      items.push({ name, file, result });
    } catch (err) {
      items.push({ name, file, error: err.message });
    }
  }
  return { items, truncated: files.length > MAX_FILES };
}
