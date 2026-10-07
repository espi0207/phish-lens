// Resumen de muchos correos a la vez, pensado para un SOC: cuántos son peligrosos, qué dominios
// y marcas se repiten, qué adjuntos son malos y la lista ordenada por riesgo. Es la parte pura
// (sin leer ficheros ni tocar la página); la usan la línea de comandos y la web.

const LEVELS = ["peligro", "sospechoso", "limpio"];
const TOP = 10;

/** El mismo título con distinto dominio o fichero cuenta como un solo tipo de hallazgo. */
const kind = (title) => title.split(": ")[0];

function top(counter, limit = TOP) {
  return [...counter.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, limit);
}

/**
 * `items` es una lista de { name, result } o { name, error }. Devuelve los totales, los repetidos
 * y `rows` (un correo por fila, del más al menos arriesgado).
 */
export function summarize(items) {
  const levels = Object.fromEntries(LEVELS.map((l) => [l, 0]));
  const senders = new Map();
  const findings = new Map();
  const severities = new Map();
  const attachments = [];
  const errors = [];
  const rows = [];

  for (const item of items) {
    if (!item.result) {
      errors.push({ name: item.name, error: item.error ?? "no se pudo leer" });
      continue;
    }
    const { result } = item;
    levels[result.verdict.level]++;
    const domain = result.from?.domain || "(sin remitente)";
    senders.set(domain, (senders.get(domain) ?? 0) + 1);
    const serious = result.findings.filter((f) => f.severity === "alta" || f.severity === "media");
    for (const f of serious) {
      const key = kind(f.title);
      findings.set(key, (findings.get(key) ?? 0) + 1);
      if (!severities.has(key) || f.severity === "alta") severities.set(key, f.severity);
    }
    const bad = result.attachments.filter((a) => a.problems?.some((p) => p !== "comprimido"));
    for (const a of bad) attachments.push({ mail: item.name, name: a.name, problems: a.problems });
    rows.push({
      name: item.name,
      verdict: result.verdict.level,
      score: result.score,
      subject: result.subject || "",
      from: result.from?.address || "",
      domain: result.from?.domain || "",
      links: result.links.length,
      qr: result.qr?.length ?? 0,
      serious: serious.map((f) => f.title),
      badAttachments: bad.map((a) => a.name),
    });
  }
  rows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  return {
    total: items.length,
    analyzed: rows.length,
    levels,
    errors,
    senders: top(senders).map(([domain, count]) => ({ domain, count })),
    findings: top(findings).map(([title, count]) => ({ title, count, severity: severities.get(title) })),
    attachments,
    rows,
  };
}

/** Una celda de CSV. Lo que empieza por = + - @ lo interpretaría Excel como fórmula: se le antepone una comilla. */
export function csvCell(value) {
  let text = String(value ?? "");
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCsv(summary) {
  const header = ["archivo", "veredicto", "puntuacion", "asunto", "remitente", "dominio", "enlaces", "qr", "hallazgos_graves", "adjuntos_peligrosos"];
  const lines = summary.rows.map((r) =>
    [r.name, r.verdict, r.score, r.subject, r.from, r.domain, r.links, r.qr, r.serious.join(" | "), r.badAttachments.join(" | ")].map(csvCell).join(","),
  );
  return [header.join(","), ...lines].join("\n") + "\n";
}

const cell = (text) => String(text ?? "").replace(/\|/g, "\\|").replace(/\s+/g, " ");

export function toMarkdown(summary) {
  const { levels } = summary;
  const out = [
    "# Resumen de correos",
    "",
    `Analizados: ${summary.analyzed} de ${summary.total}. Peligro: **${levels.peligro}**, sospechosos: **${levels.sospechoso}**, limpios: ${levels.limpio}.`,
    "",
  ];
  if (summary.errors.length) {
    out.push("## No se han podido leer", "", ...summary.errors.map((e) => `- ${cell(e.name)}: ${cell(e.error)}`), "");
  }
  if (summary.findings.length) {
    out.push("## Hallazgos más repetidos", "", "| Hallazgo | Gravedad | Correos |", "|---|---|---|");
    out.push(...summary.findings.map((f) => `| ${cell(f.title)} | ${f.severity} | ${f.count} |`), "");
  }
  if (summary.senders.length) {
    out.push("## Dominios de remitente", "", "| Dominio | Correos |", "|---|---|");
    out.push(...summary.senders.map((s) => `| ${cell(s.domain)} | ${s.count} |`), "");
  }
  if (summary.attachments.length) {
    out.push("## Adjuntos peligrosos", "", "| Correo | Adjunto | Tipo |", "|---|---|---|");
    out.push(...summary.attachments.map((a) => `| ${cell(a.mail)} | ${cell(a.name)} | ${cell(a.problems.join(", "))} |`), "");
  }
  out.push("## Correos, del más al menos arriesgado", "", "| Archivo | Veredicto | Puntos | Asunto | Remitente |", "|---|---|---|---|---|");
  out.push(...summary.rows.map((r) => `| ${cell(r.name)} | ${r.verdict} | ${r.score} | ${cell(r.subject)} | ${cell(r.from)} |`));
  return out.join("\n") + "\n";
}
