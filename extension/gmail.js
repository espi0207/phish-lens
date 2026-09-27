// En Gmail, "Mostrar original" (menú ⋮ de un correo) abre una página con el correo en
// crudo, cabeceras incluidas: justo lo que hace falta para analizarlo. Este script coge ese
// texto, se lo pasa a la parte de fondo de la extensión (que lo analiza sin sacarlo del
// navegador) y pone el veredicto arriba del todo.
//
// No depende de cómo llame Gmail a sus elementos, que cambia sin avisar: el correo es el
// bloque de texto más largo de la página que empieza con cabeceras ("Nombre: valor").

(() => {
  if (new URLSearchParams(location.search).get("view") !== "om") return;

  const HEADER = /^(received|return-path|delivered-to|from|to|subject|date|message-id|mime-version|dkim-signature|authentication-results):/im;
  const texts = [...document.querySelectorAll("pre, textarea")].map((el) => el.value ?? el.textContent);
  const raw = texts.filter((text) => HEADER.test(text.slice(0, 20000))).sort((a, b) => b.length - a.length)[0];
  if (!raw) return;

  chrome.runtime.sendMessage({ type: "analizar", raw }).then((summary) => summary && showBanner(summary));

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    Object.assign(node, attrs);
    node.append(...children.filter(Boolean));
    return node;
  }

  function showBanner(summary) {
    // En un shadow root, para que ni los estilos de Gmail cambien el aviso ni al revés.
    const host = el("div", { id: "phish-lens" });
    const root = host.attachShadow({ mode: "open" });
    const style = el("style", {
      textContent: `
        .box { font: 14px/1.45 system-ui, sans-serif; margin: 12px; padding: 14px 16px; border-radius: 12px;
               border: 1px solid; display: grid; gap: 6px; color: #111827; }
        .peligro { background: #fef3f2; border-color: #f04438; }
        .sospechoso { background: #fffaeb; border-color: #f79009; }
        .limpio { background: #ecfdf3; border-color: #12b76a; }
        .head { display: flex; align-items: center; gap: 10px; }
        .brand { font-size: 12px; color: #4b5563; }
        .verdict { font-size: 17px; font-weight: 700; flex: 1; }
        ul { margin: 0; padding-left: 20px; }
        .alta { color: #b42318; } .media { color: #b54708; }
        .actions { display: flex; gap: 8px; margin-top: 4px; }
        button { font: inherit; border-radius: 8px; border: 1px solid #d0d5dd; background: #fff; padding: 5px 12px; cursor: pointer; }
        button.primary { background: #2f6fed; border-color: #2f6fed; color: #fff; }
      `,
    });
    const findings = summary.findings.length
      ? el("ul", {}, ...summary.findings.map((f) => el("li", { className: f.severity, textContent: f.title })))
      : null;
    const box = el(
      "div",
      { className: `box ${summary.verdict.level}` },
      el("div", { className: "head" },
        el("span", { className: "verdict", textContent: summary.verdict.text }),
        el("span", { className: "brand", textContent: `phish-lens · riesgo ${summary.score}/100` })),
      findings,
      el("div", { className: "actions" },
        el("button", {
          className: "primary",
          textContent: "Ver el análisis completo",
          onclick: () => chrome.runtime.sendMessage({ type: "abrir", key: summary.key }),
        }),
        el("button", { textContent: "Cerrar", onclick: () => host.remove() })),
    );
    root.append(style, box);
    document.body.prepend(host);
  }
})();
