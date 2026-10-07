# Progreso: modo completo, QR y lote SOC

Plan: `C:\Users\Guillem\.claude\plans\recursive-pondering-cookie.md`

## Hecho
- Fase 1: marcas DGT, Seguridad Social, Cl@ve, Bizum, ING, Abanca, Ibercaja, Kutxabank, Cajamar, EVO, Renfe y Generalitat/Mossos; nombres en catalán de la Agencia Tributaria; frases de phishing en catalán; dominios con guion (`seg-social.es.falso.example`); muestras `dgt-multa` y `seg-social-catala`.
- Fase 2: `js/online.js` (RDAP, SPF/DMARC por DoH, lista negra por el DNS de seguridad de Cloudflare, acortadores con HEAD), `js/settings.js`, interruptor privado/completo, `rerate`/`isShortener` exportados desde `analyze.js`, permiso opcional de la extensión, README con "Dos modos".

- Fase 3: `js/qr.js` + jsQR 1.4.0 vendorizado (`js/vendor/`, integridad npm verificada, hash fijado en test), `mail.js` guarda las imágenes (tope 10 de 5 MB), `scripts/png.mjs` (lector de PNG para Node: pruebas y CLI), muestra `qr-paypal`, fixtures en `tests/fixtures/`.

## Desviaciones del plan (Fase 2)
- Listas negras: Spamhaus DBL devuelve `127.255.255.254` (resolutor público bloqueado) y SURBL da SERVFAIL por Cloudflare; se usa `security.cloudflare-dns.com` (0.0.0.0 = bloqueado, comprobado con `malware.testcategory.com`).
- La lista negra se consulta por host completo, no por dominio registrable.
- `connect-src` pasa a `'self' https:` porque rdap.org redirige a un servidor distinto por TLD y la CSP vale también para las redirecciones. Una prueba ata dónde puede salir la red.
- Sin `host_permissions` al instalar (RDAP y DoH admiten CORS): solo `optional_host_permissions` para acortadores.
- `.es` no está en el bootstrap RDAP de la IANA: la edad de un `.es` no se puede consultar; se avisa.

## En curso
- Nada.

## Pendiente
- Fase 4: análisis de una carpeta de `.eml` (CLI y vista web).
- Fase 3: el aviso de Gmail (background) no busca QR; las imágenes remotas y los PDF no se miran.
- Sin probar en navegador real: seguir acortadores en la extensión (`chrome.permissions` y la redirección entre orígenes).
