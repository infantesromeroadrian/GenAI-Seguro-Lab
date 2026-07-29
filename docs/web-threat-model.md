# Threat model del frontal web local

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-WEB-THREAT-001` |
| Versión | `1.1.0` |
| Fecha | 2026-07-28 |
| Superficie | `CMP-19` — navegador y gateway HTTP de loopback |
| Fuente de requisitos | [`GSL-WEB-001`](./web-interface-spec.md) |
| Rules of Engagement | [`GSL-ROE-001` 2.9.0](./rules-of-engagement.md) |

## Activos y límites

Activos protegidos:

- integridad de `DAT-01`, `DAT-02` y `DAT-03`;
- confidencialidad de la memoria del proceso y de los eventos saneados;
- autoridad cerrada de `CMP-03`, `TOL-01` y el flujo de borradores no expuesto;
- disponibilidad local razonable del proceso;
- confidencialidad de `OLLAMA_API_KEY` y minimización del egress opt-in;
- interpretación correcta: propuestas no son acciones y el doble no es un
  modelo GenAI real.

La nueva frontera `TB-07` es el intercambio HTTP entre un navegador local y el
proceso Python a través de `127.0.0.1`. Ambos siguen dentro de `TB-01`: no hay
aislamiento adicional de usuario o sistema operativo. Un proceso hostil que ya
ejecute bajo `IDN-01` conserva la autoridad efectiva de esa cuenta.

## Flujo autorizado

```text
navegador local
  → GET de assets allowlisted y /api/status
  → selección de un ID sintético
  → POST JSON same-origin + token efímero
  → gateway valida frontera
  → motor benigno adquiere lock y ejecuta controles
  → opcional: dos POST a Ollama, herramienta local y JSON validado
  → JSON saneado + journal efímero
  → DOM mediante textContent
```

No hay ruta desde `CMP-19` a `TOL-02`, al harness adversario, a datos reales o
a una escritura. Solo `--provider ollama` crea la ruta fija al endpoint
documentado; baseline nunca la usa.

## Amenazas y tratamiento

| ID | Amenaza | Control actual | Estado y límite |
|---|---|---|---|
| `WEB-T-01` | Exposición accidental a LAN o internet | Bind fijo a `127.0.0.1`; no existe opción `host` | Mitigada para la CLI soportada; un proxy o túnel externo queda prohibido y fuera del control del proceso |
| `WEB-T-02` | DNS rebinding o Host manipulado | Allowlist exacta de `127.0.0.1:<port>` y `localhost:<port>` | Mitigada en la frontera HTTP probada |
| `WEB-T-03` | CSRF desde una web maliciosa | Origin same-origin, token aleatorio en memoria, JSON, cabecera propia, sin CORS y preflight rechazado | Mitigada para navegador; no autentica otro proceso local |
| `WEB-T-04` | XSS mediante contenido del incidente o salida | DOM con `textContent`, CSP sin inline/terceros, `nosniff`, `frame-ancestors none` | Mitigada para el renderer actual; cambios de DOM obligan a reevaluar |
| `WEB-T-05` | Clickjacking o filtración de navegación | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `no-referrer`, COOP/CORP same-origin | Mitigada dentro del navegador compatible |
| `WEB-T-06` | Payload grande, JSON ambiguo o campos no previstos | 1 KiB, Content-Length, sin chunked, modelos strict/extra-forbid y rutas cerradas | Mitigada para las entradas implementadas; no es una prueba de carga |
| `WEB-T-07` | Traversal o lectura de archivos arbitrarios | Mapa estático literal de cuatro assets; no se transforma una ruta del usuario | Mitigada por ausencia de resolución dinámica |
| `WEB-T-08` | Ejecuciones concurrentes, conexiones lentas o abuso de baseline | Lock advisory no bloqueante, cola HTTP pequeña, timeout de conexión de 5 s y rechazo cerrado de métodos no allowlisted | Parcial: no hay rate limiting persistente, stress test ni aislamiento del SO |
| `WEB-T-09` | Divulgación en caché, logs o almacenamiento | `no-store`, journal en memoria, `log_message` vacío, sin cookies, local storage o analytics | Mitigada para la implementación; el navegador y el SO siguen bajo `IDN-01` |
| `WEB-T-10` | Ampliación de autoridad del modelo | No hay prompt libre; solo ID validado; el motor conserva grant y vista exactos; una tool distinta se rechaza antes de la vista | Mitigada dentro del corpus cerrado, no generalizable al comportamiento real del LLM |
| `WEB-T-11` | Dependencia web comprometida | No se añaden paquetes, CDN, fuentes, scripts o imágenes de terceros | Superficie de supply chain no ampliada por dependencias, aunque Git y la autoridad de mantenimiento permanecen |
| `WEB-T-12` | Confundir visualización con acción o seguridad total | UI etiqueta backend, determinismo, egress y coste y muestra límites | Riesgo de interpretación reducido, no eliminado |
| `WEB-T-13` | Fuga de clave, prompt, thinking o cuerpo remoto; redirect o retry | Clave solo en cabecera, endpoint fijo, redirects rechazados, cero retries, proyección cerrada y logs vacíos | Contrato probado con transporte falso y smoke real acotado; la retención del proveedor no está verificada |

## Riesgos residuales

| ID | Riesgo | Estado |
|---|---|---|
| `WEB-RR-01` | Un proceso malicioso bajo la misma cuenta puede leer el token desde `/api/status` y llamar al servicio | `ABIERTO`; el token protege el navegador frente a CSRF, no autentica procesos locales |
| `WEB-RR-02` | No se ha medido resistencia a carga, conexiones lentas o agotamiento deliberado | `ABIERTO`; no ejecutar stress, soak o fixtures DOS sin nueva autorización |
| `WEB-RR-03` | HTTP sin TLS sería inadecuado fuera de loopback | `EVITADO`; la exposición externa, proxy y túnel están prohibidos |
| `WEB-RR-04` | El comportamiento general de `gpt-oss:120b` real, prompt libre o datos reales no está evaluado | `ABIERTO`; solo el primer elemento existe opt-in; un incidente completó el flujo tras dos fallos cerrados, sin demostrar disponibilidad o generalización |
| `WEB-RR-05` | Disponibilidad, coste, términos, residencia y retención de Ollama son desconocidos | `ABIERTO`; revisar antes de una nueva prueba real y no introducir datos reales |

Estos riesgos no están aceptados por la implementación ni alteran `RR-01` a
`RR-06`. Deben reevaluarse antes de cambiar binding, rutas, entrada, modelo,
datos, identidad, herramientas, efectos o despliegue.

## Evidencia y límites

- `tests/test_web_interface.py` comprueba rutas, cabeceras, frontera
  Host/Origin/CSRF, tamaño, esquema, resultados y ausencia de borradores.
- La comprobación en navegador demuestra el flujo visible actual, no una
  evaluación adversaria independiente.
- `DAT-25` permanece inmutable y no cubre `CMP-19` o `TB-07`.
- Las pruebas Ollama con transporte falso acreditan status, dos llamadas,
  herramienta, límites y errores saneados. Un smoke instrumentado acredita el
  flujo end-to-end de `INC-BEN-001`; no acredita disponibilidad,
  reproducibilidad o comportamiento general del proveedor.
- Las cuatro fixtures DOS/SC continúan inertes.
