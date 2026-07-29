# Especificación del frontal web local

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-WEB-001` |
| Versión | `1.1.0` |
| Fecha | 2026-07-28 |
| Estado | Implementado como extensión posterior al roadmap interno 66/66 |
| Usuario | `ACT-01` — operador local |
| Datos | Los 12 incidentes benignos y sintéticos de `DAT-01` |
| Runtime | Un proceso Python, un navegador local, HTTP sobre loopback y egress Ollama solo por opt-in |

## Problema y resultado

La CLI permite ejecutar el flujo seguro, pero no muestra de forma pedagógica
la relación entre el resultado, sus métricas y el journal de seguridad. El
frontal debe hacer visible esa relación sin añadir prompt libre, datos,
herramientas, efectos o autoridad al modelo.

El resultado esperado es una interfaz local desde la que `ACT-01` puede:

1. ver el alcance real del laboratorio;
2. seleccionar uno de los 12 incidentes sintéticos;
3. ejecutar su análisis o la baseline benigna completa;
4. leer únicamente la proyección ya saneada;
5. recorrer los eventos efímeros de la operación.

## Alcance

- `main.py web --port <puerto> --provider deterministic|ollama` inicia el
  listener y fija el backend; el default es `deterministic`.
- El listener siempre se vincula a `127.0.0.1`; no existe parámetro `host`.
- HTML, CSS, JavaScript y favicon se sirven desde una allowlist fija.
- `GET /api/status` enumera capacidades e incidentes validados.
- `POST /api/analyze` acepta solo `incident_id`.
- `POST /api/baseline` acepta únicamente el objeto vacío.
- Baseline usa siempre `MOD-01`; Ollama solo puede atender `POST /api/analyze`.
- Ambas operaciones reutilizan `CMP-02`, `CMP-03`, `CMP-04/05`, `CMP-09`,
  `CMP-10` y `CMP-11`.
- El navegador recibe el resultado y el informe de seguridad saneados como
  JSON. No existe almacenamiento de sesión ni de resultados.

## No objetivos

- Prompt libre, chat, RAG abierto, uploads, rutas o texto aportado por usuario.
- Datos reales, secretos, incidentes corporativos o contenido personal.
- Otro proveedor/modelo, endpoint configurable, credenciales en UI o cloud
  para baseline/evaluaciones. Ollama se limita al contrato experimental.
- Borradores, escritura, acciones de contención o nuevas herramientas.
- Autenticación, acceso multiusuario, TLS, proxy, túnel o despliegue público.
- Persistencia, telemetría, analytics, service worker o recursos de terceros.
- Presentar la UI como evidencia de robustez adversaria o cierre de `SEC-1`.

## Requisitos verificables

| ID | Requisito | Criterio de aceptación |
|---|---|---|
| `WEB-F-01` | El operador puede descubrir el corpus permitido | `GET /api/status` devuelve 12 IDs `INC-BEN-NNN` y ninguna entrada libre |
| `WEB-F-02` | El operador puede analizar un caso | Un POST válido devuelve `FunctionalCaseResult` determinista o `CloudAnalysisResult` alojado y su `SecurityEventReport` |
| `WEB-F-03` | El operador puede ejecutar la baseline | Un POST con `{}` devuelve 12/12 casos superados, 0 llamadas externas y 0 € |
| `WEB-F-04` | La interfaz explica resultado y controles | La UI presenta métricas, secciones de salida y cronología sin interpretar HTML del resultado |
| `WEB-C-01` | La CLI anterior se conserva | Los smoke tests de `analyze` y `baseline` siguen pasando sin cambiar sus sobres |
| `WEB-S-01` | El servicio no se expone fuera del host | La factory fija `127.0.0.1` y la CLI no acepta otro host |
| `WEB-S-02` | El navegador no amplía el origen | Host cerrado, Origin same-origin, token CSRF efímero, ausencia de CORS y rechazo de preflight |
| `WEB-S-03` | La entrada permanece cerrada | JSON estricto de 1 KiB como máximo; campos extra, IDs desconocidos, chunked, tipos distintos y métodos no allowlisted se rechazan |
| `WEB-S-04` | La salida se trata como datos | JavaScript usa `textContent`; CSP impide inline y terceros; no existe `innerHTML` |
| `WEB-S-05` | La operación conserva controles existentes | Carga validada, lock no bloqueante, límites, política de salida y journal se ejecutan en la ruta web |
| `WEB-S-06` | No aparecen efectos o conservación nuevos | Tests verifican cero borradores; `Cache-Control: no-store`, sin logs raw ni persistencia |
| `WEB-A-01` | La interfaz es operable con teclado y tecnologías de apoyo | Estructura semántica, labels, estados live, foco visible, enlace de salto y reduced-motion |
| `WEB-O-01` | Los fallos son acotados | Timeout de conexión de 5 s; errores JSON genéricos sin traceback y estados 400/403/404/405/409/413/421/503 según la frontera |
| `WEB-O-02` | El backend es observable y fijo | Status y UI declaran proveedor, modelo, determinismo, egress, coste y configuración; sin clave, analyze se deshabilita y baseline sigue disponible |

## Criterio de éxito

El frontal queda utilizable cuando:

- las pruebas de `test_web_interface.py` y `test_cli_smoke.py` pasan;
- la suite completa no muestra regresiones;
- una comprobación real en navegador permite analizar un caso determinista y
  ejecutar la baseline; el runner Ollama completó un smoke end-to-end
  instrumentado, pero la ruta Ollama no se probó desde el navegador;
- las cabeceras, el DOM y los límites observados coinciden con esta
  especificación;
- las Rules of Engagement, el threat model, el inventario y el mapa C4
  reflejan la nueva superficie.

El cumplimiento de estos criterios no demuestra autenticación, resistencia a
un proceso hostil del mismo equipo, disponibilidad bajo carga, seguridad de un
modelo real ni idoneidad productiva.
