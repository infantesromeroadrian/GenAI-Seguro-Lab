# Especificación del perfil público

## Ficha

| Campo | Valor |
|---|---|
| Snapshot | `GSL-PUBLIC-STATIC-001`, determinista y reproducible |
| Análisis alojado | `GSL-PUBLIC-LLM-001`, implementado y no desplegado en este cambio |
| Fecha | 2026-07-29 |
| Datos | Solo los 12 incidentes benignos sintéticos |
| Catálogo y baseline | `/snapshots/public-profile-v1.json` |
| Runtime de análisis | `GET /api/status` y `POST /api/analyze` en Vercel Python Functions |
| URL del snapshot ya publicado | `https://genai-seguro-lab.vercel.app` |

## Un único perfil activo por capacidad

El snapshot continúa siendo la única fuente pública del catálogo y la baseline.
No se añade `/api/baseline`: esa ruta permanece ausente y debe responder `404`.
Cuando `GET /api/status` declara `mode=public_llm`, la UI usa
`POST /api/analyze` para el análisis vivo y el snapshot solo para la baseline.
Un fallo del POST se muestra como error; nunca se sustituye por un análisis
precomputado presentado como vivo.

Si las Functions no están disponibles, la UI puede cargar el snapshot como
perfil separado y se etiqueta explícitamente como precomputado. El frontal
local `GSL-WEB-001` conserva su contrato, aunque la copia visible del backend
alojado usa las etiquetas genéricas **Análisis con LLM** y **LLM alojado**.

## Contrato de las Functions

- `api/status.py` y `api/analyze.py` son handlers finos basados en
  `BaseHTTPRequestHandler`; reutilizan el contrato de aplicación y
  `run_cloud_incident`.
- `PUBLIC_LLM_ENABLED=true` es un kill switch no secreto. Solo el valor literal
  `true` habilita analyze; ausente o distinto devuelve `503` saneado y la UI
  deshabilita el botón.
- El único secreto de aplicación es `OLLAMA_API_KEY`. No se proyecta en status,
  respuestas, errores o frontend; `.env.example` permanece vacío.
- El request de analyze es un JSON cerrado de hasta 1 KiB con un único
  `incident_id` que cumple `INC-BEN-NNN`.
- Se rechazan query string, `Content-Encoding`, `Transfer-Encoding`/chunked,
  Content-Type distinto del valor exacto `application/json`, claves duplicadas
  y campos adicionales.
- Host se compara de forma exacta contra `VERCEL_URL` y
  `VERCEL_PROJECT_PRODUCTION_URL`; Origin debe ser el mismo host con HTTPS,
  `X-Forwarded-Proto=https` y `Sec-Fetch-Site=same-origin`.
- Status entrega un token aleatorio y una cookie double-submit
  `__Host-gsl-csrf` con `HttpOnly`, `Secure`, `SameSite=Strict` y sin Domain.
- No se emiten cabeceras CORS. Todas las respuestas API usan
  `Cache-Control: no-store` y errores saneados.

## Modelo, herramientas y proyección

El análisis público realiza exactamente dos llamadas sin retry ni streaming.
Cada llamada tiene timeout máximo de 25 s dentro de una Function con
`maxDuration=60`; el perfil local conserva 60 s por llamada. La generación fija
`temperature=0` y `num_predict=512`.

La aplicación valida antes de ejecutar `knowledge_search` que:

1. `query` sea exactamente `incident.category`;
2. `knowledge_ids` sea exactamente `incident.knowledge_refs`;
3. `limit` sea exactamente `1`.

La respuesta pública conserva resultado, contadores de invocaciones y
herramientas, coste desconocido y un `security_report` reducido. Omite
proveedor, modelo, fingerprints, correlation IDs, hashes internos, prompts,
thinking y cuerpos remotos.

## Evidencia y límites

El snapshot determinista se sigue regenerando sin red mediante
`scripts/generate_public_snapshot.py` y `DAT-25` permanece inmutable. La
preview histórica `dpl_CMgjChRAfFuxFjWknB2GtP38gAih` y la producción estática
`dpl_9ffPDMhPskoYu9m6sT5QTRZzbzVg` verificaron únicamente
`GSL-PUBLIC-STATIC-001`; no prueban ni publican `GSL-PUBLIC-LLM-001`.

Las pruebas nuevas usan transporte falso y no contactan con Ollama o Vercel.
Este cambio no despliega, no valida disponibilidad, coste, cuota, residencia o
retención del proveedor y no convierte el laboratorio en un sistema preparado
para producción.
