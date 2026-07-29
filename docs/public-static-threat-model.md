# Threat model del perfil público

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-PUBLIC-THREAT-001` |
| Versión | `2.0.0` |
| Fecha | 2026-07-29 |
| Superficie | UI y snapshot determinista más dos Python Functions cerradas |
| Especificación | [`GSL-PUBLIC-STATIC-001` y `GSL-PUBLIC-LLM-001`](./public-static-profile-spec.md) |

## Límite y flujo permitido

```text
navegador same-origin
  → GET /api/status
  → cookie __Host-* + token double-submit
  → POST /api/analyze {incident_id}
  → run_cloud_incident (dos llamadas alojadas, máximo 25 s cada una)
  → resultado y security_report proyectados

navegador
  → GET /snapshots/public-profile-v1.json
  → catálogo y baseline precomputada
```

No existe prompt libre, upload, `/api/baseline`, persistencia, CORS, selección
de proveedor/modelo, retry ni fallback de snapshot para un análisis vivo que
falle. `PUBLIC_LLM_ENABLED=true` habilita la ruta; `OLLAMA_API_KEY` es el único
secreto y nunca se entrega al navegador.

## Amenazas y tratamiento

| ID | Amenaza | Control | Límite |
|---|---|---|---|
| `PUB-T-01` | Confundir snapshot con ejecución viva | Modos y copy separados; el error live no usa fallback | La interpretación humana no puede eliminarse por completo |
| `PUB-T-02` | CSRF o llamada cross-site | Host/Origin HTTPS exactos, `Sec-Fetch-Site`, cookie `__Host-*` Strict y token double-submit | Una pestaña que renueve el token puede invalidar otro token abierto |
| `PUB-T-03` | CORS o exfiltración desde navegador | Sin ACAO, CSP/CORP, misma procedencia y `no-referrer` | Depende de configuración y navegador |
| `PUB-T-04` | Request smuggling o cuerpo ambiguo | Sin query, encoding o chunked; Content-Length exacto; JSON <=1 KiB | La plataforma HTTP sigue fuera del código de aplicación |
| `PUB-T-05` | Prompt injection mediante datos sintéticos | Separación de autoridad y contenido; tool call ligada exactamente al incidente | No demuestra robustez general del LLM |
| `PUB-T-06` | Exceso de alcance de herramienta | Nombre, query, IDs y limit exactos antes de ejecución; grant local | Un defecto futuro exige reevaluación |
| `PUB-T-07` | Fuga de proveedor, modelo o cuerpo remoto | Proyección tipada, errores saneados y logging de requests desactivado | Vercel y Ollama pueden conservar telemetría propia |
| `PUB-T-08` | Agotamiento o coste | Kill switch, dos llamadas, 25 s por llamada, `num_predict=512`, Function 60 s | No hay rate limit por usuario y el coste sigue desconocido |
| `PUB-T-09` | Deriva del host de producción | Allowlist desde `VERCEL_URL` y `VERCEL_PROJECT_PRODUCTION_URL` | La corrección de variables depende de Vercel |
| `PUB-T-10` | Exposición accidental del secreto | Solo entorno server-side; `.env.example` vacío; no se proyecta configuración | La custodia de variables del proyecto no se verificó |
| `PUB-T-11` | Disponibilidad del proveedor | Fallo cerrado y error `503`; no retry ni snapshot disfrazado de live | Disponibilidad no demostrada |
| `PUB-T-12` | Reinterpretar `DAT-25` | Snapshot, live LLM y evidencia histórica se separan | `DAT-25` no evalúa el perfil alojado |

## Evidencia y riesgos residuales

`tests/test_public_llm_profile.py` recorre status, cookie, POST, flujo alojado
con transporte falso, proyección, kill switch y rechazos principales. No hubo
despliegue ni llamada real en este cambio. Persisten `RR-01`, `RR-03` y
`RR-06`, además del riesgo operativo de una superficie pública sin rate limit;
ninguno queda aceptado o cerrado.
