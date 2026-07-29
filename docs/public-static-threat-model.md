# Threat model del perfil público estático

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-PUBLIC-THREAT-001` |
| Versión | `1.0.0` |
| Fecha | 2026-07-29 |
| Superficie | UI y snapshot determinista servidos como archivos estáticos |
| Especificación | [`GSL-PUBLIC-STATIC-001`](./public-static-profile-spec.md) |

## Límite y flujo permitido

El visitante público, si existe un despliegue autorizado, recibe únicamente
HTML, CSS, JavaScript, favicon y un JSON versionado desde el CDN estático:

```text
navegador
  → GET de assets same-origin
  → GET /api/status sin backend
  → fallback GET /snapshots/public-profile-v1.json
  → selección local de un ID
  → render de resultado e informe precomputados mediante textContent
```

No existe Function, API, POST, secreto, sesión, herramienta, modelo o egress
de aplicación en este perfil. El intento GET de status solo permite compartir
los assets con el frontal local.

## Amenazas y tratamiento

| ID | Amenaza | Control | Límite |
|---|---|---|---|
| `PUB-T-01` | Confundir snapshot con ejecución real | Etiquetas persistentes y botones “Mostrar … precomputado” | La interpretación humana no puede eliminarse por completo |
| `PUB-T-02` | XSS desde resultado o incidente | `textContent`, CSP sin inline o terceros y snapshot sintético | Cambiar el renderer exige reevaluación |
| `PUB-T-03` | Clickjacking o navegación filtrada | `frame-ancestors 'none'`, `DENY`, `no-referrer`, COOP/CORP | Depende del navegador y de que las cabeceras se apliquen |
| `PUB-T-04` | Introducir Function, POST o secreto por deriva | Configuración cerrada y prueba estructural de `vercel.json` y assets | No sustituye revisión del estado real de Vercel |
| `PUB-T-05` | Snapshot manipulado o desincronizado | Generador reproducible y comparación byte a byte | La publicación del artefacto sigue bajo autoridad de mantenimiento |
| `PUB-T-06` | Falsa atribución de `DAT-25` | Perfil y documentación separan demo, baseline funcional y evidencia histórica | No demuestra robustez pública o de un LLM |
| `PUB-T-07` | Carga o disponibilidad del CDN | No hay compute de aplicación que agotar | Disponibilidad y protección de plataforma no se han medido |
| `PUB-T-08` | Metadatos operativos del proveedor de hosting | La aplicación no añade analytics, cookies o telemetría | Logs, cuenta, términos y tratamiento de Vercel quedan fuera de esta verificación |

## Riesgos residuales y evidencia

- No se ha inspeccionado ni desplegado un proyecto Vercel y no existe URL
  verificada.
- HSTS y el resto de cabeceras están declarados, pero su presencia real exige
  comprobar una respuesta desplegada.
- El snapshot es una demostración educativa, no una evaluación pública,
  monitorización en vivo ni prueba de disponibilidad.
- `tests/test_public_static_profile.py` verifica regeneración, 12 casos,
  ausencia de compute/secretos, seguridad de assets y hash de `DAT-25`.

Estos límites permanecen ligados a `RR-03` y `RR-06`; no cierran ni aceptan
ningún riesgo.
