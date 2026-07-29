# Especificación del perfil público estático

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-PUBLIC-STATIC-001` |
| Versión | `1.0.0` |
| Fecha | 2026-07-29 |
| Estado | Implementado en el checkout; despliegue externo no verificado |
| Datos | Los 12 incidentes benignos sintéticos y proyecciones saneadas |
| Runtime público | Archivos estáticos; sin Functions, API, POST o secretos |

## Resultado y separación de perfiles

El perfil público reutiliza la UI de `GSL-WEB-001`, pero no publica su proceso
Python. Intenta primero `GET /api/status` para conservar el comportamiento
local. Cuando esa ruta no existe, carga
`/snapshots/public-profile-v1.json` y se identifica como
**Demo pública · snapshot determinista**.

En ese modo, los botones muestran análisis y baseline precomputados. No
afirman que el navegador ejecute un modelo, una herramienta o una evaluación.
El perfil local conserva sus POST reales y su backend Ollama opt-in; ninguna
de esas capacidades forma parte del perfil público.

## Artefactos y generación

- `vercel.json` sirve `src/genai_seguro_lab/web_assets` y no declara
  `functions`, `builds` o rutas API.
- `/assets/:path*` se reescribe a los cuatro assets existentes en la raíz
  estática.
- `scripts/generate_public_snapshot.py` llama a `run_incident` para los 12 IDs
  y a `run_functional_baseline` con reloj e identificadores opacos
  deterministas.
- `snapshots/public-profile-v1.json` conserva resultados e informes de
  seguridad saneados; declara `external_calls=false` y `cost_eur=0`.

La regeneración local es:

```bash
uv run --frozen python scripts/generate_public_snapshot.py
```

El generador no llama a Ollama, no consulta red y rechaza marcadores de
prompts, oráculos, `expected_result`, autorización o proveedor alojado.

## Requisitos verificables

| ID | Requisito | Criterio observable |
|---|---|---|
| `PUB-F-01` | Mostrar los 12 casos sin backend público | El snapshot contiene los 12 IDs, sus resultados y la baseline |
| `PUB-F-02` | Conservar el frontal local | Si `/api/status` responde, la UI mantiene POST analyze/baseline y Ollama opt-in |
| `PUB-F-03` | Etiquetar la demostración | UI, botones, estado y evidencia dicen snapshot o precomputado |
| `PUB-S-01` | No crear compute público | `vercel.json` no contiene Functions, builds ni rewrites API |
| `PUB-S-02` | No enviar datos desde la demo | El modo snapshot solo realiza GET same-origin de assets y del JSON |
| `PUB-S-03` | Tratar el snapshot como datos | El renderer usa `textContent`, nunca `innerHTML` |
| `PUB-S-04` | Aplicar cabeceras web cerradas | CSP, COOP, CORP, Permissions-Policy, Referrer-Policy, nosniff, anti-frame y HSTS |
| `PUB-O-01` | Regenerar de forma reproducible | La prueba reconstruye en memoria y compara el JSON byte a byte |
| `PUB-O-02` | No reinterpretar evidencia | `DAT-25` permanece inmutable y no se presenta como resultado del perfil público |

No se fija ni inventa una URL. Un despliegue, dominio, cuenta o configuración
real de Vercel requiere verificación y autoridad externas separadas.
