Ejecuta un laboratorio local y reproducible que analiza incidentes sintéticos
mediante un flujo determinista y herramientas con autoridad acotada.

## Responsabilidades

- Cargar y validar el corpus sintético versionado.
- Ejecutar `analyze` o `baseline` sin llamadas externas.
- Validar un corpus adversario inerte sin conectarlo al runtime benigno.
- Separar la salida del modelo de la autorización de herramientas.
- Emitir resultados JSON reproducibles y mantener los efectos locales fuera de
  la ruta ordinaria de la CLI.
- Preparar una petición vulnerable marcada para evaluación sin ejecutarla.

## Límites de confianza

| ID | Límite | Garantía actual |
|---|---|---|
| `TB-01` | Host local e identidad del SO | El proceso hereda la cuenta local; no hay identidad propia de aplicación |
| `TB-02` | Control de aplicación | Esquemas y orquestación dentro de un único proceso Python |
| `TB-03` | Salida del modelo | Toda respuesta se valida como datos tipados antes de interpretarse |
| `TB-04` | Autoridad de herramientas | El adaptador no autoriza ni ejecuta herramientas |
| `TB-05` | Efecto en filesystem | Solo creación confirmada de Markdown dentro de `sandbox/drafts/` |
| `TB-06` | Integridad de datos versionados | Esquema estricto, referencias, conteos y hashes SHA-256 |

`TB-02`, `TB-03` y `TB-04` son límites lógicos dentro del mismo proceso; no
representan aislamiento por contenedor, usuario del sistema operativo o red.

## Exclusiones verificadas

- No hay modelo GenAI real, proveedor, red, API web, Docker, cloud o base de
  datos.
- No hay autenticación interna, service account, telemetría o remoto Git.
- El corpus adversario existe como fixtures y oráculos separados, pero el
  harness ejecutable todavía no existe.
- El perfil vulnerable existe como API interna `C0`; no está conectado al
  modelo, las herramientas o la CLI.

## Evidencia

- `docs/system-inventory.md`
- `main.py`
- `src/genai_seguro_lab/`
- `data/manifest.json`
- `data/adversarial/manifest.json`
- `evaluations/benign-baseline-v1.json`
