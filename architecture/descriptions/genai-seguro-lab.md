Ejecuta un laboratorio local y reproducible que analiza incidentes sintéticos
mediante un flujo determinista y herramientas con autoridad acotada.

## Responsabilidades

- Cargar y validar el corpus sintético versionado.
- Ejecutar `analyze` o `baseline` sin llamadas externas.
- Validar el corpus adversario y conectar nueve fixtures PI/JB/EX al harness
  interno de test.
- Separar la salida del modelo de la autorización de herramientas.
- Emitir resultados JSON reproducibles y mantener los efectos locales fuera de
  la ruta ordinaria de la CLI.
- Preparar una petición vulnerable marcada para evaluación sin ejecutarla.
- Evaluar en `$TMP` dos inyecciones indirectas con un doble determinista y una
  búsqueda autorizada.
- Evaluar jailbreak de contenido y de flujo, rechazos de conocimiento y un
  marcador señuelo de CLI sin persistencia ni red.

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
- No hay autenticación interna, service account o telemetría. El remoto GitHub
  público es una integración manual de desarrollo y distribución; no es
  alcanzable desde el runtime.
- El corpus adversario conserva fixtures y oráculos separados; `CMP-07` cubre
  nueve PI/JB/EX y las otras nueve entradas siguen inertes.
- El perfil vulnerable existe como API interna `C0`; solo `CMP-07` conduce sus
  peticiones hacia el doble determinista y `TOL-01`, nunca hacia la CLI
  ordinaria o `TOL-02`.

## Evidencia

- `docs/system-inventory.md`
- `main.py`
- `src/genai_seguro_lab/`
- `data/manifest.json`
- `data/adversarial/manifest.json`
- `evaluations/benign-baseline-v1.json`
