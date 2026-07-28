Ejecuta un laboratorio local y reproducible que analiza incidentes sintéticos
mediante un flujo determinista y herramientas con autoridad acotada.

## Responsabilidades

- Cargar y validar el corpus sintético versionado.
- Ejecutar `analyze` o `baseline` sin llamadas externas, desde CLI o desde el
  frontal fijado a loopback.
- Servir cuatro assets allowlisted y tres rutas API locales mediante `CMP-19`,
  sin prompt libre, uploads, rutas, persistencia o CORS.
- Validar el corpus adversario y conectar 14 fixtures PI/JB/EX/TOL al harness
  interno de test.
- Separar la salida del modelo de la autorización de herramientas.
- Controlar mediante `CMP-09` el resumen y los borradores antes de entrega,
  huella o aprobación.
- Acotar mediante `CMP-10` el corpus, las fronteras, las operaciones y los
  efectos antes de ejecutarlos.
- Observar mediante `CMP-11` decisiones y señales con correlación opaca,
  secuencia global y un esquema sin contenido bruto.
- Publicar y reconciliar mediante `CMP-12` el único efecto local ya autorizado
  sin restaurar autoridad.
- Emitir resultados JSON reproducibles y mantener los efectos locales fuera de
  la ruta ordinaria de la CLI.
- Preparar una petición vulnerable marcada para evaluación sin ejecutarla.
- Evaluar en `$TMP` dos inyecciones indirectas con un doble determinista y una
  búsqueda autorizada.
- Evaluar jailbreak de contenido y de flujo, rechazos de conocimiento y un
  marcador señuelo de CLI sin persistencia ni red.
- Evaluar abuso de herramientas, aprobaciones y filesystem dentro de `$TMP`;
  el checkout actual rechaza la confirmación literal con cero archivos.
- Fijar mediante `CMP-08` la baseline adversaria histórica y conservar solo su
  proyección saneada y revisada.
- Repetir mediante `CMP-13` los mismos 14 casos sobre un candidato endurecido
  exacto y conservar un retest inicial neutral con `final_retest: false`.
- Derivar mediante `CMP-14` las métricas adversarias iniciales sin reejecutar el
  target ni modificar la evidencia fuente.
- Comparar mediante `CMP-15` los 12 casos benignos pre/post controles, con
  oráculos posteriores a la salida y evidencia saneada sin equivalencia
  semántica.
- Medir mediante `CMP-16` 30 pares pre/post de latencia, CPU y RSS, con
  contadores y complejidad descriptiva sin score o umbral universal.
- Consolidar manualmente seis hallazgos en `DAT-23` y verificar mediante
  `CMP-17` sus fuentes, referencias y resumen sin reejecutar evaluadores o
  generar clasificaciones.
- Fijar mediante `DAT-24` la rúbrica previa y ejecutar mediante `CMP-18` una
  sola vez el candidato final exacto en una copia temporal, sin entregar
  oráculos o rúbrica al target ni escribir evidencia automáticamente; la
  proyección revisada queda en `DAT-25`.

## Límites de confianza

| ID | Límite | Garantía actual |
|---|---|---|
| `TB-01` | Host local e identidad del SO | El proceso hereda la cuenta local; no hay identidad propia de aplicación |
| `TB-02` | Control de aplicación | Esquemas, orquestación, política de salida, límites preventivos, journal saneado y recuperación local dentro de un único proceso Python |
| `TB-03` | Salida del modelo | Toda respuesta se valida y su resumen atraviesa `CMP-09` antes de entregarse |
| `TB-04` | Autoridad de herramientas | El adaptador no autoriza ni ejecuta herramientas |
| `TB-05` | Efecto en filesystem | Solo publicación atómica aprobada y reconciliación interna dentro de `sandbox/drafts/` |
| `TB-06` | Integridad de datos versionados | Esquema estricto, referencias, conteos y hashes SHA-256 |
| `TB-07` | Navegador local ↔ gateway HTTP | Loopback, Host/Origin/CSRF, cuerpo ≤ 1 KiB, esquema estricto, CSP y cabeceras cerradas |

`TB-02`, `TB-03` y `TB-04` son límites lógicos dentro del mismo proceso.
`TB-07` separa el DOM del gateway, pero ambos permanecen en el mismo host y
cuenta. Ninguno representa aislamiento por contenedor o identidad del sistema
operativo.

## Exclusiones verificadas

- No hay modelo GenAI real, proveedor, red externa, API pública, Docker, cloud
  o base de datos. `CMP-19` solo atiende en `127.0.0.1`.
- No hay autenticación general, service account, logging persistente o
  telemetría externa. Solo existe la autoridad sintética interna de
  borradores; no verifica presencia humana. El remoto GitHub público es una
  integración manual de desarrollo y distribución; no es alcanzable desde el
  runtime.
- `CMP-09` no usa un clasificador o proveedor y no ofrece detección universal;
  solo aplica las reglas explícitas documentadas.
- `CMP-10` usa plazos y un lock cooperativos; no cancela llamadas bloqueadas,
  limita llamadas directas a la API o aísla el proceso.
- `CMP-11` vive en memoria y su cadena no firmada no autentica al emisor,
  correlaciona sesiones o activa respuesta y recuperación.
- `CMP-12` depende de primitivas POSIX y de un lock cooperativo; no resiste
  código hostil con la autoridad de `IDN-01`, instala handlers globales o
  implementa recuperación operativa general.
- El corpus adversario conserva fixtures y oráculos separados; `CMP-07` cubre
  14 PI/JB/EX/TOL, `CMP-08` fija su baseline canónica, `CMP-13` conserva el
  retest neutral inicial, `CMP-14` deriva su comparación y las otras cuatro
  entradas siguen inertes. `CMP-15` solo ejecuta el corpus benigno canónico y
  `CMP-16` solo mide dos candidatos benignos fijados bajo `$TMP`; `CMP-17`
  solo verifica `DAT-20/21/22/23` y emite un informe efímero. `CMP-18` conservó
  `DAT-24` fuera del target y fijó `DAT-25` tras el único run canónico.
- El perfil vulnerable existe como API interna `C0`; solo `CMP-07` conduce sus
  peticiones hacia el doble determinista y `TOL-01`; M06 invoca `TOL-02`
  únicamente desde pytest y bajo `$TMP`, nunca desde la CLI o el flujo benigno.

## Evidencia

- `docs/system-inventory.md`
- `main.py`
- `src/genai_seguro_lab/`
- `data/manifest.json`
- `data/adversarial/manifest.json`
- `evaluations/benign-baseline-v1.json`
- `evaluations/adversarial-baseline-v1/`
- `evaluations/adversarial-retest-v1/`
- `evaluations/adversarial-metrics-v1.json`
- `evaluations/benign-pre-controls-functional-v1.json`
- `evaluations/benign-utility-v1.json`
- `evaluations/operational-metrics-v1.json`
- `evaluations/control-findings-v1.json`
- `evaluations/final-retest-rubric-v1.json`
- `evaluations/final-retest-v1.json`
- `docs/resource-limits-policy.md`
- `docs/sandbox-recovery-policy.md`
