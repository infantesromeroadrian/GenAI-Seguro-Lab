Ejecuta un laboratorio local y reproducible que analiza incidentes sintéticos
mediante un flujo determinista y herramientas con autoridad acotada.

## Responsabilidades

- Cargar y validar el corpus sintético versionado.
- Ejecutar `analyze` o `baseline` sin llamadas externas.
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

## Límites de confianza

| ID | Límite | Garantía actual |
|---|---|---|
| `TB-01` | Host local e identidad del SO | El proceso hereda la cuenta local; no hay identidad propia de aplicación |
| `TB-02` | Control de aplicación | Esquemas, orquestación, política de salida, límites preventivos, journal saneado y recuperación local dentro de un único proceso Python |
| `TB-03` | Salida del modelo | Toda respuesta se valida y su resumen atraviesa `CMP-09` antes de entregarse |
| `TB-04` | Autoridad de herramientas | El adaptador no autoriza ni ejecuta herramientas |
| `TB-05` | Efecto en filesystem | Solo publicación atómica aprobada y reconciliación interna dentro de `sandbox/drafts/` |
| `TB-06` | Integridad de datos versionados | Esquema estricto, referencias, conteos y hashes SHA-256 |

`TB-02`, `TB-03` y `TB-04` son límites lógicos dentro del mismo proceso; no
representan aislamiento por contenedor, usuario del sistema operativo o red.

## Exclusiones verificadas

- No hay modelo GenAI real, proveedor, red, API web, Docker, cloud o base de
  datos.
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
  retest neutral inicial y las otras cuatro entradas siguen inertes.
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
- `docs/resource-limits-policy.md`
- `docs/sandbox-recovery-policy.md`
