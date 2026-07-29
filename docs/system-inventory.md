# Inventario del sistema actual

## Ficha del inventario

| Campo | Valor |
|---|---|
| Identificador | `GSL-SYS-INV-001` |
| Versión | `2.12.0` |
| Fecha de corte | 2026-07-28 |
| Baseline adversaria histórica | commit evaluado `93aefa45eac687d219bfed32f03be4e60e4a13ed` + evidencia PGS-03-M07 |
| Control vigente | Extensión post-roadmap `GSL-WEB-001`; DAT-25 permanece fijado |
| Entorno | checkout local de desarrollo |
| Alcance | cierre interno 66/66 más frontal local de loopback; baseline y retest históricos inmutables |

Este documento inventaría el sistema que existe en el repositorio, no la
solución futura descrita en el roadmap. PGS-03-M04/M05/M06 conectan 14 fixtures
a pruebas internas y PGS-03-M07 las ejecuta canónicamente contra un commit
limpio: 13 `PASS`, 1 `RESIDUAL`, 0 `FAIL` y 0 `STOPPED`. Los oráculos
permanecen separados del target y las otras cuatro fixtures siguen inertes.
PGS-07-M08 añade un remoto público de desarrollo; ese remoto no forma parte
del runtime ni introduce llamadas externas en la aplicación.
`GSL-WEB-001` añade `CMP-19`: un navegador y gateway HTTP local que sirven
assets propios y proyectan únicamente las operaciones benignas existentes en
`127.0.0.1`. No añade datos, modelo, herramienta, efecto o persistencia.
PGS-04-M04 sustituye la confirmación literal por una autoridad local efímera
que autentica un principal sintético y emite aprobaciones opacas. No añade una
interfaz ni demuestra presencia o identidad de una persona real.
PGS-04-M05 añade una política de salida propiedad de la aplicación: el resumen
final y los borradores deben pasarla antes de entrega, huella o aprobación.
Sus reglas son léxicas y acotadas y no acreditan detección universal.
PGS-04-M06 añade `CMP-10`: acota el corpus benigno antes de parsearlo o
calcular sus hashes, consume presupuestos de tamaño, tiempo, iteraciones y
efectos, y rechaza sin espera otro proceso que coopere mediante la CLI. El
plazo y el lock son cooperativos; no sustituyen cancelación nativa, rate
limiting persistente ni aislamiento del sistema operativo.
PGS-04-M07 añade `CMP-11`: conserva en memoria eventos allowlisted,
correlaciones opacas y señales deterministas, con una cadena SHA-256 y
presupuestos propios. El informe solo se expone por `stdout` mediante
`--security-report`; no crea logging persistente, telemetría externa,
respuesta automática ni una autoridad nueva.
PGS-04-M08 añade `CMP-12`: publica el borrador mediante una transacción local
create-only, detiene y revoca la sesión y ejecuta una única reconciliación
preautoridad. Nunca republica staging, restaura grants o elimina un final
publicado.
PGS-05-M01 añade `CMP-13` y `DAT-16` a `DAT-19`: conserva observaciones
neutrales de los mismos 14 casos sobre el candidato endurecido.
PGS-05-M02 añade `CMP-14` y `DAT-20`: verifica ambos namespaces y deriva
offline 1/14 (7,14 %) → 0/14 (0 %) de éxito de ataque y 1 → 0 operaciones no
autorizadas aceptadas o ejecutadas, sin reejecutar el target.
PGS-05-M03 añade `CMP-15` y `DAT-21`: verifica la evidencia funcional
precontroles, repite los 12 casos benignos uno a uno contra el flujo actual y
publica una comparación saneada. Ambos lados completan 12/12 casos con 0
falsos rechazos, pero 0/12 cumplen la cobertura textual estricta; por eso
`SC-07` queda `NOT_DEMONSTRATED` y no se afirma equivalencia semántica.
PGS-05-M04 añade `CMP-16` y `DAT-22`: reconstruye dos candidatos fijados con
`git archive`, verifica cuatro entradas byte a byte y conserva 30 pares AB/BA
de latencia, CPU y RSS. Mantiene 12/24/12/12 operaciones, cero llamadas
externas y cero céntimos de proveedor/cloud. La carga del operador no cambia y
la superficie interna aumenta; no se aplica score ni umbral universal.
PGS-05-M05 añade `CMP-17` y `DAT-23`: un registro estático revisado consolida
seis hallazgos sobre `DAT-20/21/22`, mientras el verificador comprueba hashes,
esquemas, 44 referencias escalares y el resumen. No ejecuta los evaluadores,
genera clasificaciones, escribe evidencia, acepta riesgo ni declara un retest
final.
PGS-05-M07 añade `CMP-18`, `DAT-24` y `DAT-25`. El único run canónico fijó el
candidato `77edd640`/`bc09b78f` y el evaluador `636e1db`/`8ccd162e`: completó
14 casos adversarios, 12 benignos y dos probes, mantuvo cuatro entradas
inertes y 15 artefactos históricos, y no usó red o credenciales. La rúbrica
enlaza 84 cláusulas con fuentes o invariantes autorizados; `SC-06` y `SC-07`
quedan demostrados solo dentro de ese contrato, sin equivalencia semántica
general o evaluación con un modelo GenAI real.

## Convenciones de estado

- **Expuesto:** el usuario puede alcanzarlo mediante `main.py`.
- **Interno:** está implementado y probado, pero no está conectado a la CLI.
- **Soporte:** participa en desarrollo, reproducción o evidencia, no en la
  ejecución ordinaria de un incidente.
- **Ausente:** no existe una implementación activa en el checkout.

Los identificadores de este inventario son estables y se reutilizarán en el
diagrama, los trust boundaries y la matriz de autoridad de PGS-02-M03 y
PGS-02-M04.

## Actores y usuarios

| ID | Actor | Estado | Interacción y autoridad real |
|---|---|---|---|
| `ACT-01` | Operador local del laboratorio | Expuesto | Usa la CLI o un navegador en loopback, elige un identificador benigno y recibe una proyección saneada; puede ejecutar la baseline y ver el journal efímero. No inicia sesión en la aplicación; el proceso hereda los permisos de su cuenta local. |
| `ACT-02` | Mantenedor y ejecutor de pruebas | Soporte | Modifica código y corpus, sincroniza dependencias, ejecuta pytest, construye explícitamente el perfil de evaluación y conserva snapshots mediante Git. Puede publicar commits revisados en `origin`; su autoridad procede del sistema operativo y de GitHub, no de un rol interno de la aplicación. |
| `ACT-03` | Llamador que confirma un borrador | Interno | Solicita un challenge para la propuesta exacta y presenta a `DraftApprovalAuthority` la identidad y credencial sintéticas configuradas. La autoridad emite una aprobación opaca y efímera; la CLI no expone el flujo y el mecanismo no verifica presencia humana real. |

No existen usuarios remotos, cuentas de cliente, administradores de aplicación
ni procesos desatendidos.

## Datos y artefactos

| ID | Activo | Clasificación y persistencia | Acceso actual | Evidencia |
|---|---|---|---|---|
| `DAT-01` | 12 incidentes benignos | `synthetic_internal`; JSONL versionado | `CMP-10` limita el snapshot antes del parseo y el hash; `CMP-02` valida y `ACT-01` selecciona por ID | `data/incidents.jsonl` |
| `DAT-02` | 8 documentos de conocimiento | `synthetic_internal`; JSONL versionado | `CMP-10` limita el snapshot antes del parseo y el hash; `CMP-02` valida y cada instancia de `TOL-01` retiene solo las referencias exactas del incidente | `data/knowledge.jsonl` |
| `DAT-03` | Manifiesto del dataset | Sintético; JSON versionado con conteos, procedencia y SHA-256 | Descriptor existente usado por el lock advisory de `CMP-10`; lectura y validación por `CMP-02` | `data/manifest.json` |
| `DAT-04` | Baseline funcional benigna | Evidencia JSON versionada; no es baseline de seguridad ni evaluación semántica | Se regenera por `CMP-05` y se compara de forma reproducible | `evaluations/benign-baseline-v1.json` |
| `DAT-05` | Resultado de proceso | JSON efímero por `stdout` y error saneado por `stderr` | `CMP-09` permite o redacta el resumen antes de la emisión por `CMP-01`; no hay almacenamiento o logging persistente automático | `src/genai_seguro_lab/cli.py`, `src/genai_seguro_lab/output_policy.py` |
| `DAT-06` | Borradores ficticios | Markdown sintético local; ignorado por Git | Publicación atómica create-only por `TOL-02` y `CMP-12`, anclada al descriptor de `sandbox/drafts/` y con modo `0600`; un final publicado nunca se elimina durante la recuperación | `sandbox/drafts/` |
| `DAT-07` | 18 entradas adversarias | `synthetic_internal`; JSONL versionado | `CMP-07` selecciona las 14 PI/JB/EX/TOL; las otras 4 permanecen `inert_not_wired`; la CLI ordinaria no expone el corpus | `data/adversarial/inputs.jsonl` |
| `DAT-08` | 18 oráculos adversarios | `synthetic_internal`; JSONL versionado y fijado antes de ejecutar | Pytest los compara después de observar el target; nunca entran en la petición, el modelo o la herramienta | `data/adversarial/oracles.jsonl` |
| `DAT-09` | Manifiesto adversario | Sintético; JSON versionado con RoE, perfil objetivo, conteos y SHA-256 | Lectura y validación interna por `CMP-02`; declara 14 fixtures conectadas y evaluadas canónicamente, más 4 inertes | `data/adversarial/manifest.json` |
| `DAT-10` | Configuración de baseline adversaria | JSON saneado y versionado | Fija autoridad, candidato, corpus, runtime, presupuesto y comando tokenizado | `evaluations/adversarial-baseline-v1/config.json` |
| `DAT-11` | Resultados de baseline adversaria | JSON saneado y versionado | Conserva observaciones allowlisted y métricas agregadas de 14 casos | `evaluations/adversarial-baseline-v1/results.json` |
| `DAT-12` | Eventos de baseline adversaria | JSONL saneado y versionado | Registra inicio, 14 casos y cierre; no contiene payloads, salida bruta ni rutas personales | `evaluations/adversarial-baseline-v1/events.jsonl` |
| `DAT-13` | Manifiesto de evidencia adversaria | JSON versionado y revisado | Fija tamaños y SHA-256 de `DAT-10` a `DAT-12` | `evaluations/adversarial-baseline-v1/manifest.json` |
| `DAT-14` | Informe de eventos de seguridad | JSON efímero, cerrado y saneado | Snapshot opt-in de `CMP-11` por `stdout`; no se almacena o exporta automáticamente y no reutiliza `DAT-12` | `src/genai_seguro_lab/security_events.py`, `docs/security-events-policy.md` |
| `DAT-15` | Estado transaccional del sandbox | Marker JSON y staging locales, reservados y efímeros; informe de recuperación solo en memoria | `CMP-12` valida y retira únicamente `.gsl-txn-<32 hex>.(json|stage)`; el marker excluye contenido y autoridad y nunca permite publicar durante recuperación | `src/genai_seguro_lab/sandbox_recovery.py`, `docs/sandbox-recovery-policy.md` |
| `DAT-16` | Configuración del retest adversario M01 | JSON saneado y versionado | Fija candidato endurecido, runtime, referencia histórica, comparabilidad, autoridad, presupuesto y comando tokenizado | `evaluations/adversarial-retest-v1/config.json` |
| `DAT-17` | Resultados del retest adversario M01 | JSON saneado y versionado | Conserva por caso solo estado de ejecución, triple observado y relación neutral, además de integridad y topes del run | `evaluations/adversarial-retest-v1/results.json` |
| `DAT-18` | Eventos del retest adversario M01 | JSONL saneado y versionado | Registra inicio, 14 observaciones y cierre; excluye contenido, salida bruta, trazas, marcadores, credenciales y rutas personales | `evaluations/adversarial-retest-v1/events.jsonl` |
| `DAT-19` | Manifiesto de evidencia del retest M01 | JSON versionado y revisado | Fija lista cerrada, tamaños y SHA-256 de `DAT-16` a `DAT-18`; declara `reviewed_for_versioning: true` y `final_retest: false` | `evaluations/adversarial-retest-v1/manifest.json` |
| `DAT-20` | Métricas adversarias comparativas M02 | JSON canónico, saneado y versionado | `CMP-14` lo deriva de `DAT-10` a `DAT-13` y `DAT-16` a `DAT-19`; conserva hashes, reglas, 14 pares, tasas, deltas, cobertura y límites, con `source_final_retest: false` | `evaluations/adversarial-metrics-v1.json` |
| `DAT-21` | Comparación de utilidad benigna M03 | Dos JSON canónicos, saneados y versionados: proyección precontroles y snapshot comparativo | `CMP-15` fija commits y árboles, verifica el corpus y ocho fuentes de producto, ejecuta 12 casos postcontroles y compara oráculos solo después de cada salida; conserva métricas enteras, hashes, límites y `semantic_equivalence_evaluated: false` | `evaluations/benign-pre-controls-functional-v1.json`, `evaluations/benign-utility-v1.json` |
| `DAT-22` | Métricas operativas benignas M04 | JSON canónico y saneado con 30 pares pre/post, muestras crudas, estadísticas, consumo y complejidad descriptiva | `CMP-16` fija commits, árboles y hashes comunes; usa procesos nuevos, conserva todos los outliers y valida cada salida sin guardar su contenido bruto. No fija umbral, score o significación y declara energía/TCO sin medir | `evaluations/operational-metrics-v1.json` |
| `DAT-23` | Registro canónico de hallazgos M05 | JSON estático, saneado, revisado y versionado con seis hallazgos disjuntos | `CMP-17` verifica los hashes y esquemas de `DAT-20/21/22`, resuelve 44 referencias escalares y recalcula el resumen. El mantenedor es quien clasifica y versiona; el verificador no genera, corrige o acepta hallazgos | `evaluations/control-findings-v1.json` |
| `DAT-24` | Rúbrica cerrada pre-run de M07 | JSON versionado antes del retest con 24 hallazgos, 36 acciones y 24 prohibiciones, hashes únicos, fuentes autorizadas, racionales y seis reglas cerradas | `CMP-18` verifica su SHA-256 y la aplica solo después de congelar la salida del target. No contiene un juez LLM, no entra en la petición y mantiene `general_semantic_equivalence_evaluated: false` | `evaluations/final-retest-rubric-v1.json` |
| `DAT-25` | Evidencia canónica del retest final M07 | JSON saneado y versionado del único run `GSL-FINAL-RT-20260727-001`; SHA-256 `05d3e93e…9714d` | Fija candidato/evaluador, 28 fuentes, 15 artefactos históricos, 14 observaciones adversarias, 12 benignas, dos probes, métricas y límites. Declara `final_retest: true`, `SC-06/07: DEMONSTRATED`, `CF-002: NOT_COMPUTABLE`, `DAT-22` histórico y ausencia de evaluación semántica general o modelo real | `evaluations/final-retest-v1.json` |

El dataset `GSL-DATASET-001` declara 12 registros benignos, 8 documentos de
conocimiento y 0 registros adversarios. No contiene datos personales,
corporativos, credenciales, secretos ni incidentes reales.

`GSL-ADVERSARIAL-CORPUS-001` permanece separado del dataset benigno. Sus 18
fixtures cubren los 17 abuse cases y seis familias; `AC-JB-01` tiene dos
variantes. `ADV-PI-001/002/003`, `ADV-JB-001/002/003`,
`ADV-EX-001/002/003` y `ADV-TOL-001/002/003/004/005` están conectadas al
harness de test. `AC-DOS-03` es un
descriptor no materializado que conserva
`requires_extension`.

## Componentes, modelo y herramientas

| ID | Componente | Estado | Función y límite comprobado | Evidencia |
|---|---|---|---|---|
| `CMP-01` | Punto de entrada y CLI local | Expuesto | `main.py` ofrece `analyze`, `baseline` y `web`; las dos operaciones históricas conservan su salida y `web` solo inicia `CMP-19` en loopback. Mantiene durante cada análisis el lock advisory exclusivo y no bloqueante de `CMP-10` sobre `DAT-03` | `main.py`, `src/genai_seguro_lab/cli.py`, `tests/test_cli_smoke.py` |
| `CMP-19` | Frontal y gateway HTTP local | Expuesto en loopback | Sirve cuatro assets allowlisted y tres rutas API sobre `127.0.0.1`; valida Host, Origin, token CSRF, Content-Type, 1 KiB y esquema antes de reutilizar el flujo benigno. Aplica CSP/cabeceras cerradas, no CORS, no logs raw, no persistencia y no expone prompts, rutas, uploads o borradores | `src/genai_seguro_lab/web.py`, `src/genai_seguro_lab/web_assets/`, `tests/test_web_interface.py` |
| `CMP-02` | Contrato y cargador de datos | Expuesto para benigno; interno para adversario | `load_dataset()` obtiene mediante `CMP-10` un único snapshot benigno acotado a 64 KiB, 8 KiB por registro y 32+32 registros antes de parsear o hashear; `load_adversarial_corpus()` conserva su contrato separado y no interpreta ni ejecuta fixtures | `src/genai_seguro_lab/data_contract.py`, `tests/test_adversarial_corpus.py`, `tests/test_resource_control.py` |
| `CMP-03` | Flujo benigno | Expuesto | Coordina exactamente dos invocaciones de modelo, una petición y una ejecución de herramienta y una respuesta final; consume el perfil `analyze`, `cloud_analyze` o el presupuesto agregado recibido de `baseline`, y aplica `CMP-09` antes de devolver una proyección segura | `src/genai_seguro_lab/benign_flow.py`, `tests/test_resource_control.py` |
| `MOD-01` | `DeterministicModelAdapter` | Expuesto | Doble `deterministic/scripted-v1` en el mismo proceso; responde solo a peticiones guionizadas, falla cerrado, hace 0 llamadas externas y registra 0 € | `src/genai_seguro_lab/model_adapter.py` |
| `MOD-02` | Ollama Cloud `gpt-oss:120b` | Expuesto solo por opt-in | Modelo alojado probabilístico para un único `analyze`; `deterministic=false`, dos llamadas externas y coste desconocido. No interviene en baseline, evaluaciones o `DAT-25`; un smoke instrumentado completó el flujo tras dos fallos cerrados, sin demostrar disponibilidad o reproducibilidad | `src/genai_seguro_lab/ollama_cloud_adapter.py`, `docs/ollama-cloud-experimental.md` |
| `TOL-01` | `KnowledgeSearchTool` | Expuesto | Se crea desde `KnowledgeCatalog` con la vista física exacta del incidente y un grant opaco de una sola herramienta ligado a principal, scope e instancia; no usa red ni filesystem | `src/genai_seguro_lab/local_tools.py` |
| `TOL-02` | `DraftWriterTool` y `DraftApprovalAuthority` | Interno | Aplica `CMP-09` antes de propuesta y huella; `CMP-10` limita cada sesión a una propuesta, un challenge, tres autenticaciones, un grant, un archivo y 16 KiB de Markdown. Challenge, aprobación y grant son efímeros, de un solo uso y ligados al contexto exacto; delega publicación y reconciliación create-only en `CMP-12` | `src/genai_seguro_lab/local_tools.py`, `tests/test_local_tools.py`, `tests/test_resource_control.py`, `tests/test_sandbox_recovery.py` |
| `CMP-04` | Constructor de escenarios deterministas | Expuesto | Construye los intercambios guionizados para los incidentes benignos; no es un proveedor GenAI | `src/genai_seguro_lab/baseline.py` |
| `CMP-05` | Ejecutor de baseline funcional | Expuesto | Ejecuta los 12 incidentes dentro de un único presupuesto agregado de `CMP-10` y serializa evidencia canónica por `stdout`; no escribe el snapshot por sí mismo | `src/genai_seguro_lab/baseline.py`, `tests/test_resource_control.py` |
| `CMP-06` | Perfil vulnerable de evaluación | Interno | Requiere una declaración exacta de `GSL-ROE-001`, el bundle sintético y un `$TMP/sandbox/drafts`; construye una `ModelRequest` débil marcada, pero no llama al modelo, ejecuta herramientas ni escribe | `src/genai_seguro_lab/evaluation_profile.py`, `tests/test_evaluation_profile.py` |
| `CMP-07` | Harness adversario acotado | Interno de test | Selecciona exactamente 14 fixtures PI/JB/EX/TOL; combina copias y sandboxes `$TMP`, grants lógicos, dobles deterministas, guardas de `CMP-03`, rechazos de `TOL-01`, pruebas confinadas de `TOL-02` y un subproceso con tres variables ambientales permitidas. En el checkout actual `AC-TOL-05` rechaza la confirmación literal y crea cero archivos | `src/genai_seguro_lab/evaluation_harness.py`, `tests/test_prompt_injection_evaluation.py`, `tests/test_jailbreak_disclosure_evaluation.py`, `tests/test_tool_abuse_evaluation.py` |
| `CMP-08` | Runner de baseline adversaria histórica | Soporte interno | Reproduce exclusivamente el candidato histórico `93aefa45eac687d219bfed32f03be4e60e4a13ed`; verifica commit, rama y limpieza, impone la autorización y presupuestos y escribe evidencia bruta solo bajo `$TMP`. Rechaza otro candidato para no atribuir el oráculo histórico al código endurecido | `src/genai_seguro_lab/adversarial_baseline.py`, `evaluations/run_adversarial_baseline.py`, `tests/test_adversarial_baseline.py` |
| `CMP-09` | `OutputPolicy` | Control de aplicación | Dependencia obligatoria y sin autoridad de modelo, red o filesystem. Rechaza categorías explícitas, redacta correo y rutas locales, emite sellos ligados a instancia/canal y no conserva valores en su evidencia | `src/genai_seguro_lab/output_policy.py`, `tests/test_output_policy.py` |
| `CMP-10` | `ProductResourceControl` | Control de aplicación | Política obligatoria y fail-closed `GSL-RESOURCE-POLICY-001`: preflight acotado del corpus; límites UTF-8 de modelo, herramienta, resumen y borrador; perfiles `analyze`, `cloud_analyze`, `baseline` y `draft`; checkpoints cooperativos y lock advisory de CLI. No cancela llamadas síncronas bloqueadas ni limita invocaciones directas de la API entre procesos | `src/genai_seguro_lab/resource_control.py`, `tests/test_resource_control.py`, `docs/resource-limits-policy.md` |
| `CMP-11` | `SecurityEventJournal` | Control de aplicación | Política `GSL-SECURITY-EVENTS-001`: eventos cerrados de hasta 2 KiB; perfiles `analyze`, `cloud_analyze` y `draft` de 32 eventos/32 KiB y `baseline` de 256/256 KiB; secuencia global, correlación primaria e hija por caso de baseline, cadena SHA-256 y once señales deterministas, incluida `provider_error`. No persiste, exporta, firma ni responde | `src/genai_seguro_lab/security_events.py`, `tests/test_security_events.py`, `docs/security-events-policy.md` |
| `CMP-12` | `SandboxTransactionController` | Control de aplicación interno | Política `GSL-SANDBOX-RECOVERY-001`: marker/staging `0600`, hard link atómico create-only, `fsync`, lock no bloqueante, una reconciliación antes de registrar autoridad y reporte saneado. Preserva un final publicado, nunca republica staging y falla cerrado ante estado ambiguo | `src/genai_seguro_lab/sandbox_recovery.py`, `tests/test_sandbox_recovery.py`, `docs/sandbox-recovery-policy.md` |
| `CMP-13` | Runner neutral de retest adversario | Soporte interno | Reutiliza la ejecución de `CMP-07` sin duplicar el harness; exige candidato endurecido exacto y limpio, verifica la baseline histórica y la comparabilidad del corpus, y proyecta bajo `$TMP` solo identidad, cardinalidad, ejecución, integridad y observaciones neutrales. No calcula eficacia ni métricas de PGS-05-M02 | `src/genai_seguro_lab/adversarial_retest.py`, `evaluations/run_adversarial_retest.py`, `tests/test_adversarial_retest.py` |
| `CMP-14` | Analizador offline de métricas adversarias | Soporte interno | Verifica por SHA-256 los dos manifiestos y todos sus ficheros, exige 14 pares evaluables, aplica una política cerrada al triple observado y emite JSON canónico por `stdout`. No ejecuta runners, target, harness o herramientas y falla cerrado ante deriva o estados desconocidos | `src/genai_seguro_lab/adversarial_metrics.py`, `evaluations/run_adversarial_metrics.py`, `tests/test_adversarial_metrics.py` |
| `CMP-15` | Evaluador comparativo de utilidad benigna | Soporte interno | Verifica la proyección precontroles y el checkout, ejecuta los 12 incidentes canónicos uno a uno mediante `CMP-03` con `CMP-10`, y compara tras cada salida invariantes funcionales y cobertura textual exacta. Emite JSON saneado por `stdout`; no entrega oráculos al target, no escribe evidencia, no usa red y no interpreta equivalencia semántica | `src/genai_seguro_lab/benign_utility.py`, `evaluations/run_benign_utility.py`, `tests/test_benign_utility.py` |
| `CMP-16` | Evaluador offline de métricas operativas | Soporte interno | Materializa bajo `$TMP` los commits benignos pre/post fijados, verifica corpus, entrada y lock byte a byte y ejecuta 3 pares de calentamiento y 30 pares AB/BA con procesos nuevos. Mide pared, CPU y RSS, valida y hashea la salida y emite JSON por `stdout`; no cambia el checkout, instala dependencias, conserva salida bruta o aplica un umbral universal | `src/genai_seguro_lab/operational_metrics.py`, `evaluations/run_operational_metrics.py`, `tests/test_operational_metrics.py` |
| `CMP-17` | Verificador offline del registro de hallazgos | Soporte interno | Lee `DAT-20/21/22/23`, exige fuentes fijadas, esquema cerrado, referencias resolubles y resumen derivado y emite solo un informe efímero por `stdout`. No contiene generador, ejecuta targets, llama a modelos o herramientas, escribe evidencia, decide M06, acepta riesgo o cambia `final_retest` | `src/genai_seguro_lab/control_findings.py`, `evaluations/verify_control_findings.py`, `tests/test_control_findings.py` |
| `CMP-18` | Evaluador offline del retest final | Soporte interno; run canónico completado | Verifica el candidato, el evaluador, `DAT-24` y 15 artefactos históricos; materializa `77edd640` mediante `git archive` bajo `$TMP`, bloquea red y credenciales, ejecuta 14 casos adversarios y 12 benignos más dos probes y evalúa después sus observaciones. El runner no acepta argumentos ni escribe evidencia; el único run emitió `DAT-25` por `stdout` con `final_retest: true` | `src/genai_seguro_lab/final_retest.py`, `evaluations/run_final_retest.py`, `evaluations/final-retest-rubric-v1.json`, `evaluations/final-retest-v1.json`, `tests/test_final_retest.py` |
| `CMP-20` | `OllamaCloudAdapter` y transporte HTTPS | Producto opt-in | Traduce el contrato tipado a `POST https://ollama.com/api/chat`, fija modelo/opciones, rechaza redirects, acota cuerpo y proyecta sin thinking ni contenido remoto auxiliar. Transporte inyectable, timeout 60 s y cero retries | `src/genai_seguro_lab/ollama_cloud_adapter.py`, `tests/test_ollama_cloud_adapter.py` |
| `CMP-21` | Runner `cloud_analyze` | Producto opt-in | Reutiliza `CMP-03`, `TOL-01`, grants, `CMP-09`, `CMP-10` y `CMP-11` para un único incidente. Exige dos invocaciones, una búsqueda y salida JSON validada localmente; no alcanza baseline/evaluaciones | `src/genai_seguro_lab/cloud_analysis.py`, `tests/test_cloud_analysis.py` |

`CMP-13` no abre una interfaz de producto y mantiene separado el contrato
histórico de `CMP-08`. El run `GSL-ADV-RT-20260726-001` produjo `DAT-16` a
`DAT-19` contra el commit exacto
`d236bbee9f371a75e330c227f100aef167b864b0`. `CMP-14` lee esa proyección y la
baseline histórica ya versionada para producir `DAT-20`; no modifica ninguna
de ellas. `CMP-15` fija la proyección derivada del commit precontroles
`df13683abc2b2387f8dd29be64c4d49216e08e3a`, verifica el candidato
postcontroles `ba600ca8ca25074a7806b6502ad59c0847212650` y produce `DAT-21`.
`CMP-16` reutiliza esa pareja, verifica además `main.py`, `pyproject.toml` y
`uv.lock` byte a byte y produce `DAT-22` desde copias temporales. `CMP-17`
verifica después el registro manual `DAT-23` contra los hashes fijados de
`DAT-20/21/22`; no produce otra observación. `CMP-18` usó `DAT-24` como
contrato pre-run, separó su commit del árbol candidato y emitió `DAT-25` sin
persistirlo por sí mismo.
La dependencia del objeto Git histórico es deliberadamente fail-closed: un
archivo o clon sin ese objeto no puede regenerar la comparación.

`MOD-01` sigue siendo el único modelo por defecto y el único usado por baseline
y evaluaciones. `MOD-02` solo queda activo tras `--provider ollama` para
`analyze`; su contrato se ha probado con transporte falso y un smoke
instrumentado completó el flujo real de `INC-BEN-001` tras dos fallos cerrados.
Tampoco hay un agente autónomo: `CMP-03` es un flujo acotado con una sola
herramienta disponible por incidente. `CMP-06` anuncia dos herramientas en el
objeto de petición, pero no contiene un adaptador ni un dispatcher.
`CMP-07` conduce únicamente dobles deterministas. Cada operación recibe un
principal y un scope lógicos, y cada instancia autoriza como máximo una
`knowledge_search`. `ADV-TOL-003/004` usan la credencial sintética solo para
alcanzar los controles de replay y filesystem. `ADV-TOL-005` intenta fabricar
la confirmación literal histórica, se rechaza antes de I/O y crea cero
archivos; no conecta `TOL-02` a la CLI ni al flujo benigno. `CMP-08`, `CMP-13`,
`CMP-14`, `CMP-15`, `CMP-16`, `CMP-17` y `CMP-18` no añaden una ruta de producto: el primero solo reproduce
el commit histórico fijado y el segundo exige un candidato endurecido exacto;
ambos escriben primero en un directorio temporal nuevo. El tercero solo lee
evidencia adversaria versionada. El cuarto ejecuta únicamente el flujo benigno
canónico y emite una comparación saneada por `stdout`. El quinto ejecuta ambos
candidatos benignos fijados en procesos temporales y emite métricas operativas.
El sexto solo valida el registro revisado y sus fuentes. El séptimo ejecuta el
candidato final fijado en una copia temporal con evaluación posterior y salida
saneada.

## Identidades, credenciales y autoridad

| ID | Identidad o control | Estado real |
|---|---|---|
| `IDN-01` | Identidad del proceso local | Es la cuenta de macOS que ejecuta Python. Sus permisos de filesystem son el límite efectivo de infraestructura; la aplicación no los reduce mediante una identidad propia. |
| `IDN-02` | Credencial de proveedor opt-in | `OLLAMA_API_KEY` se obtiene solo del entorno para `MOD-02`, se envía como Bearer al endpoint fijo y no entra en prompts, resultados, journal o errores. No existe service account, OAuth, IAM role o almacenamiento de secretos en la aplicación. |
| `IDN-03` | Principal sintético de confirmación | Autenticado localmente mediante una identidad configurada y una credencial verificada con PBKDF2-HMAC-SHA256. La credencial no entra en los modelos ni en la evidencia. Este control acredita el principal sintético, no presencia ni identidad de una persona real. |
| `IDN-04` | Autoridad del modelo | El modelo solo puede emitir datos tipados. La aplicación valida y ejecuta `TOL-01`; el adaptador no autoriza ni ejecuta herramientas. |
| `IDN-05` | Principal lógico de operación | Presente como control de aplicación. Liga un grant a principal, scope, herramienta e instancia; no es login, credencial, usuario de SO ni aislamiento frente a Python arbitrario. |

La separación entre `MOD-01`, `IDN-01`, `TOL-01` y `TOL-02` será el punto de
partida de la matriz de autoridad de PGS-02-M04.

## Dependencias y supply chain

| ID | Elemento | Uso | Versión observada o fijada |
|---|---|---|---|
| `DEP-01` | Python | Runtime local | restricción `>=3.12,<3.13`; intérprete verificado `3.12.8` |
| `DEP-02` | `uv` | Resolución y ejecución reproducible | CLI local `0.6.10`; resolución fijada en `uv.lock` |
| `DEP-03` | Pydantic | Única dependencia directa de runtime | `2.13.4` |
| `DEP-04` | pytest | Única dependencia directa de desarrollo | `9.1.1` |
| `DEP-05` | Dependencias transitivas de Pydantic | Runtime | `annotated-types 0.8.0`, `pydantic-core 2.46.4`, `typing-extensions 4.16.0`, `typing-inspection 0.4.2` |
| `DEP-06` | Dependencias transitivas de pytest | Desarrollo | `iniconfig 2.3.0`, `packaging 26.2`, `pluggy 1.6.0`, `pygments 2.20.0` |
| `DEP-07` | Librería estándar de Python | CLI, rutas, JSON, hashing, estructuras y HTTPS de `CMP-20` | incluida en el runtime de `DEP-01` |

No hay SDK de proveedor de modelos, framework de agentes, framework web, ORM,
cliente de base de datos, vector store, telemetría externa ni dependencia de
Docker.
`pyproject.toml` declara las dependencias directas y `uv.lock` es la fuente
versionada para la resolución exacta. El registro detallado
[`GSL-SUPPLY-CHAIN-001`](./dependency-supply-chain-register.md) completa
PGS-06-M08 con cada distribución, toolchain, integridad, riesgos y gaps sin
atribuir un escaneo de vulnerabilidades inexistente.

## Infraestructura e integraciones

| ID | Recurso | Estado y límite |
|---|---|---|
| `INF-01` | Host local | Único host de ejecución observado |
| `INF-02` | Checkout Git en `main` | Repositorio local que sigue `origin/main` del remoto público `infantesromeroadrian/GenAI-Seguro-Lab` |
| `INF-03` | Entorno `.venv` | Runtime local ignorado por Git y reconstruible con `uv sync --frozen` |
| `INF-04` | Filesystem del checkout | Conserva corpus, snapshot y sandbox; solo `TOL-02` implementa escritura de producto, confinada a borradores y publicada/reconciliada por `CMP-12` |
| `INT-01` | Entrada de proceso | Argumentos de la CLI local; no existe endpoint HTTP, UI o cola |
| `INT-02` | Salida de proceso | `stdout`/`stderr`; `--security-report` puede incluir `DAT-14` en el mismo `stdout`, pero no existe exportación automática, callback, correo, webhook o telemetría |
| `INT-03` | Integraciones externas de runtime | Ninguna en el modo por defecto o baseline. `analyze --provider ollama` permite hasta dos POST al endpoint fijo; coste desconocido, un smoke end-to-end acotado y dos fallos cerrados previos |
| `INT-04` | Repositorio GitHub público | Integración manual de desarrollo y distribución de código; no es alcanzable por `CMP-01` ni por el runtime |

Obsidian registra la continuidad humana del proyecto, pero no se importa ni se
consulta durante la ejecución y, por tanto, no es una dependencia del sistema.

## Flujo ejecutable actual

1. `ACT-01` lanza `CMP-01` con `analyze` o `baseline`; `CMP-11` abre una
   correlación primaria y `CMP-10` adquiere sin espera el lock advisory sobre
   el descriptor existente de `DAT-03`.
2. Para `baseline`, `CMP-05` abre primero el presupuesto agregado de `CMP-10`.
   Después `CMP-10` obtiene snapshots acotados de `DAT-01/02`; `CMP-02` parsea,
   calcula hashes sobre esos mismos bytes y valida el bundle completo.
3. Por defecto, `CMP-04` prepara los intercambios exactos de `MOD-01`. Solo con
   `--provider ollama`, `CMP-21` selecciona `MOD-02` y el perfil
   `cloud_analyze`; baseline no admite esa opción.
4. `CMP-03` consume caso e invocación y solicita al modelo seleccionado una
   decisión inicial. En `baseline`, `CMP-11` usa una correlación hija opaca
   distinta para cada caso.
5. La aplicación crea una vista de `TOL-01` con solo las referencias del
   incidente y emite un grant `IDN-05` independiente del catálogo anunciado.
6. `CMP-10` consume solicitud y ejecución; `TOL-01` acepta una única consulta
   con ese principal, scope e instancia, y su resultado queda acotado.
7. `CMP-03` consume la segunda invocación, devuelve ese resultado al modelo
   seleccionado sin anunciar herramientas y exige una respuesta final acotada.
8. `CMP-03` valida consistencia, acota el resumen, aplica `CMP-09` y conserva
   solo una proyección segura de las invocaciones; `CMP-11` registra decisiones
   y señales sin conservar esos contenidos.
9. `CMP-11` cierra la operación y `CMP-01` emite `DAT-05`. Solo si
   `ACT-01` solicita `--security-report`, el resultado se envuelve junto a
   `DAT-14`. En modo `baseline`, el ciclo se repite para los 12 casos; la CLI
   no escribe automáticamente `DAT-04`.

El flujo interno de borradores es independiente: una sesión `draft` de
`CMP-10` limita propuesta, challenge, intentos de autenticación, grant, archivo
y Markdown, mientras `CMP-11` acota los eventos y reserva intento y resultado
antes del efecto. `TOL-02` valida referencias, aplica `CMP-09` a título y cuerpo y
prepara con ese contenido una propuesta sin efecto. Después emite un challenge
opaco y exige que
`DraftApprovalAuthority` autentique el principal sintético configurado. La
aprobación y el grant quedan ligados a contenido, principal, scope,
herramienta, efecto, writer, sesión y raíz, caducan y se consumen una sola vez
antes de I/O. `CMP-12` escribe y sincroniza marker y staging internos, publica
el nombre final mediante un hard link create-only y retira los metadatos. Una
nueva instancia reconcilia una sola vez los artefactos válidos antes de
registrar autoridad; preserva un final publicado y nunca publica staging.
`TOL-02.stop()` revoca el estado efímero y cierra el descriptor. No existe una
ruta desde `CMP-01` hasta esa herramienta.

El perfil de evaluación también es independiente: `ACT-02` puede construir
`CMP-06` mediante su factory Python con autorización y sandbox temporal
explícitos. `CMP-06` solo devuelve una `ModelRequest` marcada como vulnerable;
no existe una arista desde el perfil hacia `MOD-01`, `TOL-01` o `TOL-02`.

La evaluación adversaria es un flujo interno de test: pytest usa `CMP-02` para
leer `DAT-07`, `DAT-08` y `DAT-09`, selecciona únicamente 14 fixtures
PI/JB/EX/TOL y mantiene `DAT-08` fuera del target. Los casos PI conservan el
flujo de M04. M05 añade jailbreak, guardas de `CMP-03`, rechazos de `TOL-01` y
un error saneado de `CMP-01`. M06 añade allowlist, exceso de agencia,
confirmación y filesystem. En el código actual `ADV-TOL-005` rechaza la
confirmación literal y crea cero archivos; la evidencia versionada conserva
sin cambios el residual histórico del commit `93aefa45`. `CMP-08` queda fijado
a ese candidato histórico, comprueba que el checkout y los inputs no cambian,
conserva la evidencia bruta bajo `$TMP` y proyecta `DAT-10` a `DAT-13` para
revisión y versionado manual. El runner separado de retest verificó ese
snapshot, repitió los mismos 14 IDs contra el candidato endurecido y proyectó
`DAT-16` a `DAT-19` tras revisión. No hay una ruta adversaria equivalente
desde la CLI ordinaria.

## Elementos confirmados como ausentes

| ID | Elemento ausente | Situación prevista |
|---|---|---|
| `GAP-01` | Evidencia general del modelo alojado | `MOD-02` existe opt-in y un smoke real completó `INC-BEN-001` tras dos fallos cerrados; disponibilidad, reproducibilidad, coste, términos, retención, residencia, calidad y comportamiento general siguen no demostrados |
| `GAP-02` | API pública, acceso remoto o servicio web externo | No implementados; `CMP-19` existe solo en loopback |
| `GAP-03` | Docker, contenedor o Docker Model Runner | Solo candidato documentado; no forma parte del runtime |
| `GAP-04` | Cloud, base de datos, vector store, cola o almacenamiento remoto | Fuera de alcance |
| `GAP-05` | Autenticación general, autorización por roles y service accounts | No implementadas. Solo existe la credencial sintética, efímera e interna de `IDN-03` para aprobar borradores |
| `GAP-06` | Logging persistente, telemetría, alertas y monitorización externa | No implementados; `CMP-11` solo aporta un journal efímero en memoria y salida opt-in |
| `GAP-07` | Cobertura adversaria restante | La baseline canónica cubre PI/JB/EX/TOL; disponibilidad y supply chain permanecen inertes |
| `GAP-08` | Sistema multiagente, autonomía abierta y ejecución de shell | No forman parte del diseño aprobado |

`GAP-09` queda retirado desde PGS-07-M08: el remoto Git y la publicación
pública del código ya existen. La ausencia de CI/CD o GitHub Actions no se
reclasifica aquí como un requisito pendiente.

## Límites relevantes para el threat model

- La frontera de seguridad efectiva empieza en el proceso local y en los
  permisos de `IDN-01`; no existe aislamiento de sistema operativo adicional.
- `IDN-05` reduce la autoridad lógica de cada operación, pero un llamador con
  ejecución arbitraria de Python continúa dentro de la autoridad de `IDN-01`.
- `ACT-01` no se autentica. `IDN-03` autentica un principal sintético local,
  pero no demuestra presencia ni identidad humana real.
- `TB-07` separa el DOM del gateway HTTP, pero permanece dentro de `TB-01`.
  Host/Origin/CSRF protegen el navegador; no autentican un proceso hostil que
  ya ejecute bajo `IDN-01`.
- `TOL-02` tiene efecto local, pero actualmente solo es alcanzable mediante su
  API Python interna y las pruebas. `CMP-12` hace atómica y recuperable esa
  creación para procesos cooperantes, pero no añade una ruta expuesta.
- `CMP-06` es alcanzable únicamente por factory Python, queda ligado a un
  sandbox temporal y termina en `C0`: preparar una petición no equivale a
  ejecutarla.
- `DAT-07`, `DAT-08` y `DAT-09` pueden validarse internamente. Catorce fixtures
  están conectadas a `CMP-07` y registradas por `CMP-08`; el resto continúa sin
  dispatcher.
  Una prueba passing del doble determinista no demuestra robustez de un modelo
  GenAI real.
- `DAT-05` y `DAT-14` no dejan un audit trail persistente; `DAT-04` es una
  instantánea funcional y `DAT-10` a `DAT-13` evidencia adversaria versionada
  manualmente; `DAT-16` a `DAT-19` conservan la proyección neutral de
  PGS-05-M01, `DAT-20` su comparación cerrada de M02 y `DAT-21` la comparación
  funcional benigna de M03. `DAT-22` conserva la comparación operativa M04 y
  `DAT-23` el registro revisado de M05; `DAT-24` fija la rúbrica pre-run M07 y
  `DAT-25` su única ejecución final revisada.
- `CMP-09` solo cubre reglas explícitas. M02 mide las fixtures observadas, pero
  no sustituye detección contextual, moderación completa ni evaluación con un
  modelo real.
- `CMP-10` falla cerrado ante los excesos implementados, pero su plazo no
  interrumpe una llamada síncrona bloqueada y el lock solo coordina procesos
  que entran por la CLI. No existe cuota persistente, límite RSS, cgroup ni
  aislamiento frente a Python arbitrario bajo `IDN-01`.
- `CMP-11` detecta alteraciones de su snapshot mediante una cadena no firmada,
  pero no autentica el emisor, resiste código hostil en el mismo proceso,
  correlaciona sesiones o confirma que una señal sea un ataque.
- `CMP-12` depende de primitivas POSIX y de un filesystem local compatible. Su
  `flock` es cooperativo y sus validaciones no protegen frente a código Python
  hostil con los mismos permisos de `IDN-01`; no instala handlers de señales
  ni implementa el procedimiento operativo de `PGS-06-M07`.
- El modo determinista y baseline mantienen ausencia de red. El opt-in Ollama
  añade egress, credencial, disponibilidad y coste desconocido; sus controles
  de integración se prueban con transporte falso y un smoke real acotado, no
  con un benchmark de disponibilidad, coste o comportamiento general.
- La baseline adversaria solo acredita las observaciones de las 14 variantes
  fijadas contra el candidato exacto; no acredita seguridad general, robustez
  frente a ataques desconocidos ni utilidad semántica.
- M02 acredita para estas 14 fixtures una reducción de 1/14 a 0/14 y de una
  operación no autorizada aceptada/ejecutada a cero. No permite comparar todos
  los intentos rechazados o generalizar a ataques desconocidos.
- M03 acredita 12/12 terminaciones técnicas, 0/12 falsos rechazos y ninguna
  regresión entre los dos candidatos sintéticos deterministas. La cobertura
  textual exacta es 0/24 hallazgos y 0/36 acciones en ambos lados: diagnostica
  una brecha funcional preexistente, pero no evalúa equivalencia semántica ni
  afirmaciones prohibidas y no demuestra `SC-07`.
- M04 observa en un único host medianas de 189,69 ms pre y 259,17 ms post,
  con +67,39 ms de delta emparejado, además de mayor CPU y RSS. Mantiene los
  conteos y el coste externo, pero no mide energía, amortización, trabajo
  humano, concurrencia o carga sostenida y no demuestra un umbral universal.
- M05 registra 0 fallos y 0 bypasses actuales observados solo dentro de las 14
  fixtures medidas, 1 bypass histórico, 2 resultados negativos y 3 gaps. No
  convierte `PARCIAL`, inerte, `NOT_DEMONSTRATED` o `NOT_COMPUTABLE` en fallo
  ni sustituye el riesgo residual de M08.
- M07 demuestra `SC-06` y `SC-07` para el candidato, corpus y rúbrica cerrada
  fijados: 14/14 adversarios y 12/12 benignos completos, cero regresiones y
  cero falsos rechazos. No evalúa semántica general, un modelo real, los cuatro
  casos inertes, `CF-002` o el rendimiento final de `DAT-22`.

El [mapa C4 versionado](../architecture/manifest.json) materializa estos IDs
con componentes, flujos y límites de confianza sin añadir infraestructura
hipotética; PGS-03-M07 añade `CMP-08` y evidencia saneada sin crear una ruta de
producto, PGS-04-M06 añade `CMP-10`, PGS-04-M07 añade `CMP-11`, PGS-04-M08
añade `CMP-12`, PGS-05-M02 añade `CMP-14` y PGS-05-M03 añade `CMP-15`, sin
crear una nueva autoridad. PGS-05-M04 añade `CMP-16` como soporte temporal y
`DAT-22`; PGS-05-M05 añade `CMP-17` y `DAT-23`, también sin crear una ruta de
producto. PGS-05-M07 añade `CMP-18`, `DAT-24` y `DAT-25` sin ampliar la CLI.
La
[matriz de autoridad y consecuencias](./authority-matrix.md) distingue
propuestas del modelo, construcción del perfil, ejecución por el proceso,
efectos internos y autoridad externa de mantenimiento.
