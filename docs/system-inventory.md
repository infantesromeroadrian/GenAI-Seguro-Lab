# Inventario del sistema actual

## Ficha del inventario

| Campo | Valor |
|---|---|
| Identificador | `GSL-SYS-INV-001` |
| Versión | `1.9.0` |
| Fecha de corte | 2026-07-26 |
| Baseline adversaria histórica | commit evaluado `93aefa45eac687d219bfed32f03be4e60e4a13ed` + evidencia PGS-03-M07 |
| Control vigente | PGS-04-M04 en esta revisión; el commit exacto se obtiene del historial Git |
| Entorno | checkout local de desarrollo |
| Alcance | estado implementado hasta PGS-04-M04, con baseline histórica PGS-03-M07 y publicación PGS-07-M08 |

Este documento inventaría el sistema que existe en el repositorio, no la
solución futura descrita en el roadmap. PGS-03-M04/M05/M06 conectan 14 fixtures
a pruebas internas y PGS-03-M07 las ejecuta canónicamente contra un commit
limpio: 13 `PASS`, 1 `RESIDUAL`, 0 `FAIL` y 0 `STOPPED`. Los oráculos
permanecen separados del target y las otras cuatro fixtures siguen inertes.
PGS-07-M08 añade un remoto público de desarrollo; ese remoto no forma parte
del runtime ni introduce llamadas externas en la aplicación.
PGS-04-M04 sustituye la confirmación literal por una autoridad local efímera
que autentica un principal sintético y emite aprobaciones opacas. No añade una
interfaz ni demuestra presencia o identidad de una persona real.

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
| `ACT-01` | Operador local del laboratorio | Expuesto | Lanza `analyze` o `baseline`, elige un identificador de incidente y recibe JSON por `stdout`. No inicia sesión en la aplicación; el proceso hereda los permisos de su cuenta local. |
| `ACT-02` | Mantenedor y ejecutor de pruebas | Soporte | Modifica código y corpus, sincroniza dependencias, ejecuta pytest, construye explícitamente el perfil de evaluación y conserva snapshots mediante Git. Puede publicar commits revisados en `origin`; su autoridad procede del sistema operativo y de GitHub, no de un rol interno de la aplicación. |
| `ACT-03` | Llamador que confirma un borrador | Interno | Solicita un challenge para la propuesta exacta y presenta a `DraftApprovalAuthority` la identidad y credencial sintéticas configuradas. La autoridad emite una aprobación opaca y efímera; la CLI no expone el flujo y el mecanismo no verifica presencia humana real. |

No existen usuarios remotos, cuentas de cliente, administradores de aplicación
ni procesos desatendidos.

## Datos y artefactos

| ID | Activo | Clasificación y persistencia | Acceso actual | Evidencia |
|---|---|---|---|---|
| `DAT-01` | 12 incidentes benignos | `synthetic_internal`; JSONL versionado | Lectura por `CMP-02`; selección por `ACT-01` mediante ID | `data/incidents.jsonl` |
| `DAT-02` | 8 documentos de conocimiento | `synthetic_internal`; JSONL versionado | Lectura y validación completa por `CMP-02`; cada instancia de `TOL-01` retiene solo las referencias exactas del incidente | `data/knowledge.jsonl` |
| `DAT-03` | Manifiesto del dataset | Sintético; JSON versionado con conteos, procedencia y SHA-256 | Lectura y validación por `CMP-02` | `data/manifest.json` |
| `DAT-04` | Baseline funcional benigna | Evidencia JSON versionada; no es baseline de seguridad ni evaluación semántica | Se regenera por `CMP-05` y se compara de forma reproducible | `evaluations/benign-baseline-v1.json` |
| `DAT-05` | Resultado de proceso | JSON efímero por `stdout` y error saneado por `stderr` | Emisión por `CMP-01`; no hay almacenamiento o logging persistente automático | `src/genai_seguro_lab/cli.py` |
| `DAT-06` | Borradores ficticios | Markdown sintético local; ignorado por Git | Creación exclusiva y no-follow por `TOL-02`, anclada al descriptor de `sandbox/drafts/` y con modo `0600`; actualmente no hay borradores generados en el checkout | `sandbox/drafts/` |
| `DAT-07` | 18 entradas adversarias | `synthetic_internal`; JSONL versionado | `CMP-07` selecciona las 14 PI/JB/EX/TOL; las otras 4 permanecen `inert_not_wired`; la CLI ordinaria no expone el corpus | `data/adversarial/inputs.jsonl` |
| `DAT-08` | 18 oráculos adversarios | `synthetic_internal`; JSONL versionado y fijado antes de ejecutar | Pytest los compara después de observar el target; nunca entran en la petición, el modelo o la herramienta | `data/adversarial/oracles.jsonl` |
| `DAT-09` | Manifiesto adversario | Sintético; JSON versionado con RoE, perfil objetivo, conteos y SHA-256 | Lectura y validación interna por `CMP-02`; declara 14 fixtures conectadas y evaluadas canónicamente, más 4 inertes | `data/adversarial/manifest.json` |
| `DAT-10` | Configuración de baseline adversaria | JSON saneado y versionado | Fija autoridad, candidato, corpus, runtime, presupuesto y comando tokenizado | `evaluations/adversarial-baseline-v1/config.json` |
| `DAT-11` | Resultados de baseline adversaria | JSON saneado y versionado | Conserva observaciones allowlisted y métricas agregadas de 14 casos | `evaluations/adversarial-baseline-v1/results.json` |
| `DAT-12` | Eventos de baseline adversaria | JSONL saneado y versionado | Registra inicio, 14 casos y cierre; no contiene payloads, salida bruta ni rutas personales | `evaluations/adversarial-baseline-v1/events.jsonl` |
| `DAT-13` | Manifiesto de evidencia adversaria | JSON versionado y revisado | Fija tamaños y SHA-256 de `DAT-10` a `DAT-12` | `evaluations/adversarial-baseline-v1/manifest.json` |

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
| `CMP-01` | Punto de entrada y CLI local | Expuesto | `main.py` ofrece únicamente `analyze` y `baseline`; ambas operaciones son de solo lectura y sin red | `main.py`, `src/genai_seguro_lab/cli.py` |
| `CMP-02` | Contrato y cargador de datos | Expuesto para benigno; interno para adversario | `load_dataset()` entrega el corpus benigno a la CLI; `load_adversarial_corpus()` valida entradas y oráculos separados, cobertura, límites RoE, conteos y hashes, pero no interpreta ni ejecuta las fixtures | `src/genai_seguro_lab/data_contract.py`, `tests/test_adversarial_corpus.py` |
| `CMP-03` | Flujo benigno | Expuesto | Coordina exactamente dos invocaciones de modelo, una petición de herramienta y una respuesta final; no hay bucle abierto ni reintento | `src/genai_seguro_lab/benign_flow.py` |
| `MOD-01` | `DeterministicModelAdapter` | Expuesto | Doble `deterministic/scripted-v1` en el mismo proceso; responde solo a peticiones guionizadas, falla cerrado, hace 0 llamadas externas y registra 0 € | `src/genai_seguro_lab/model_adapter.py` |
| `TOL-01` | `KnowledgeSearchTool` | Expuesto | Se crea desde `KnowledgeCatalog` con la vista física exacta del incidente y un grant opaco de una sola herramienta ligado a principal, scope e instancia; no usa red ni filesystem | `src/genai_seguro_lab/local_tools.py` |
| `TOL-02` | `DraftWriterTool` y `DraftApprovalAuthority` | Interno | Separa preparación, challenge, autenticación sintética, aprobación y grant de efecto. Challenge, aprobación y grant son efímeros, de un solo uso y quedan ligados a identidad configurada, propuesta, principal, scope, herramienta, efecto, writer, sesión y raíz. La creación usa descriptor, `O_EXCL`, `O_NOFOLLOW` y modo `0600` | `src/genai_seguro_lab/local_tools.py`, `tests/test_local_tools.py` |
| `CMP-04` | Constructor de escenarios deterministas | Expuesto | Construye los intercambios guionizados para los incidentes benignos; no es un proveedor GenAI | `src/genai_seguro_lab/baseline.py` |
| `CMP-05` | Ejecutor de baseline funcional | Expuesto | Ejecuta los 12 incidentes y serializa evidencia canónica por `stdout`; no escribe el snapshot por sí mismo | `src/genai_seguro_lab/baseline.py` |
| `CMP-06` | Perfil vulnerable de evaluación | Interno | Requiere una declaración exacta de `GSL-ROE-001`, el bundle sintético y un `$TMP/sandbox/drafts`; construye una `ModelRequest` débil marcada, pero no llama al modelo, ejecuta herramientas ni escribe | `src/genai_seguro_lab/evaluation_profile.py`, `tests/test_evaluation_profile.py` |
| `CMP-07` | Harness adversario acotado | Interno de test | Selecciona exactamente 14 fixtures PI/JB/EX/TOL; combina copias y sandboxes `$TMP`, grants lógicos, dobles deterministas, guardas de `CMP-03`, rechazos de `TOL-01`, pruebas confinadas de `TOL-02` y un subproceso con tres variables ambientales permitidas. En el checkout actual `AC-TOL-05` rechaza la confirmación literal y crea cero archivos | `src/genai_seguro_lab/evaluation_harness.py`, `tests/test_prompt_injection_evaluation.py`, `tests/test_jailbreak_disclosure_evaluation.py`, `tests/test_tool_abuse_evaluation.py` |
| `CMP-08` | Runner de baseline adversaria histórica | Soporte interno | Reproduce exclusivamente el candidato histórico `93aefa45eac687d219bfed32f03be4e60e4a13ed`; verifica commit, rama y limpieza, impone la autorización y presupuestos y escribe evidencia bruta solo bajo `$TMP`. Rechaza otro candidato para no atribuir el oráculo histórico al código endurecido | `src/genai_seguro_lab/adversarial_baseline.py`, `evaluations/run_adversarial_baseline.py`, `tests/test_adversarial_baseline.py` |

`MOD-01` es el único modelo activo, pero no es un modelo GenAI real. Tampoco
hay un agente autónomo: `CMP-03` es un flujo acotado y determinista con una sola
herramienta disponible por incidente. `CMP-06` anuncia dos herramientas en el
objeto de petición, pero no contiene un adaptador ni un dispatcher.
`CMP-07` conduce únicamente dobles deterministas. Cada operación recibe un
principal y un scope lógicos, y cada instancia autoriza como máximo una
`knowledge_search`. `ADV-TOL-003/004` usan la credencial sintética solo para
alcanzar los controles de replay y filesystem. `ADV-TOL-005` intenta fabricar
la confirmación literal histórica, se rechaza antes de I/O y crea cero
archivos; no conecta `TOL-02` a la CLI ni al flujo benigno. `CMP-08` no añade
una ruta de producto: solo reproduce el commit histórico fijado y escribe en
un directorio temporal nuevo.

## Identidades, credenciales y autoridad

| ID | Identidad o control | Estado real |
|---|---|---|
| `IDN-01` | Identidad del proceso local | Es la cuenta de macOS que ejecuta Python. Sus permisos de filesystem son el límite efectivo de infraestructura; la aplicación no los reduce mediante una identidad propia. |
| `IDN-02` | Identidad de aplicación o servicio | Ausente. No hay cuenta interna, token de servicio, IAM role, OAuth, API key ni credencial de proveedor. |
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
| `DEP-07` | Librería estándar de Python | CLI, rutas, JSON, hashing y estructuras | incluida en el runtime de `DEP-01` |

No hay SDK de proveedor de modelos, framework de agentes, framework web, ORM,
cliente de base de datos, vector store, telemetría ni dependencia de Docker.
`pyproject.toml` declara las dependencias directas y `uv.lock` es la fuente
versionada para la resolución exacta.

## Infraestructura e integraciones

| ID | Recurso | Estado y límite |
|---|---|---|
| `INF-01` | Host local | Único host de ejecución observado |
| `INF-02` | Checkout Git en `main` | Repositorio local que sigue `origin/main` del remoto público `infantesromeroadrian/GenAI-Seguro-Lab` |
| `INF-03` | Entorno `.venv` | Runtime local ignorado por Git y reconstruible con `uv sync --frozen` |
| `INF-04` | Filesystem del checkout | Conserva corpus, snapshot y sandbox; solo `TOL-02` implementa escritura de producto, confinada a borradores |
| `INT-01` | Entrada de proceso | Argumentos de la CLI local; no existe endpoint HTTP, UI o cola |
| `INT-02` | Salida de proceso | `stdout`/`stderr`; no existe exportación, callback, correo, webhook o telemetría |
| `INT-03` | Integraciones externas de runtime | Ninguna activa; la baseline registra 0 llamadas externas |
| `INT-04` | Repositorio GitHub público | Integración manual de desarrollo y distribución de código; no es alcanzable por `CMP-01` ni por el runtime |

Obsidian registra la continuidad humana del proyecto, pero no se importa ni se
consulta durante la ejecución y, por tanto, no es una dependencia del sistema.

## Flujo ejecutable actual

1. `ACT-01` lanza `CMP-01` con `analyze` o `baseline`.
2. `CMP-02` lee `DAT-01`, `DAT-02` y `DAT-03`, y valida el bundle completo.
3. `CMP-04` prepara los intercambios exactos de `MOD-01`.
4. `CMP-03` solicita a `MOD-01` una decisión inicial.
5. La aplicación crea una vista de `TOL-01` con solo las referencias del
   incidente y emite un grant `IDN-05` independiente del catálogo anunciado.
6. `TOL-01` acepta una única consulta con ese principal, scope e instancia.
7. `CMP-03` devuelve ese resultado a `MOD-01` y exige una respuesta final.
8. `CMP-01` emite `DAT-05`. En modo `baseline`, el ciclo se repite para los 12
   casos; la CLI no escribe automáticamente `DAT-04`.

El flujo interno de borradores es independiente: `TOL-02` prepara una
propuesta sin efecto, emite un challenge opaco y exige que
`DraftApprovalAuthority` autentique el principal sintético configurado. La
aprobación y el grant quedan ligados a contenido, principal, scope,
herramienta, efecto, writer, sesión y raíz, caducan y se consumen una sola vez
antes de I/O. No existe una ruta desde `CMP-01` hasta esa herramienta.

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
revisión y versionado manual. No hay una ruta adversaria equivalente desde la
CLI ordinaria.

## Elementos confirmados como ausentes

| ID | Elemento ausente | Situación prevista |
|---|---|---|
| `GAP-01` | Modelo GenAI real y proveedor | Opcional y desactivado hasta una autorización específica |
| `GAP-02` | Red, API pública o servicio web | Fuera del mínimo viable actual |
| `GAP-03` | Docker, contenedor o Docker Model Runner | Solo candidato documentado; no forma parte del runtime |
| `GAP-04` | Cloud, base de datos, vector store, cola o almacenamiento remoto | Fuera de alcance |
| `GAP-05` | Autenticación general, autorización por roles y service accounts | No implementadas. Solo existe la credencial sintética, efímera e interna de `IDN-03` para aprobar borradores |
| `GAP-06` | Logging persistente, telemetría y monitorización | No implementados |
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
- `TOL-02` tiene efecto local, pero actualmente solo es alcanzable mediante su
  API Python interna y las pruebas.
- `CMP-06` es alcanzable únicamente por factory Python, queda ligado a un
  sandbox temporal y termina en `C0`: preparar una petición no equivale a
  ejecutarla.
- `DAT-07`, `DAT-08` y `DAT-09` pueden validarse internamente. Catorce fixtures
  están conectadas a `CMP-07` y registradas por `CMP-08`; el resto continúa sin
  dispatcher.
  Una prueba passing del doble determinista no demuestra robustez de un modelo
  GenAI real.
- `DAT-05` no deja un audit trail persistente; `DAT-04` es una instantánea
  funcional y `DAT-10` a `DAT-13` evidencia adversaria versionada manualmente.
- La ausencia de red y proveedor elimina esas superficies del sistema actual,
  pero deberán inventariarse de nuevo si se incorporan.
- La baseline adversaria solo acredita las observaciones de las 14 variantes
  fijadas contra el candidato exacto; no acredita seguridad general, robustez
  frente a ataques desconocidos ni utilidad semántica.

El [mapa C4 versionado](../architecture/manifest.json) materializa estos IDs
con componentes, flujos y límites de confianza sin añadir infraestructura
hipotética; PGS-03-M07 añade `CMP-08` y evidencia saneada sin crear una ruta de
producto. La
[matriz de autoridad y consecuencias](./authority-matrix.md) distingue
propuestas del modelo, construcción del perfil, ejecución por el proceso,
efectos internos y autoridad externa de mantenimiento.
