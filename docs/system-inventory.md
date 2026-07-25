# Inventario del sistema actual

## Ficha del inventario

| Campo | Valor |
|---|---|
| Identificador | `GSL-SYS-INV-001` |
| Versión | `1.2.0` |
| Fecha de corte | 2026-07-25 |
| Baseline de código | commit `3c4657efbc7dc92b232b83f3185d27968c2ba78b` + candidato PGS-03-M03 |
| Entorno | checkout local de desarrollo |
| Alcance | estado implementado por PGS-03-M03 |

Este documento inventaría el sistema que existe en el repositorio, no la
solución futura descrita en el roadmap. PGS-03-M03 añade un corpus adversario
inerte con entradas y oráculos separados. Puede validarse mediante una API
Python interna, pero no está conectado al perfil, al modelo, a las herramientas
o a una ejecución.

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
| `ACT-02` | Mantenedor y ejecutor de pruebas | Soporte | Modifica código y corpus, sincroniza dependencias, ejecuta pytest, construye explícitamente el perfil de evaluación y conserva snapshots mediante Git local. Su autoridad procede del sistema operativo y del repositorio, no de un rol interno de la aplicación. |
| `ACT-03` | Llamador que confirma un borrador | Interno | Puede aportar a `DraftWriterTool` una confirmación separada y ligada a la propuesta exacta. La implementación comprueba consentimiento declarado, pero no autentica quién confirma; la CLI actual no expone este flujo. |

No existen usuarios remotos, cuentas de cliente, administradores de aplicación
ni procesos desatendidos.

## Datos y artefactos

| ID | Activo | Clasificación y persistencia | Acceso actual | Evidencia |
|---|---|---|---|---|
| `DAT-01` | 12 incidentes benignos | `synthetic_internal`; JSONL versionado | Lectura por `CMP-02`; selección por `ACT-01` mediante ID | `data/incidents.jsonl` |
| `DAT-02` | 8 documentos de conocimiento | `synthetic_internal`; JSONL versionado | Lectura por `CMP-02`; búsqueda en memoria por `TOL-01` | `data/knowledge.jsonl` |
| `DAT-03` | Manifiesto del dataset | Sintético; JSON versionado con conteos, procedencia y SHA-256 | Lectura y validación por `CMP-02` | `data/manifest.json` |
| `DAT-04` | Baseline funcional benigna | Evidencia JSON versionada; no es baseline de seguridad ni evaluación semántica | Se regenera por `CMP-05` y se compara de forma reproducible | `evaluations/benign-baseline-v1.json` |
| `DAT-05` | Resultado de proceso | JSON efímero por `stdout` y error saneado por `stderr` | Emisión por `CMP-01`; no hay almacenamiento o logging persistente automático | `src/genai_seguro_lab/cli.py` |
| `DAT-06` | Borradores ficticios | Markdown sintético local; ignorado por Git | Creación exclusiva por `TOL-02`; actualmente no hay borradores generados en el checkout | `sandbox/drafts/` |
| `DAT-07` | 18 entradas adversarias | `synthetic_internal`; JSONL versionado e inerte | Lectura solo por la API interna de `CMP-02` y pytest; no llega a la CLI o al modelo | `data/adversarial/inputs.jsonl` |
| `DAT-08` | 18 oráculos adversarios | `synthetic_internal`; JSONL versionado y fijado antes de ejecutar | Lectura solo por la API interna de `CMP-02` y pytest; se mantiene separado de `DAT-07` | `data/adversarial/oracles.jsonl` |
| `DAT-09` | Manifiesto adversario | Sintético; JSON versionado con RoE, perfil objetivo, conteos y SHA-256 | Lectura y validación interna por `CMP-02`; declara cero conexiones y cero ejecuciones | `data/adversarial/manifest.json` |

El dataset `GSL-DATASET-001` declara 12 registros benignos, 8 documentos de
conocimiento y 0 registros adversarios. No contiene datos personales,
corporativos, credenciales, secretos ni incidentes reales.

`GSL-ADVERSARIAL-CORPUS-001` permanece separado del dataset benigno. Sus 18
fixtures cubren los 17 abuse cases y seis familias; `AC-JB-01` tiene dos
variantes. `AC-DOS-03` es un descriptor no materializado que conserva
`requires_extension`.

## Componentes, modelo y herramientas

| ID | Componente | Estado | Función y límite comprobado | Evidencia |
|---|---|---|---|---|
| `CMP-01` | Punto de entrada y CLI local | Expuesto | `main.py` ofrece únicamente `analyze` y `baseline`; ambas operaciones son de solo lectura y sin red | `main.py`, `src/genai_seguro_lab/cli.py` |
| `CMP-02` | Contrato y cargador de datos | Expuesto para benigno; interno para adversario | `load_dataset()` entrega el corpus benigno a la CLI; `load_adversarial_corpus()` valida entradas y oráculos separados, cobertura, límites RoE, conteos y hashes, pero no interpreta ni ejecuta las fixtures | `src/genai_seguro_lab/data_contract.py`, `tests/test_adversarial_corpus.py` |
| `CMP-03` | Flujo benigno | Expuesto | Coordina exactamente dos invocaciones de modelo, una petición de herramienta y una respuesta final; no hay bucle abierto ni reintento | `src/genai_seguro_lab/benign_flow.py` |
| `MOD-01` | `DeterministicModelAdapter` | Expuesto | Doble `deterministic/scripted-v1` en el mismo proceso; responde solo a peticiones guionizadas, falla cerrado, hace 0 llamadas externas y registra 0 € | `src/genai_seguro_lab/model_adapter.py` |
| `TOL-01` | `KnowledgeSearchTool` | Expuesto | Consulta solo documentos ya validados y cargados en memoria; restringe los IDs a las referencias del incidente y no usa red ni filesystem | `src/genai_seguro_lab/local_tools.py` |
| `TOL-02` | `DraftWriterTool` | Interno | Prepara una propuesta y, tras confirmación exacta separada, solo crea un Markdown nuevo en `sandbox/drafts/`; impide rutas, symlinks y sobrescritura | `src/genai_seguro_lab/local_tools.py`, `tests/test_local_tools.py` |
| `CMP-04` | Constructor de escenarios deterministas | Expuesto | Construye los intercambios guionizados para los incidentes benignos; no es un proveedor GenAI | `src/genai_seguro_lab/baseline.py` |
| `CMP-05` | Ejecutor de baseline funcional | Expuesto | Ejecuta los 12 incidentes y serializa evidencia canónica por `stdout`; no escribe el snapshot por sí mismo | `src/genai_seguro_lab/baseline.py` |
| `CMP-06` | Perfil vulnerable de evaluación | Interno | Requiere una declaración exacta de `GSL-ROE-001`, el bundle sintético y un `$TMP/sandbox/drafts`; construye una `ModelRequest` débil marcada, pero no llama al modelo, ejecuta herramientas ni escribe | `src/genai_seguro_lab/evaluation_profile.py`, `tests/test_evaluation_profile.py` |

`MOD-01` es el único modelo activo, pero no es un modelo GenAI real. Tampoco
hay un agente autónomo: `CMP-03` es un flujo acotado y determinista con una sola
herramienta disponible por incidente. `CMP-06` anuncia dos herramientas en el
objeto de petición, pero no contiene un adaptador ni un dispatcher capaz de
invocarlas.

## Identidades, credenciales y autoridad

| ID | Identidad o control | Estado real |
|---|---|---|
| `IDN-01` | Identidad del proceso local | Es la cuenta de macOS que ejecuta Python. Sus permisos de filesystem son el límite efectivo de infraestructura; la aplicación no los reduce mediante una identidad propia. |
| `IDN-02` | Identidad de aplicación o servicio | Ausente. No hay cuenta interna, token de servicio, IAM role, OAuth, API key ni credencial de proveedor. |
| `IDN-03` | Identidad humana de confirmación | No autenticada. `confirmed_by_user: true` y la huella SHA-256 demuestran coincidencia con una propuesta, no la identidad de la persona. |
| `IDN-04` | Autoridad del modelo | El modelo solo puede emitir datos tipados. La aplicación valida y ejecuta `TOL-01`; el adaptador no autoriza ni ejecuta herramientas. |

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
| `INF-01` | Mac local | Único host de ejecución observado; el proyecto es una carpeta física local |
| `INF-02` | Checkout Git en `main` | Repositorio local sin remoto configurado y sin publicación |
| `INF-03` | Entorno `.venv` | Runtime local ignorado por Git y reconstruible con `uv sync --frozen` |
| `INF-04` | Filesystem del checkout | Conserva corpus, snapshot y sandbox; solo `TOL-02` implementa escritura de producto, confinada a borradores |
| `INT-01` | Entrada de proceso | Argumentos de la CLI local; no existe endpoint HTTP, UI o cola |
| `INT-02` | Salida de proceso | `stdout`/`stderr`; no existe exportación, callback, correo, webhook o telemetría |
| `INT-03` | Integraciones externas | Ninguna activa; la baseline registra 0 llamadas externas |

Obsidian registra la continuidad humana del proyecto, pero no se importa ni se
consulta durante la ejecución y, por tanto, no es una dependencia del sistema.

## Flujo ejecutable actual

1. `ACT-01` lanza `CMP-01` con `analyze` o `baseline`.
2. `CMP-02` lee `DAT-01`, `DAT-02` y `DAT-03`, y valida el bundle completo.
3. `CMP-04` prepara los intercambios exactos de `MOD-01`.
4. `CMP-03` solicita a `MOD-01` una decisión inicial.
5. La aplicación autoriza y ejecuta una única consulta de `TOL-01` sobre el
   subconjunto de `DAT-02` permitido por el incidente.
6. `CMP-03` devuelve ese resultado a `MOD-01` y exige una respuesta final.
7. `CMP-01` emite `DAT-05`. En modo `baseline`, el ciclo se repite para los 12
   casos; la CLI no escribe automáticamente `DAT-04`.

El flujo interno de borradores es independiente: `TOL-02` puede preparar una
propuesta y crear `DAT-06` tras recibir una confirmación exacta de `ACT-03`,
pero no existe una ruta desde `CMP-01` hasta esa herramienta.

El perfil de evaluación también es independiente: `ACT-02` puede construir
`CMP-06` mediante su factory Python con autorización y sandbox temporal
explícitos. `CMP-06` solo devuelve una `ModelRequest` marcada como vulnerable;
no existe una arista desde el perfil hacia `MOD-01`, `TOL-01` o `TOL-02`.

La carga adversaria es otro flujo interno independiente: `ACT-02` o pytest
pueden pedir a `CMP-02` que lea `DAT-07`, `DAT-08` y `DAT-09`. El resultado
termina en un bundle tipado en memoria; no existe una arista desde ese bundle
hacia `CMP-06`, `MOD-01`, `TOL-01`, `TOL-02` o `CMP-01`.

## Elementos confirmados como ausentes

| ID | Elemento ausente | Situación prevista |
|---|---|---|
| `GAP-01` | Modelo GenAI real y proveedor | Opcional y desactivado hasta una autorización específica |
| `GAP-02` | Red, API pública o servicio web | Fuera del mínimo viable actual |
| `GAP-03` | Docker, contenedor o Docker Model Runner | Solo candidato documentado; no forma parte del runtime |
| `GAP-04` | Cloud, base de datos, vector store, cola o almacenamiento remoto | Fuera de alcance |
| `GAP-05` | Autenticación, autorización por roles y service accounts | No implementadas |
| `GAP-06` | Logging persistente, telemetría y monitorización | No implementados |
| `GAP-07` | Harness adversario y dispatcher de casos | El corpus inerte ya existe; la conexión y las pruebas pertenecen a PGS-03-M04 a PGS-03-M06 |
| `GAP-08` | Sistema multiagente, autonomía abierta y ejecución de shell | No forman parte del diseño aprobado |
| `GAP-09` | Remoto Git y publicación en GitHub | Pendientes de una decisión separada |

## Límites relevantes para el threat model

- La frontera de seguridad efectiva empieza en el proceso local y en los
  permisos de `IDN-01`; no existe aislamiento de sistema operativo adicional.
- `ACT-01` no se autentica y `IDN-03` no demuestra identidad humana.
- `TOL-02` tiene efecto local, pero actualmente solo es alcanzable mediante su
  API Python interna y las pruebas.
- `CMP-06` es alcanzable únicamente por factory Python, queda ligado a un
  sandbox temporal y termina en `C0`: preparar una petición no equivale a
  ejecutarla.
- `DAT-07`, `DAT-08` y `DAT-09` pueden validarse internamente, pero el bundle
  adversario no está conectado a ningún componente ejecutor. Preparar una
  fixture y su oráculo no equivale a reproducir un ataque.
- `DAT-05` no deja un audit trail persistente; `DAT-04` es una instantánea
  funcional versionada manualmente.
- La ausencia de red y proveedor elimina esas superficies del sistema actual,
  pero deberán inventariarse de nuevo si se incorporan.
- La baseline solo acredita reproducibilidad del flujo benigno; no acredita
  seguridad, robustez adversarial ni utilidad semántica.

El [mapa C4 versionado](../architecture/manifest.json) materializa estos IDs
con componentes, flujos y límites de confianza sin añadir infraestructura
hipotética; PGS-03-M03 incorpora el almacén adversario inerte. La
[matriz de autoridad y consecuencias](./authority-matrix.md) distingue
propuestas del modelo, construcción del perfil, ejecución por el proceso,
efectos internos y autoridad externa de mantenimiento.
