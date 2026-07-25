# GenAI Seguro Lab

Laboratorio local y reproducible para aprender y demostrar cómo se diseña, ataca, protege y evalúa una aplicación GenAI con herramientas.

> **Estado:** PGS-00-M01 a PGS-00-M06, PGS-01-M01 a PGS-01-M07, PGS-02-M01 a PGS-02-M08, PGS-03-M01 a PGS-03-M04, PGS-07-M08, P01-M01, P01-M04, P01-M05 y P01-M06 completadas. El flujo benigno dispone de interfaz local y baseline funcional; el harness interno ya cubre los tres casos de prompt injection con datos temporales y sin efectos, mientras las otras 15 fixtures permanecen inertes. El código está publicado en un repositorio público, pero todavía no existe un modelo GenAI real, baseline adversaria canónica, proveedor o despliegue cloud.

## En una frase

GenAI Seguro Lab será un asistente que analiza incidentes de ciberseguridad ficticios y permite comparar, con las mismas pruebas, una baseline vulnerable y una versión protegida.

## Identidad y ubicación local

- **Nombre del proyecto:** GenAI Seguro Lab.
- **Nombre de la carpeta:** `GenAI-Seguro-Lab`.
- **Repositorio Git:** inicializado localmente sobre la rama `main`.
- **Repositorio remoto:** [infantesromeroadrian/GenAI-Seguro-Lab](https://github.com/infantesromeroadrian/GenAI-Seguro-Lab).
- **Visibilidad:** pública.
- **Rama publicada:** `main`, con seguimiento de `origin/main`.

## Estructura actual

```text
.
├── .gitignore
├── .python-version
├── README.md
├── main.py
├── plan-proyecto-GenAI-Seguro-Lab.md
├── pyproject.toml
├── uv.lock
├── architecture/
│   ├── manifest.json
│   ├── diagrams/
│   │   ├── application-components.json
│   │   ├── local-containers.json
│   │   └── system-context.json
│   └── descriptions/
├── src/
│   └── genai_seguro_lab/
│       ├── __init__.py
│       ├── baseline.py
│       ├── benign_flow.py
│       ├── cli.py
│       ├── data_contract.py
│       ├── evaluation_harness.py
│       ├── evaluation_profile.py
│       ├── local_tools.py
│       └── model_adapter.py
├── tests/
│   ├── README.md
│   ├── test_benign_flow.py
│   ├── test_cli_smoke.py
│   ├── test_data_contract.py
│   ├── test_evaluation_profile.py
│   ├── test_adversarial_corpus.py
│   ├── test_local_tools.py
│   ├── test_model_adapter.py
│   └── test_prompt_injection_evaluation.py
├── evaluations/
│   ├── README.md
│   └── benign-baseline-v1.json
├── data/
│   ├── README.md
│   ├── incidents.jsonl
│   ├── knowledge.jsonl
│   ├── adversarial/
│   │   ├── README.md
│   │   ├── inputs.jsonl
│   │   ├── oracles.jsonl
│   │   └── manifest.json
│   └── manifest.json
├── docs/
│   ├── README.md
│   ├── abuse-cases.md
│   ├── authority-matrix.md
│   ├── control-responsibility-mapping.md
│   ├── framework-versions.md
│   ├── risk-prioritization.md
│   ├── rules-of-engagement.md
│   ├── system-inventory.md
│   └── threat-crosswalk.md
└── sandbox/
    ├── README.md
    └── drafts/
        └── README.md
```

PGS-01-M02 reserva límites explícitos para código, pruebas, evaluaciones, datos, documentación y borradores. PGS-01-M03 fija el entorno, PGS-01-M04 incorpora el primer corpus verificable, PGS-01-M05 añade la frontera determinista de modelo, PGS-01-M06 implementa el primer flujo benigno con herramientas locales confinadas, PGS-01-M07 fija su interfaz y primera baseline funcional, PGS-03-M02 añade el perfil vulnerable aislado, PGS-03-M03 prepara el corpus adversario y PGS-03-M04 conecta únicamente sus tres casos de prompt injection a pruebas internas. Todavía no existe un modelo GenAI real.

## Entorno reproducible

- Python queda restringido a `>=3.12,<3.13`; `.python-version` selecciona la serie 3.12.
- `uv.lock` fija la resolución completa. En la verificación actual utiliza Python 3.12.8, Pydantic 2.13.4 y pytest 9.1.1.
- Pydantic 2 es una dependencia de ejecución y pytest 9 pertenece al grupo de desarrollo.
- pytest usa configuración TOML nativa, modo estricto, `tests/` como raíz de descubrimiento y `src/` como ruta de importación.
- `[tool.uv] package = false` mantiene deliberadamente el proyecto como
  aplicación local plana. `main.py` resuelve el `src/` del propio checkout y
  ofrece un punto de entrada estable sin instalación editable ni
  `PYTHONPATH`; pytest conserva `src/` como ruta de importación para las
  pruebas.

Reconstrucción y comprobación:

```bash
uv sync --frozen
uv lock --check
uv sync --frozen --check
uv run --frozen pytest --version
```

`.gitignore` excluye entornos, cachés, artefactos de build, credenciales locales comunes y borradores generados, pero no sustituye un escaneo de secretos antes de cada commit. `.env.example` y `sandbox/drafts/README.md` permanecen expresamente versionables.

## Corpus sintético actual

- `data/incidents.jsonl` contiene 12 incidentes benignos ficticios.
- `data/knowledge.jsonl` contiene 8 documentos sintéticos, uno por categoría cubierta.
- `data/manifest.json` fija la versión, los conteos, la procedencia y los hashes SHA-256.
- `src/genai_seguro_lab/data_contract.py` valida el esquema en modo estricto, rechaza campos adicionales y comprueba identificadores, referencias, conteos y hashes.
- El corpus declara `synthetic: true`, sensibilidad `synthetic_internal` y procedencia `authored_for_lab`.
- `data/adversarial/` contiene 18 entradas y 18 oráculos separados para los 17
  abuse cases y seis familias; su manifiesto declara 3 fixtures conectadas a
  test, 15 inertes y 0 evaluaciones canónicas versionadas.
- El dataset benigno conserva cero registros adversarios y sigue siendo el
  único que consume la CLI.

Comprobación específica:

```bash
uv run --frozen pytest tests/test_data_contract.py
uv run --frozen pytest tests/test_adversarial_corpus.py
uv run --frozen pytest tests/test_prompt_injection_evaluation.py
```

## Adaptador determinista actual

`src/genai_seguro_lab/model_adapter.py` define la frontera mínima común de
modelo y un doble de pruebas ejecutado en proceso:

- `ModelAdapter` establece el protocolo de cualquier adaptador futuro.
- Peticiones, mensajes, respuestas y solicitudes de herramienta usan esquemas
  estrictos, inmutables y sin campos adicionales.
- `DeterministicModelAdapter` solo responde a intercambios configurados
  expresamente y los indexa mediante la huella SHA-256 de la petición completa.
- La misma petición produce un resultado serializado idéntico; una petición
  distinta o desconocida falla cerrada sin repetir su contenido en el error.
- El descriptor registra proveedor `deterministic`, modelo `scripted-v1`,
  llamadas externas desactivadas y coste de 0 €.
- Una solicitud de herramienta es solo salida del modelo. El adaptador no
  contiene autorización ni ejecuta herramientas; PGS-01-M06 aplica esa
  autorización fuera del adaptador.

Comprobación específica:

```bash
uv run --frozen pytest tests/test_model_adapter.py
```

## Flujo benigno y herramientas locales

`src/genai_seguro_lab/benign_flow.py` coordina un ciclo deliberadamente
pequeño y reproducible:

```text
incidente sintético
  → modelo determinista
  → una búsqueda de conocimiento autorizada
  → respuesta final del modelo
```

- El primer resultado debe solicitar exactamente una herramienta y el segundo
  debe ser una respuesta final; no existen bucles abiertos ni reintentos.
- `knowledge_search` solo consulta los documentos sintéticos ya cargados en
  memoria y referenciados por el incidente. No accede al sistema de archivos ni
  a la red y el flujo falla cerrado si no obtiene coincidencias autorizadas.
- El incidente enviado al modelo excluye `expected_result` y la procedencia,
  para no filtrar el oráculo de evaluación.
- `draft_create` solo prepara una propuesta tipada. Escribir exige que el
  llamador aporte por separado una confirmación marcada como humana y con la
  huella SHA-256 exacta de esa propuesta; el modelo no puede incluir ni
  fabricar esa confirmación en sus argumentos.
- El nombre del borrador no admite rutas. La escritura queda limitada al
  directorio físico `sandbox/drafts/`, rechaza enlaces simbólicos y utiliza
  creación exclusiva: nunca modifica, sobrescribe o borra.
- La confirmación se consume una sola vez durante el proceso. La política
  `create-only` del destino mantiene el bloqueo de sobrescritura entre
  ejecuciones.
- Esta capa verifica contenido y consentimiento declarado, pero todavía no
  autentica la identidad humana: esa frontera pertenecerá a la futura interfaz.

Comprobación específica:

```bash
uv run --frozen pytest tests/test_benign_flow.py tests/test_local_tools.py
```

## Interfaz local y baseline funcional

`main.py` expone dos operaciones locales, de solo lectura y con salida JSON:

```bash
uv run --frozen python main.py analyze --incident INC-BEN-001
uv run --frozen python main.py baseline
```

- `analyze` ejecuta un incidente benigno por su identificador exacto.
- `baseline` ejecuta los 12 incidentes del corpus y emite el resultado
  completo por `stdout`.
- La ejecución es determinista y no usa red, proveedor externo, secretos,
  escritura de borradores ni gasto.
- `evaluations/benign-baseline-v1.json` conserva la instantánea canónica:
  12/12 casos completados, 24 invocaciones del doble de modelo, 12 consultas
  autorizadas, 0 llamadas externas y 0 €.
- `passed` significa únicamente que el flujo técnico benigno terminó según su
  contrato. Esta evidencia declara `security_baseline: false` y
  `semantic_utility_evaluated: false`; no demuestra resistencia a ataques ni
  calidad semántica.
- Las pruebas smoke comprueban también la ejecución desde fuera del
  repositorio, la estabilidad byte a byte, el fallo saneado ante un
  identificador desconocido y la ausencia de borradores reales.

Comprobación específica:

```bash
uv run --frozen pytest tests/test_cli_smoke.py
```

## Baseline de marcos y fuentes

[docs/framework-versions.md](./docs/framework-versions.md) fija la fotografía
consultada el 25 de julio de 2026:

| Fuente | Versión seleccionada |
|---|---|
| OWASP Top 10 for LLM Applications | Version 2025, documento v2.0 |
| OWASP Top 10 for Agentic Applications | Version 2026 |
| MITRE ATLAS data | release `v2026.06`, `ATLAS.yaml` 5.6.0, commit `651dad9` |
| NIST AI Risk Management Framework | AI RMF 1.0, NIST AI 100-1 |
| NIST SP 800-218A | Final, julio de 2024 |

NIST AI 600-1 queda registrado como perfil GenAI complementario. NIST informa
de que AI RMF 1.0 está siendo revisado; por ello el proyecto conserva 1.0 como
baseline y comprobará de nuevo el estado oficial antes de realizar los mapeos
y el cierre. Este registro no implementa controles ni acredita conformidad.

## Inventario del sistema actual

[docs/system-inventory.md](./docs/system-inventory.md) fija
`GSL-SYS-INV-001`, la fotografía verificable del checkout local antes de
dibujar su arquitectura:

- identifica tres actores, nueve activos de datos, seis componentes, un único
  modelo determinista y dos herramientas;
- distingue lo expuesto por la CLI de lo implementado solo como API interna;
- documenta que el proceso hereda la identidad de macOS y que no existen
  autenticación interna, credenciales de proveedor ni service accounts;
- registra Python, `uv`, las dependencias directas y toda la resolución
  transitiva fijada;
- confirma que el runtime no tiene red, API, Docker, cloud, base de datos,
  vector store, telemetría o modelo GenAI real, y separa de ese runtime el
  repositorio GitHub público usado para desarrollo y distribución;
- asigna IDs estables que PGS-02-M03 y PGS-02-M04 reutilizarán para los trust
  boundaries y la matriz de autoridad.

`DraftWriterTool` existe y está probado, pero no está conectado a `main.py`.
Su confirmación demuestra coincidencia con la propuesta, no autentica la
identidad humana. El inventario describe estas limitaciones sin convertir
componentes planificados en infraestructura desplegada.

## Arquitectura y trust boundaries

[architecture/manifest.json](./architecture/manifest.json) inicializa un mapa
C4 compatible con Tecture, derivado de `GSL-SYS-INV-001`:

- **L1 — contexto:** operador, mantenedor, llamador interno de borradores y
  GenAI Seguro Lab; no aparecen sistemas externos porque no existen
  integraciones activas;
- **L2 — contenedores locales:** terminal, proceso Python, datos versionados,
  evidencia funcional y sandbox de borradores dentro del mismo Mac;
- **L3 — componentes:** CLI, contrato de datos, motor de baseline, flujo
  benigno, modelo determinista, búsqueda autorizada y escritor de borradores.

El mapa hace visibles seis límites:

| ID | Límite de confianza |
|---|---|
| `TB-01` | Host local e identidad heredada del sistema operativo |
| `TB-02` | Control de aplicación dentro del proceso Python |
| `TB-03` | Salida del modelo tratada como datos tipados |
| `TB-04` | Autoridad de herramientas separada del adaptador |
| `TB-05` | Efecto `create-only` en `sandbox/drafts/` |
| `TB-06` | Integridad del corpus mediante esquema y SHA-256 |

`TB-02`, `TB-03` y `TB-04` son límites lógicos en un único proceso, no
aislamiento por contenedor o identidad. En el diagrama L3,
`DraftWriterTool` permanece sin arista de ejecución: está implementada, pero
no conectada a la CLI ni al flujo benigno.

## Matriz de autoridad y consecuencias

[docs/authority-matrix.md](./docs/authority-matrix.md) fija
`GSL-AUTH-MATRIX-001` y convierte el inventario y los trust boundaries en
cadenas de autoridad observables:

- `MOD-01` carece de identidad de ejecución y solo devuelve datos tipados;
- `CMP-03` decide si una propuesta pertenece al único flujo permitido;
- `IDN-01`, la cuenta macOS del proceso, aporta la autoridad efectiva;
- `TOL-01` limita la lectura al subconjunto autorizado del corpus sintético;
- `TOL-02` solo puede crear un borrador confinado mediante su API interna y
  una confirmación exacta que todavía no autentica a la persona;
- `ACT-02`, mediante su cuenta macOS y Git fuera del runtime, posee la mayor
  autoridad actual porque puede modificar código, datos, dependencias y
  evidencia.

La matriz clasifica las consecuencias actuales desde `C0` —datos en memoria—
hasta `C3` —mutación de mantenimiento— y registra las rutas que no existen:
el modelo no ejecuta herramientas, la CLI no alcanza `DraftWriterTool`, la
aplicación no escribe la baseline y no hay red, proveedor, shell o usuario
remoto. Es una descripción del estado implementado, no una evaluación de
riesgo; la priorización se mantiene en un registro separado.

## Catálogo de abuse cases

[docs/abuse-cases.md](./docs/abuse-cases.md) fija
`GSL-ABUSE-CASES-001` con 17 escenarios derivados de la arquitectura y de la
autoridad real:

- 3 de prompt injection;
- 2 de jailbreak;
- 3 de exfiltración;
- 5 de abuso de herramientas;
- 3 de denegación de servicio;
- 1 de supply chain y mantenimiento.

El catálogo separa un caso `SIN-RUTA`, nueve `INTERNO`, seis `MANTENIMIENTO` y
uno `CLI`. Esto evita presentar como exposición activa una entrada que no
existe o atribuir al modelo una modificación que exige permisos de
Git/filesystem.

Los hallazgos más relevantes son que la CLI no acepta prompts libres, que
`TOL-01` permite construir pruebas internas de autorización, que
`DraftWriterTool` sigue sin estar conectada pero acepta una confirmación exacta
sin autenticar a la persona, y que la repetición de procesos es el único caso
de disponibilidad alcanzable por la interfaz ordinaria. No se ejecutó ningún
ataque en esta microtarea.

## Priorización del riesgo actual

[docs/risk-prioritization.md](./docs/risk-prioritization.md) fija
`GSL-RISK-PRIORITY-001`. La puntuación combina el impacto máximo implementado,
la probabilidad condicionada de éxito y la capacidad real de alcanzar la ruta.
No representa frecuencia de incidentes ni severidad universal.

| Prioridad | Casos | Tratamiento |
|---|---:|---|
| `PR-1` | 2 | `AC-TOL-05` y `AC-DOS-01`, después de aprobar las Rules of Engagement |
| `PR-2` | 3 | `AC-EX-03`, `AC-EX-02` y `AC-SC-01` |
| `PR-3` | 11 | regresiones o casos que necesitan un perfil específico |
| `PR-0` | 1 | `AC-PI-01`, en espera porque no existe prompt libre |

El primer residual funcional es la confirmación interna no autenticada de
`DraftWriterTool`. La única superficie adversaria ordinaria es la repetición
de procesos por CLI. Los escenarios de prompt injection y jailbreak se
recalcularán cuando exista un modelo real o el perfil vulnerable cambie su
alcanzabilidad. No se ejecutó ningún ataque durante la priorización.

## Rules of Engagement

[docs/rules-of-engagement.md](./docs/rules-of-engagement.md) fija
`GSL-ROE-001` para las futuras evaluaciones del laboratorio propio:

- delimita activos incluidos y excluye terceros, red, proveedores, datos
  reales y el host como objetivo;
- separa la autorización del usuario, la ejecución de `ACT-01` y la autoridad
  de riesgo de `ACT-02`;
- asigna un vehículo y una restricción a cada uno de los 17 abuse cases;
- establece topes de procesos, tiempo, turnos, tamaño, archivos y memoria;
- exige sandbox y copias temporales para cualquier efecto o corrupción;
- define evidencia saneada y condiciones de parada sin reintento automático.

`AC-DOS-01` queda limitado a un piloto de dos procesos, 20 invocaciones y 60
segundos. `AC-DOS-03` no está autorizado por las reglas base y necesitará una
ampliación posterior. PGS-03-M04 comprueba el rechazo de `--prompt` y ejecuta
los dos casos indirectos en `$TMP`, con dos turnos deterministas, una consulta
autorizada, cero borradores, cero red y sin habilitar una ruta adversaria en la
CLI ordinaria.

## Crosswalk de amenazas

[docs/threat-crosswalk.md](./docs/threat-crosswalk.md) fija
`GSL-THREAT-CROSSWALK-001` y asigna a cada uno de los 17 casos una relación
directa, parcial o ausente con:

- OWASP Top 10 for LLM Applications 2025;
- OWASP Top 10 for Agentic Applications 2026;
- MITRE ATLAS data release `v2026.06`.

El crosswalk conserva gaps deliberados. No usa `LLM08:2025` porque el sistema
no tiene vectores ni embeddings, no fuerza los casos de disponibilidad local
dentro de categorías agentic y no presenta una invocación genérica de
herramienta como equivalente exacto de consentimiento o replay.

La revalidación previa detectó que MITRE publicó `v2026.06` después del
snapshot original. La release mantiene `version: 5.6.0` en `ATLAS.yaml`; las
18 técnicas candidatas conservan identificador, nombre, madurez y tácticas,
aunque cambió la descripción de `AML.T0054 LLM Jailbreak`. No se modificaron
las prioridades ni se ejecutaron ataques.

## Por qué existe

Una aplicación GenAI puede tratar contenido no confiable como si fueran instrucciones, revelar información, utilizar herramientas fuera de contexto o ejecutar una acción que el usuario no pretendía autorizar.

Este proyecto busca demostrar de forma práctica el ciclo:

```text
arquitectura
    ↓
amenaza
    ↓
ataque controlado
    ↓
control
    ↓
retest
    ↓
métricas y riesgo residual
```

El objetivo no es afirmar que un guardrail hace que un sistema sea invulnerable, sino producir evidencia reproducible sobre qué protege, qué no protege y qué coste tiene para la utilidad.

## Usuario y escenario

El usuario inicial será una persona que practica análisis de incidentes en un laboratorio local.

Recibirá un incidente ficticio y podrá pedir al asistente que:

1. consulte una base de conocimiento sintética;
2. resuma los hechos relevantes;
3. proponga una actuación;
4. cree un borrador dentro de un sandbox local.

Algunos documentos del laboratorio contendrán instrucciones adversarias controladas. El sistema deberá distinguir entre el objetivo del usuario y el contenido no confiable.

## Producto mínimo aprobado

El producto mínimo tendrá un único flujo principal:

```text
Usuario
  ↓
Interfaz local
  ↓
Núcleo de la aplicación
  ↓
Adaptador de modelo
  ↓
Solicitud de herramienta
  ↓
Política de autorización y confirmación humana
  ↓
Herramienta confinada al sandbox
  ↓
Respuesta y registro saneado
```

Las dos herramientas aprobadas son:

- **Consulta de conocimiento:** lectura de documentos sintéticos, sin acceso al sistema de archivos general.
- **Creación de borrador:** escritura de una nota ficticia únicamente dentro del sandbox.

Los nombres técnicos y esquemas de implementación se fijarán más adelante. Su autoridad y sus límites funcionales quedan aprobados en el contrato siguiente.

### Decisión PGS-00-M01

Esta definición quedó aprobada el 25 de julio de 2026:

- **Producto:** asistente GenAI local para analizar incidentes de ciberseguridad ficticios.
- **Usuario:** persona que practica análisis de incidentes en un laboratorio propio.
- **Problema:** el contenido no confiable puede desviar al modelo, revelar información o provocar un uso no autorizado de herramientas.
- **Resultado esperado:** comparar una baseline vulnerable y una versión protegida con las mismas pruebas, métricas de seguridad y utilidad, y riesgo residual explícito.
- **Línea seleccionada:** B — seguridad de aplicaciones GenAI.

Esta aprobación no fijó por sí sola las capacidades. Estas quedaron aprobadas después en PGS-00-M02; el stack, la estrategia de modelo y el presupuesto quedaron fijados en PGS-00-M04.

## Componentes previstos

| Componente | Responsabilidad | Límite principal |
|---|---|---|
| Interfaz local | Recibir el incidente y mostrar la respuesta | Sin interfaz pública ni autenticación remota |
| Núcleo de aplicación | Coordinar contexto, modelo, políticas y herramientas | Un único flujo; sin multiagente por defecto |
| Adaptador de modelo | Desacoplar la aplicación del proveedor | Un único proveedor real opcional, aún no elegido |
| Modelo determinista de pruebas | Repetir casos sin variación ni coste externo | No sustituye la validación con un modelo GenAI real |
| Base de conocimiento sintética | Aportar procedimientos e incidentes ficticios | Sin datos personales, corporativos o confidenciales |
| Herramientas | Consultar conocimiento y crear borradores | Permisos mínimos y efectos solo en el sandbox |
| Motor de políticas | Validar capacidad, argumentos y autorización | Ninguna decisión del modelo concede autoridad por sí misma |
| Confirmación humana | Autorizar acciones con efecto | El modelo solo puede proponer |
| Sandbox | Confinar datos y escrituras del laboratorio | Sin acceso a sistemas o cuentas externas |
| Harness de evaluación | Ejecutar los corpus benigno y adversario | Solo contra el proyecto propio |
| Observabilidad | Registrar decisiones, bloqueos y uso de herramientas | Logs estructurados y saneados |
| Documentación de gobierno | Explicar responsables, riesgos y límites | Debe reflejar el sistema real, no aspiraciones |

## Capacidades y autoridad aprobadas

### Matriz de capacidades

| Capacidad | Entrada permitida | Salida o efecto | Autoridad | Confirmación |
|---|---|---|---|---|
| Analizar incidente | Incidente sintético seleccionado y pregunta del usuario | Resumen estructurado con hechos, fuentes, incertidumbres y datos ausentes | Solicitada por el usuario | No |
| Consultar conocimiento | Consulta derivada del incidente y filtros admitidos | Fragmentos de la base sintética autorizada | El modelo puede solicitar; la política valida | No |
| Proponer actuación | Hechos recuperados y contexto autorizado | Recomendación, justificación, riesgos y pasos propuestos | El modelo propone, pero no ejecuta | No |
| Crear borrador | Título, cuerpo y referencias mostrados previamente al usuario | Creación de un archivo nuevo dentro de `sandbox/drafts/` | Solo el usuario concede autoridad | Sí, explícita y de un solo uso |

### Reglas de autoridad

- El modelo puede solicitar una capacidad, pero nunca autorizarla.
- El motor de políticas valida la capacidad, los argumentos y el destino.
- La confirmación del borrador debe mostrar el contenido exacto antes de escribir.
- Si cambian el título, el cuerpo, las referencias o el destino, la confirmación deja de ser válida.
- La creación es `create-only`: no puede sobrescribir, modificar o eliminar otro borrador.
- El resultado de una propuesta nunca puede presentarse como una acción ejecutada.
- El perfil vulnerable solo puede activar capacidades inseguras desde el harness aislado de evaluación.
- Toda capacidad no incluida expresamente en la matriz queda denegada por defecto.

### Accesos expresamente denegados

- Sistema de archivos fuera de la base sintética y `sandbox/drafts/`.
- Shell, ejecución de código, procesos del sistema o instalación de software.
- Red, navegación web, correo, mensajería, APIs o sistemas de tickets.
- Secretos, credenciales, variables de entorno sensibles o datos reales.
- Modificación o eliminación de incidentes, documentos o borradores.
- Activación del perfil vulnerable desde la interfaz normal o por decisión del modelo.

Los límites numéricos de tamaño, tiempo, iteraciones y consumo se fijarán antes de ejecutar la baseline, dentro de PGS-04-M06.

## Stack aprobado

| Área | Decisión |
|---|---|
| Runtime | Python 3.12, restringido a `>=3.12,<3.13` |
| Gestión del proyecto | `uv`, con `pyproject.toml`, `.python-version` y `uv.lock` |
| Validación | Pydantic 2, en modo estricto y rechazando campos adicionales no declarados |
| Pruebas | pytest 9, con fixtures y casos parametrizados |
| Núcleo | Librería estándar para CLI, rutas, JSON/JSONL y logging |
| Interfaz inicial | Línea de comandos local |
| Framework de agentes | Ninguno durante el mínimo viable |
| API pública, base de datos y cloud | No se incorporan durante esta fase |

Las versiones exactas se fijarán en `uv.lock` cuando se inicialice el proyecto. Esta decisión no instala todavía paquetes ni crea código.

## Estrategia de modelo

El diseño contempla dos modos:

1. **Sustituto determinista canónico:** se ejecutará en proceso y permitirá probar políticas, herramientas y trazabilidad de forma reproducible y sin coste externo.
2. **Un único modelo GenAI real opcional:** estará desactivado por defecto y solo se utilizará si aporta evidencia de comportamiento que el sustituto no pueda producir.

No habrá varios proveedores, fallback automático ni reintentos en segundo plano. Cuando se autorice una prueba real, el proveedor, el identificador del modelo y sus parámetros deberán quedar registrados junto al resultado.

### Candidato local: Docker AI

- **Docker Model Runner** es el candidato preferente para la validación opcional con un modelo real local.
- **Docker Compose** se incorporará únicamente si aporta reproducibilidad al empaquetado de la aplicación y el modelo.
- **MCP Gateway** queda fuera del mínimo viable y solo se evaluará si aparecen servidores MCP.
- **Docker Sandboxes** aísla agentes de programación; no sustituye el sandbox de borradores del producto.

La máquina ya dispone del cliente Docker, Compose y el comando `docker model`, pero el daemon no estaba iniciado durante esta comprobación. No se ha arrancado Docker ni descargado ningún modelo.

## Presupuesto aprobado

- Ejecución local y pruebas deterministas: **0 €**.
- Cloud y despliegue: **0 €**.
- Validación opcional con un modelo real: tope acumulado de **5 €** para PGS-01.
- El tope no autoriza gasto ni llamadas a una API; ambas requieren una autorización posterior y específica.
- Al alcanzar el tope, la ejecución se detiene sin recarga ni ampliación automática.

## Amenazas dentro del alcance

- Prompt injection directa.
- Prompt injection indirecta procedente de documentos.
- Jailbreak orientado a saltarse las reglas del laboratorio.
- Revelación de información incluida en el contexto.
- Argumentos manipulados en llamadas a herramientas.
- Uso de una herramienta sin autoridad suficiente.
- Exceso de agencia o acciones sin confirmación.
- Consumo abusivo de iteraciones, tiempo o recursos.
- Fallos de guardrails y degradación de utilidad.
- Riesgos de dependencias y supply chain que realmente incorpore el proyecto.

## Amenazas fuera del alcance inicial

- Envenenamiento de entrenamiento, porque no se entrenará un modelo.
- Membership inference o model extraction, salvo que cambie la arquitectura.
- Explotación de proveedores, cuentas o sistemas de terceros.
- Malware, persistencia o movimiento lateral.
- Ataques contra infraestructura cloud.
- Acciones físicas o decisiones reales sobre personas.

Si la arquitectura cambia, el threat model deberá revisarse antes de ampliar las pruebas.

## Controles previstos

- Separación entre instrucciones de sistema, entrada del usuario y contenido no confiable.
- Esquemas y allowlists para entradas, salidas y argumentos de herramientas.
- Mínimo privilegio para datos, identidades y capacidades.
- Confirmación humana antes de cualquier acción con efecto.
- Filtrado y redacción de información sensible.
- Límites de tamaño, tiempo, iteraciones y consumo.
- Registro de decisiones y eventos de seguridad.
- Parada segura y recuperación del sandbox.
- Tests de regresión para los ataques reproducidos.
- Defensa en profundidad: ningún control se tratará como protección completa.

## Perfil vulnerable

`src/genai_seguro_lab/evaluation_profile.py` implementa
`GSL-PROFILE-VULNERABLE-001` como configuración deliberadamente débil y
exclusiva de evaluación:

- exige una declaración estricta ligada a `GSL-ROE-001`;
- solo acepta el `DatasetBundle` sintético validado y un
  `$TMP/sandbox/drafts` ya existente;
- rechaza el sandbox del checkout canónico;
- construye una `ModelRequest` marcada que mezcla deliberadamente contenido no
  confiable con instrucciones y anuncia `knowledge_search` y `draft_create`;
- no llama al adaptador, no ejecuta herramientas, no escribe archivos, no usa
  red y no está importado ni expuesto por la CLI;
- omite el oráculo `expected_result` de la petición preparada.

El descriptor inmutable declara `default_profile: false`,
`cli_reachable: false`, `external_calls: false` y
`execution_enabled: false`. El corpus adversario ya está preparado y separado;
las microtareas posteriores construirán el harness y su autorización por run.

## Contrato de evidencia

Cada prueba deberá relacionar:

```text
activo
  → amenaza
  → hipótesis
  → entrada
  → resultado de baseline
  → control
  → resultado de retest
  → métrica
  → riesgo residual
```

No se considerará demostrado un control únicamente porque exista en el código.

## Métricas previstas

### Seguridad

- Tasa de éxito de los ataques del corpus.
- Número de llamadas de herramienta no autorizadas.
- Casos con exposición de información.
- Casos detectados, bloqueados o escalados a confirmación humana.

### Utilidad

- Tareas benignas completadas correctamente.
- Falsos rechazos.
- Calidad del resumen o del borrador según el resultado esperado.

### Operación

- Latencia.
- Iteraciones y consumo.
- Errores y recuperaciones.
- Coste, si se utiliza un proveedor externo.

Los tamaños del corpus y los umbrales se fijarán antes de ejecutar la baseline, no después de conocer los resultados.

## Requisitos mínimos

| ID | Requisito observable |
|---|---|
| RF-01 | El sistema analiza un incidente sintético y genera un resumen trazable. |
| RF-02 | El sistema consulta únicamente la base de conocimiento autorizada. |
| RF-03 | El sistema puede crear un borrador solo dentro del sandbox. |
| RF-04 | Toda acción con efecto requiere confirmación humana. |
| RS-01 | El corpus adversario reproduce al menos un fallo contra la baseline vulnerable. |
| RS-02 | El retest utiliza exactamente las mismas entradas que la baseline. |
| RS-03 | Ningún caso crítico endurecido produce una llamada no autorizada. |
| RS-04 | Los logs no contienen secretos ni datos reales. |
| RS-05 | El perfil vulnerable no puede activarse como modo normal de ejecución. |
| RO-01 | Una persona puede reconstruir el laboratorio siguiendo la documentación. |
| RO-02 | Cada claim relevante apunta a una prueba, log o documento versionado. |

## Contrato de datos y límites éticos

### Datos admitidos

El corpus operativo será **100 % sintético**. Cada elemento deberá incluir un identificador, tipo de caso, procedencia, marca `synthetic: true`, sensibilidad y resultado esperado.

| ID | Dato admitido | Condición |
|---|---|---|
| DAT-01 | Incidentes ficticios | No pueden reproducir personas, organizaciones, direcciones, cuentas o eventos reales identificables |
| DAT-02 | Documentos de conocimiento sintéticos | Deben haberse creado para el laboratorio y mantener procedencia |
| DAT-03 | Prompts y documentos adversarios | Deben ser mínimos, seguros, estar etiquetados y dirigirse solo al laboratorio propio |
| DAT-04 | Metadatos de evaluación | Identificador de caso, configuración, resultado esperado, decisión de política, latencia y consumo |
| DAT-05 | Respuestas y borradores generados | Solo a partir de entradas sintéticas y dentro de los artefactos autorizados del proyecto |

Una fuente pública solo podrá utilizarse como referencia para redactar material sintético. Deberán documentarse la URL, autoría, fecha de consulta y licencia o permiso de uso cuando corresponda. No se copiarán incidentes reales ni grandes fragmentos de una fuente al corpus.

### Datos prohibidos

- Datos personales o atributos que permitan identificar o reidentificar a una persona.
- Datos médicos, biométricos, financieros, laborales, educativos o de menores reales.
- Credenciales, secretos, tokens, claves, cookies o variables de entorno sensibles, aunque estén caducados.
- Documentos, código, tickets, correos, logs o incidentes corporativos no creados para este laboratorio.
- Malware ejecutable, payloads operativos, datos robados o instrucciones diseñadas para atacar a terceros.
- Material sin procedencia o sin derecho suficiente para almacenarlo y redistribuirlo.
- Entradas obtenidas mediante vigilancia, scraping de personas o conversaciones sin consentimiento.

La disponibilidad pública de un dato no lo convierte automáticamente en admisible.

### Tratamiento y registro

- El sistema local no tendrá telemetría, subida o exportación automática.
- Los logs normales usarán identificadores de caso y una lista cerrada de campos; no duplicarán prompts, documentos o respuestas completas.
- Los resultados completos solo podrán conservarse como evidencia si proceden del corpus sintético y superan una revisión de secretos y contenido no permitido.
- Las entradas ad hoc no se conservarán por defecto.
- Una integración alojada estará desactivada por defecto y solo podrá recibir el subconjunto sintético expresamente autorizado.
- El acceso por `localhost` a un modelo local también estará desactivado hasta aprobar el adaptador y su endpoint exacto; no concede acceso a otras redes.
- La política detallada de conservación y eliminación se cerrará en PGS-06-M05; hasta entonces no habrá borrado automático ni sincronización externa.

### Acciones permitidas

- Leer casos y documentos incluidos en la base sintética autorizada.
- Analizar y resumir un incidente ficticio.
- Proponer una actuación sin ejecutarla.
- Ejecutar pruebas benignas o adversarias contra el laboratorio propio.
- Crear un archivo nuevo en `sandbox/drafts/` tras una confirmación humana de un solo uso vinculada al contenido exacto.

### Acciones prohibidas

- Acceder a redes externas, web, correo, mensajería, APIs externas, cloud o sistemas de tickets desde el flujo normal.
- Leer o escribir fuera de la base sintética y `sandbox/drafts/`.
- Ejecutar shell, código, procesos, instaladores, malware o payloads.
- Modificar, sobrescribir o eliminar datos, documentos, configuración o borradores.
- Obtener, inferir, revelar o utilizar credenciales, secretos o información sobre personas reales.
- Escanear, probar, evadir controles o actuar contra modelos, cuentas, dispositivos o sistemas de terceros.
- Enviar comunicaciones, abrir incidencias, cambiar permisos, efectuar pagos o producir cualquier otro efecto externo.
- Entrenar o ajustar un modelo con los datos del laboratorio.
- Activar el perfil vulnerable fuera del harness aislado de evaluación.

Toda acción no enumerada como permitida queda denegada por defecto.

### Límites éticos

- El proyecto es educativo y defensivo; no se utilizará para operar un SOC ni responder a incidentes reales.
- Ninguna salida decidirá sobre empleo, crédito, salud, educación, justicia, vigilancia, seguridad física o derechos de una persona.
- Los atributos protegidos quedan fuera del corpus principal. Una futura prueba de equidad requerirá un cambio de alcance y datos sintéticos específicos.
- Las respuestas se identificarán como generadas por IA y no se presentarán como hechos verificados o acciones ejecutadas.
- Los fallos, bypasses, falsos rechazos, degradación de utilidad y riesgo residual se conservarán en la evidencia.
- Los ejemplos adversarios contendrán únicamente el detalle necesario para probar el control dentro del laboratorio.
- Una confirmación humana autoriza solo el borrador mostrado; no concede permiso general ni puede reutilizarse.

### Criterios de aceptación de PGS-00-M05

- [x] **AC-05-01:** el corpus operativo queda limitado a datos sintéticos.
- [x] **AC-05-02:** las categorías admitidas y prohibidas están enumeradas.
- [x] **AC-05-03:** los efectos posibles están limitados a lectura autorizada y creación confirmada de un borrador.
- [x] **AC-05-04:** red, shell, terceros, secretos, datos reales, modificación y borrado están denegados.
- [x] **AC-05-05:** el perfil vulnerable queda confinado al harness de evaluación.
- [x] **AC-05-06:** cualquier proveedor alojado permanece desactivado y no recibe datos sin autorización posterior.
- [x] **AC-05-07:** cada futuro caso deberá declarar procedencia, carácter sintético y resultado esperado.
- [x] **AC-05-08:** los límites éticos son verificables mediante revisión de corpus, configuración, efectos y logs.

## Entregables contractuales

| ID | Entregable observable |
|---|---|
| DEL-01 | Repositorio local reproducible con Python 3.12, `uv`, lockfile, CLI y guía de ejecución |
| DEL-02 | Corpus sintético benigno y adversario con esquema, procedencia y resultados esperados |
| DEL-03 | Arquitectura, flujo de datos, límites de confianza y matriz de capacidad y autoridad |
| DEL-04 | Threat model, abuse cases priorizados y crosswalk con OWASP, MITRE ATLAS y NIST |
| DEL-05 | Perfil vulnerable aislado y harness capaz de reproducir al menos un fallo controlado |
| DEL-06 | Versión endurecida con controles vinculados a amenazas y pruebas |
| DEL-07 | Informe baseline–control–retest con seguridad, utilidad, latencia, consumo y riesgo residual |
| DEL-08 | ADR, registro de riesgos, system/data/model cards, evaluación de impacto, RACI y runbooks |
| DEL-09 | Logs y artefactos saneados con trazabilidad entre requisito, prueba, resultado y límite |
| DEL-10 | Evidencia de reconstrucción limpia y revisión independiente de una prueba benigna y otra adversaria |

## No-objetivos aprobados

- No es un SOC, SIEM ni sistema de respuesta real.
- No está diseñado ni certificado para producción.
- No pretende demostrar seguridad total o invulnerabilidad.
- No cubrirá todas las amenazas posibles contra LLM, agentes o modelos.
- No entrenará ni ajustará un modelo fundacional.
- No reutilizará código o arquitectura de FraudAI-Agent.
- No utilizará datos personales, corporativos, confidenciales o incidentes reales.
- No desplegará en AWS, cloud o una API pública durante esta fase.
- No construirá interfaz gráfica, arquitectura multiagente, múltiples proveedores o toda la plataforma Docker AI sin una necesidad demostrada.
- No ejecutará acciones autónomas fuera del sandbox ni pruebas contra terceros.
- No obtendrá una certificación regulatoria ni afirmará cumplimiento legal integral.
- No publicará resultados de evaluación, releases u otros artefactos externos
  sin una decisión posterior independiente; la publicación pública del código
  fuente fue autorizada expresamente el 2026-07-25.

## Criterios de éxito aprobados

| ID | Criterio verificable |
|---|---|
| SC-01 | Un entorno limpio con Python 3.12 puede ejecutar `uv sync --frozen` y seguir la guía sin dependencias manuales ocultas |
| SC-02 | La suite completa de pytest termina sin fallos |
| SC-03 | El corpus contiene al menos 12 casos benignos y 18 adversarios distribuidos entre seis o más familias de amenaza |
| SC-04 | La baseline fija reproduce al menos un fallo crítico con la misma entrada y configuración |
| SC-05 | En la versión endurecida, ningún caso crítico produce un efecto o llamada de herramienta no autorizados |
| SC-06 | Baseline y retest utilizan exactamente el mismo corpus; la tasa de éxito del ataque disminuye y todo bypass restante queda documentado |
| SC-07 | Al menos el 90 % de los casos benignos conserva el resultado esperado y la tasa de falsos rechazos no supera el 10 % |
| SC-08 | El perfil vulnerable no puede activarse desde el flujo normal |
| SC-09 | Corpus, repositorio, resultados y logs no contienen secretos ni datos reales; los logs respetan su lista cerrada de campos |
| SC-10 | Latencia, iteraciones, consumo y coste se miden para baseline y versión endurecida, aunque no se fija un umbral universal de rendimiento |
| SC-11 | El modo determinista cuesta 0 € y cualquier prueba real respeta el techo autorizado y registra modelo, configuración y coste |
| SC-12 | Una revisión independiente puede reconstruir el proyecto y reproducir al menos un caso benigno y otro adversario |
| SC-13 | Cada afirmación relevante apunta a requisito, versión, prueba, resultado, control y riesgo residual |

Los tamaños y umbrales quedan fijados antes de implementar o ejecutar la baseline. Si una medición demuestra que un criterio es inadecuado, deberá cambiarse mediante una decisión documentada antes del retest final, nunca para ocultar un resultado.

## Política de commits y publicación

- El primer commit contiene juntas PGS-00-M01 a PGS-00-M06 porque todavía no existía Git; no se ha fabricado un historial retroactivo.
- Desde PGS-01, cada microtarea que produzca cambios cerrará con un commit funcional coherente. Código, pruebas y documentación inseparables permanecerán en el mismo commit.
- Una microtarea sin cambios de repositorio no generará un commit vacío.
- El estado del commit y cualquier publicación quedarán registrados en la evidencia de la microtarea.
- El remoto público y el primer `push` fueron autorizados expresamente el
  2026-07-25. Los siguientes pushes conservarán la misma granularidad de los
  commits verificados.

## Estado actual

- [x] Creado el plan inicial.
- [x] Creado este README de definición.
- [x] Aprobar o corregir producto, usuario, problema y resultado esperado.
- [x] Fijar capacidades y permisos.
- [x] Confirmar nombre y ruta.
- [x] Elegir stack, estrategia de modelo y presupuesto.
- [x] Fijar datos admitidos, acciones prohibidas y límites éticos.
- [x] Aprobar criterios de éxito, entregables y no-objetivos.
- [x] Inicializar el repositorio Git local y crear el commit inicial del contrato.
- [x] Crear la estructura mínima de código, tests, evaluaciones, datos y documentación.
- [x] Configurar dependencias reproducibles y exclusión de secretos.
- [x] Crear el dataset sintético de incidentes y la base de conocimiento.
- [x] Implementar el adaptador determinista de modelo para tests.
- [x] Implementar el flujo benigno mínimo y las herramientas confinadas al sandbox.
- [x] Añadir smoke tests y registrar la primera baseline funcional.
- [x] Registrar las versiones consultadas de OWASP, MITRE ATLAS y NIST.
- [x] Inventariar usuarios, datos, modelo, herramientas, identidades, dependencias e infraestructura.
- [x] Dibujar componentes, flujo de datos y trust boundaries.
- [x] Crear la matriz de autoridad y consecuencias.
- [x] Enumerar los abuse cases del sistema actual.
- [x] Priorizar los abuse cases por impacto, probabilidad condicionada y capacidad real.
- [x] Mapear las amenazas a OWASP y MITRE ATLAS.
- [x] Mapear responsables y controles previstos a NIST AI RMF y NIST SP 800-218A.
- [x] Definir las Rules of Engagement del laboratorio propio.
- [x] Crear el perfil vulnerable aislado y exclusivo para evaluación.
- [x] Preparar el corpus adversario con entradas y resultados esperados.
- [x] Implementar pruebas para prompt injection directa e indirecta.
- [x] Crear el repositorio público y publicar `main` en GitHub.

**PGS-00-M01 a PGS-00-M06, PGS-01-M01 a PGS-01-M07, PGS-02-M01 a PGS-02-M08, PGS-03-M01 a PGS-03-M04, PGS-07-M08, P01-M01, P01-M04, P01-M05 y P01-M06 están completadas.** El avance interno es **26 de 66 microtareas (39,4 %)**; SEC-1 permanece abierto hasta producir la evidencia técnica posterior. P01-M07 sigue abierta hasta completar las pruebas y P01-M08 hasta implementar y verificar PGS-04.

## Roadmap

El desglose completo de fases, microtareas, dependencias y trazabilidad está en:

[Plan del proyecto GenAI Seguro Lab](./plan-proyecto-GenAI-Seguro-Lab.md)

La siguiente microtarea es:

**PGS-03-M05 — implementar pruebas para jailbreak y revelación de información.**

## Uso responsable

Las pruebas se limitarán al laboratorio propio, con un corpus operativo sintético y sin efectos fuera del sandbox. Este proyecto no autoriza pruebas contra sistemas de terceros.
