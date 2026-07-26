# Política de validación y allowlists

- **ID:** `GSL-VALIDATION-POLICY-001`
- **Versión:** 1.5
- **Fecha:** 2026-07-26
- **Microtareas:** PGS-04-M02 a PGS-04-M08
- **Ámbito:** flujo benigno determinista y herramientas locales

## Objetivo

Definir una frontera comprobable entre los datos que produce un modelo y las
decisiones que puede aceptar la aplicación. La regla general es:

> La salida del modelo siempre es dato no confiable. Solo un esquema cerrado y
> una allowlist aportada por la aplicación pueden convertirla en una petición
> procesable.

Esta política trata `CTL-05` y los abuse cases `AC-JB-02`, `AC-EX-01`,
`AC-EX-02`, `AC-TOL-01` y `AC-TOL-02`. No atribuye seguridad completa ni
conformidad normativa.

## Entradas del flujo

El flujo ordinario construye dos sobres Pydantic estrictos:

- `BenignTaskInput`: admite únicamente la operación
  `analyze_synthetic_incident` y el ID del incidente.
- `BenignIncidentInput`: admite ID, categoría, título, escenario, indicadores
  y referencias de conocimiento.

Ambos rechazan tipos laxos y campos adicionales. El sobre del incidente omite
deliberadamente `expected_result`, procedencia y metadatos del corpus para no
exponer el oráculo de evaluación al modelo.

Los mensajes conservan además su clase de confianza. Los sobres anteriores no
convierten el escenario en instrucción: continúa siendo
`untrusted_content`.

## Salida del modelo

`ModelResponse.output_text` permanece como transporte bruto en el adaptador.
Esto permite observar respuestas inválidas sin confundir transporte con
autorización.

Antes de devolver un resultado, el flujo ordinario exige que ese texto sea un
JSON válido conforme a `BenignFinalOutput`:

| Campo | Restricción |
|---|---|
| `incident_id` | Debe coincidir con el incidente en curso |
| `summary` | Texto no vacío |
| `knowledge_ids` | IDs únicos y exactamente iguales a los documentos devueltos por la búsqueda autorizada |
| `actions_executed` | Solo admite `false` |
| `compromise_confirmed` | Solo admite `false` |

Los campos adicionales y el texto libre fallan cerrados. Tras estas
comprobaciones, `CMP-09` aplica `GSL-OUTPUT-POLICY-001` al resumen: rechaza
categorías explícitas de alta señal, redacta correo y rutas locales y emite
evidencia sin valores. `BenignAnalysisResult.invocations` conserva solo una
proyección de métricas y no la petición o respuesta brutas. Esta política es
léxica y acotada; no demuestra veracidad ni detección universal.

## Validación y autoridad de herramientas

PGS-04-M03 sustituyó la allowlist autocontenida por
`ToolExecutionGrant`, un grant inmutable emitido y ligado por la aplicación.
Contiene:

- `principal` y `scope` lógicos de la operación;
- exactamente una herramienta: `knowledge_search` o `draft_create`;
- `allowed_knowledge_ids`: IDs de conocimiento únicos autorizados para esa
  invocación;
- un binding opaco a la instancia que puede aceptarlo.

El nombre recibido en `ModelToolRequest` permanece como texto bruto para que
un intento de usar `shell` u otra capacidad desconocida pueda transportarse,
observarse y rechazarse. En cambio, una herramienta desconocida no puede
anunciarse en `ModelRequest.available_tools`.

El catálogo anunciado al modelo no concede autoridad y no se usa para
construir el grant. La política de mínimo privilegio completa está en
[`GSL-LEAST-PRIVILEGE-001`](./least-privilege-policy.md).

### `knowledge_search`

La búsqueda solo se ejecuta cuando:

1. el catálogo de aplicación crea una vista exacta para el incidente;
2. el grant pertenece a esa instancia, principal y scope;
3. el grant permite únicamente `knowledge_search`;
4. los argumentos cumplen `KnowledgeSearchArguments`;
5. todos los IDs solicitados pertenecen a los documentos retenidos.

La salida se construye como `KnowledgeSearchResult`, también estricto e
inmutable.

### `draft_create`

La preparación de un borrador solo se acepta cuando:

1. el grant de preparación pertenece a la instancia y permite únicamente
   `draft_create`;
2. los argumentos cumplen `DraftCreateArguments`;
3. todas las referencias de la propuesta están en el scope autorizado;
4. `CMP-09` permite o redacta título y cuerpo antes de crear la propuesta y
   calcular su huella.

El grant de preparación no concede permiso para escribir. La creación exige
un challenge opaco, autenticación de la identidad sintética configurada y una
aprobación opaca, todos fuera de los datos del modelo. El
`DraftEffectGrant` queda ligado a propuesta, identidad, principal, scope,
herramienta, efecto, writer, sesión, instancia y raíz; caduca y se consume una
sola vez antes de I/O. Este mecanismo no verifica presencia humana real.

### Publicación y recuperación de `draft_create`

Después de consumir el grant, `CMP-12` vuelve a validar el nombre final,
descriptor de raíz, ausencia de destino, límites y namespace interno. Marker,
staging e informe de recuperación usan esquemas estrictos y cerrados. La
reconciliación valida tipo, owner, modo, tamaño, hash, inode y nlinks antes de
retirar únicamente artefactos internos. Un estado ambiguo no se corrige de
forma heurística: impide registrar la autoridad del writer y deja intacto el
sandbox.

La recuperación no acepta contenido o autoridad serializados, no publica el
staging y no expone una ruta CLI. Véase
[`GSL-SANDBOX-RECOVERY-001`](./sandbox-recovery-policy.md).

## Validación de eventos

`GSL-SECURITY-EVENTS-001` usa un esquema Pydantic separado, estricto e
inmutable. Solo acepta taxonomías cerradas, identificadores de correlación
opacos, secuencia, tiempo acotado y hashes. No añade un campo de texto que
necesite sanitización posterior y no serializa el grant o la identidad
presentada. Un evento observa una decisión ya tomada; nunca satisface una
precondición de autoridad.

## Fallo cerrado

| Condición | Resultado observable |
|---|---|
| Argumentos con forma, tipo o campos inválidos | `ToolArgumentsError` |
| Herramienta o referencia fuera de la allowlist | `ToolDeniedError` |
| Grant fabricado o scope que no pertenece a la instancia | `ToolPolicyError` o `ToolDeniedError` |
| Credencial, challenge, aprobación o grant de efecto inválidos | `DraftApprovalError` |
| Salida final sin esquema o inconsistente con la ejecución | `BenignFlowError` |
| Contenido rechazado por la política de salida | `OutputPolicyRejectedError` genérico, sin reflejar el valor |
| Sello de política fabricado, cruzado o de otro canal | `PolicyCheckedTextError` |
| Journal sin capacidad o con ciclo de vida inválido | `SecurityEventError`; no se devuelve salida ni se inicia el efecto |
| Destino final existente | `DraftAlreadyExistsError`; nunca sobrescribe |
| Lock de transacción ocupado | `SandboxRecoveryLockError`; no espera ni reintenta |
| Marker, staging o final incoherentes durante recuperación | `SandboxRecoveryError`; cero mutaciones y writer no disponible |

Los errores no incluyen el contenido adversario ni habilitan una segunda
herramienta, un reintento o una ruta alternativa.

## Evidencia ejecutable

- `tests/test_validation_policy.py`: sobres de entrada, allowlists, afirmaciones
  prohibidas y consistencia de la salida final.
- `tests/test_model_adapter.py`: separación entre transporte de nombres brutos
  y catálogo anunciado.
- `tests/test_local_tools.py`: esquemas, política obligatoria, alcance de datos
  y referencias de borrador, además de los grants ligados por M03.
- `tests/test_benign_flow.py`: integración del ciclo completo.
- `tests/test_output_policy.py`: precedencia, reglas, redacción, opacidad y
  binding del sello de salida.
- `tests/test_instruction_boundary.py`: conservación de las clases de
  confianza.
- `tests/test_security_events.py`: esquema cerrado, correlación, cadena,
  canarios y fallo previo al efecto.
- `tests/test_sandbox_recovery.py`: esquemas internos, owner/modo/hash/nlinks,
  estado ambiguo, lock y publicación create-only.

La baseline benigna canónica debe permanecer idéntica byte a byte después de
incorporar esta política. La evidencia adversaria versionada no se reescribe en
esta microtarea.

## Límites y trabajo posterior

- La evidencia actual usa un adaptador determinista, no un modelo GenAI real.
- El perfil vulnerable aislado conserva su frontera débil para evaluación y no
  representa el comportamiento ordinario.
- PGS-04-M03 reduce la autoridad lógica de identidades, datos y herramientas;
  `IDN-01` conserva los permisos de la cuenta macOS.
- PGS-04-M04 autentica un principal sintético local; una futura interfaz debe
  añadir presencia e identidad humanas reales.
- PGS-04-M05 filtra y redacta categorías explícitas, pero no detecta de forma
  universal secretos codificados, PII, homoglifos, paráfrasis o contenido
  activo.
- `GSL-RESOURCE-POLICY-001` impone límites preventivos de recursos; su plazo
  es cooperativo y no puede interrumpir una dependencia síncrona bloqueada.
- `GSL-SECURITY-EVENTS-001` observa metadatos en memoria; no persiste,
  autentica, responde o prueba un ataque.
- `GSL-SANDBOX-RECOVERY-001` valida y reconcilia el efecto local, pero depende
  de primitivas POSIX y no resiste código hostil con la autoridad de
  `IDN-01`.
- PGS-05-M01 ya repitió el mismo corpus y PGS-05-M02 fijó la comparación
  adversaria inicial; faltan utilidad, operación, bypasses y retest final.
