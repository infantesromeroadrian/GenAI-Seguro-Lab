# Política de validación y allowlists

- **ID:** `GSL-VALIDATION-POLICY-001`
- **Versión:** 1.0
- **Fecha:** 2026-07-25
- **Microtarea:** PGS-04-M02
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

Los campos adicionales y el texto libre fallan cerrados. Esta validación
impide atribuir efectos o conocimiento no autorizados, pero no determina si el
resumen es veraz, seguro o está correctamente redactado; esa política de
contenido pertenece a PGS-04-M05.

## Política de ejecución de herramientas

`ToolExecutionPolicy` es un objeto Pydantic estricto, inmutable y construido
por la aplicación. Contiene:

- `allowed_tools`: subconjunto único de `knowledge_search` y `draft_create`;
- `allowed_knowledge_ids`: IDs de conocimiento únicos autorizados para esa
  invocación.

El nombre recibido en `ModelToolRequest` permanece como texto bruto para que
un intento de usar `shell` u otra capacidad desconocida pueda transportarse,
observarse y rechazarse. En cambio, una herramienta desconocida no puede
anunciarse en `ModelRequest.available_tools`.

### `knowledge_search`

La búsqueda solo se ejecuta cuando:

1. la política permite `knowledge_search`;
2. los argumentos cumplen `KnowledgeSearchArguments`;
3. la allowlist de la política contiene únicamente documentos cargados;
4. todos los IDs solicitados están en esa allowlist.

La salida se construye como `KnowledgeSearchResult`, también estricto e
inmutable.

### `draft_create`

La preparación de un borrador solo se acepta cuando:

1. la política permite `draft_create`;
2. los argumentos cumplen `DraftCreateArguments`;
3. todas las referencias de la propuesta están en la allowlist.

La política no concede permiso para escribir. La creación continúa separada de
la propuesta y exige la confirmación exacta ya existente; la autenticación de
la identidad humana sigue pendiente de PGS-04-M04.

## Fallo cerrado

| Condición | Resultado observable |
|---|---|
| Argumentos con forma, tipo o campos inválidos | `ToolArgumentsError` |
| Herramienta o referencia fuera de la allowlist | `ToolDeniedError` |
| Allowlist de búsqueda que cita datos inexistentes | `ToolPolicyError` |
| Salida final sin esquema o inconsistente con la ejecución | `BenignFlowError` |

Los errores no incluyen el contenido adversario ni habilitan una segunda
herramienta, un reintento o una ruta alternativa.

## Evidencia ejecutable

- `tests/test_validation_policy.py`: sobres de entrada, allowlists, afirmaciones
  prohibidas y consistencia de la salida final.
- `tests/test_model_adapter.py`: separación entre transporte de nombres brutos
  y catálogo anunciado.
- `tests/test_local_tools.py`: esquemas, política obligatoria, alcance de datos
  y referencias de borrador.
- `tests/test_benign_flow.py`: integración del ciclo completo.
- `tests/test_instruction_boundary.py`: conservación de las clases de
  confianza.

La baseline benigna canónica debe permanecer idéntica byte a byte después de
incorporar esta política. La evidencia adversaria versionada no se reescribe en
esta microtarea.

## Límites y trabajo posterior

- La evidencia actual usa un adaptador determinista, no un modelo GenAI real.
- El perfil vulnerable aislado conserva su frontera débil para evaluación y no
  representa el comportamiento ordinario.
- PGS-04-M03 debe reducir los permisos efectivos de identidades, datos y
  herramientas.
- PGS-04-M04 debe autenticar la confirmación humana.
- PGS-04-M05 debe filtrar y redactar contenido.
- PGS-04-M06 debe imponer límites preventivos de recursos.
- PGS-05 debe repetir el mismo corpus y medir el control frente a la baseline.
