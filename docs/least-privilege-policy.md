# Política de mínimo privilegio

- **ID:** `GSL-LEAST-PRIVILEGE-001`
- **Versión:** 1.3
- **Fecha:** 2026-07-26
- **Microtareas:** PGS-04-M03, PGS-04-M04 y PGS-04-M08
- **Ámbito:** identidades lógicas, datos y herramientas del runtime local

## Resultado

El laboratorio aplica mínimo privilegio **dentro de la aplicación** mediante
seis límites independientes:

1. cada operación recibe un principal y un scope lógicos;
2. cada grant autoriza exactamente una herramienta;
3. la búsqueda retiene únicamente los documentos referenciados por el
   incidente validado;
4. preparar un borrador y crear el archivo son autoridades distintas;
5. el efecto exige una aprobación opaca emitida tras autenticar un principal
   sintético local;
6. detener o recuperar una transacción nunca restaura una autoridad consumida
   ni publica un staging pendiente.

Estos controles reducen la autoridad que puede alcanzar una salida del modelo
o un llamador ordinario. No crean una identidad de servicio, no reducen los
permisos de la cuenta macOS y no aíslan procesos hostiles dentro del mismo
intérprete.

## Identidad y scope lógicos

`ToolExecutionGrant` es un objeto inmutable emitido por la aplicación. Liga:

| Campo | Función |
|---|---|
| `principal` | capacidad lógica que actúa, por ejemplo `benign-flow` |
| `scope` | operación exacta, por ejemplo `incident:INC-BEN-001` |
| `tool` | una sola herramienta conocida |
| `allowed_knowledge_ids` | referencias sintéticas permitidas |
| binding opaco | instancia concreta que puede aceptar el grant |

El constructor público rechaza grants sin el emisor interno. La herramienta
comprueba además identidad de objeto, binding, principal, scope, nombre e IDs.
El catálogo anunciado en `ModelRequest.available_tools` solo informa al
modelo: no se copia ni se convierte en autoridad ejecutable.

Estos principales son etiquetas de control de aplicación, no usuarios
autenticados. `IDN-01` continúa siendo la identidad efectiva del proceso y
`IDN-02` continúa ausente.

## Mínimo acceso a conocimiento

`KnowledgeCatalog` conserva el corpus sintético validado bajo control de la
aplicación. Para cada incidente crea una instancia nueva de
`KnowledgeSearchTool` que:

- contiene exactamente `incident.knowledge_refs`, en el mismo orden;
- emite un único grant `knowledge_search` ligado a ese incidente;
- rechaza un ID global válido si no pertenece a la vista;
- rechaza grants de otro principal, scope o instancia;
- no usa filesystem, red ni escritura.

El proceso Python y el catálogo siguen teniendo el bundle completo en memoria
para validar el dataset y ejecutar la baseline. El control reduce lo que
retiene y divulga la herramienta, no proporciona separación de memoria a
nivel de sistema operativo.

## Separación de propuesta y efecto

`DraftWriterTool` y `DraftApprovalAuthority` aplican tres autoridades:

1. `prepare_grant` permite validar una petición `draft_create` y producir una
   propuesta sin I/O;
2. un challenge y una aprobación opacos acreditan el principal sintético
   configurado mediante una credencial local;
3. `DraftEffectGrant` permite crear una vez el archivo exacto después de
   `authorize_effect()`.

Challenge, aprobación y grant tienen TTL, pertenecen a una única sesión y
quedan ligados a identidad configurada, principal, scope, herramienta,
efecto, writer, instancia, raíz, identidad del objeto propuesta y huella de su
contenido. Antes de cualquier I/O se rechazan:

- propuestas construidas directamente;
- propuestas de otra instancia o raíz;
- grants fabricados o de otro scope;
- identidad o credencial incorrectas;
- challenge, aprobación o grant fabricados, caducados, consumidos o de otra
  sesión;
- huellas distintas y replays.

La raíz `sandbox/drafts/` se abre y conserva mediante un descriptor de
directorio. `CMP-12` crea marker y staging internos con `O_EXCL`,
`O_NOFOLLOW` y modo `0600`, sincroniza el contenido y publica el nombre final
mediante un hard link create-only. No se admiten rutas, sobrescritura, borrado
del final ni seguimiento de symlinks.

La credencial se verifica con PBKDF2-HMAC-SHA256 y no forma parte del
`ModelToolRequest`, del `repr` de los objetos opacos ni de la evidencia del
harness. El consumo del grant se realiza antes de I/O: un fallo posterior
exige una nueva aprobación y nunca reintenta implícitamente.

`stop()` revoca la autoridad efímera de la sesión y cierra el descriptor. La
reconciliación de la siguiente instancia solo retira artefactos del namespace
interno validado: nunca recrea propuestas, challenges, aprobaciones, grants o
cuotas, y nunca publica el staging. El contrato completo está en
[`GSL-SANDBOX-RECOVERY-001`](./sandbox-recovery-policy.md).

`ADV-TOL-005` conserva su entrada literal para poder comparar el control con
la baseline histórica, pero el checkout actual la rechaza antes de I/O y crea
cero archivos. La evidencia publicada de PGS-03-M07 permanece inmutable y
continúa describiendo el commit histórico.

## Entorno de subprocesos

La única prueba que lanza una CLI hija, `ADV-EX-003`, ya no copia
`os.environ`. Recibe únicamente:

- `PYTHONDONTWRITEBYTECODE=1`;
- `PYTHONIOENCODING=utf-8`;
- `PYTHONUTF8=1`.

No hereda por esa ruta tokens, credenciales, configuración de proveedor,
`PYTHONPATH` ni otras variables del proceso padre.

## Evidencia ejecutable

- `tests/test_local_tools.py`: proyección física, grants fabricados y
  extranjeros, propuesta fabricada o cruzada, credenciales, binding, TTL,
  cierre, consumo concurrente, efecto, replay, symlinks, carrera de ruta y
  modo `0600`.
- `tests/test_benign_flow.py`: integración del principal y scope por incidente.
- `tests/test_validation_policy.py`: una salida del modelo no puede emitir un
  grant.
- `tests/test_jailbreak_disclosure_evaluation.py`: entorno ambiental cerrado
  del subproceso.
- `tests/test_sandbox_recovery.py`: publicación atómica, revocación,
  reconciliación no autoritativa y fallo cerrado.
- Suite completa y baseline benigna canónica: regresión funcional.

## Estado del control y límites

`CTL-06` permanece `PARCIAL`. PGS-04-M03 demuestra mínimo privilegio lógico en
la aplicación, pero no:

- reduce los permisos de `IDN-01` sobre el checkout;
- crea un usuario, proceso o sandbox de sistema operativo;
- autentica a una persona real o verifica su presencia; PGS-04-M04 solo
  acredita un principal sintético local;
- protege frente a ejecución arbitraria de Python bajo la cuenta local;
- sustituye la política de salida M05; la recuperación M08 y las cuotas M06
  acotan estado y consumo, pero no reducen la autoridad de `IDN-01`;
- convierte eventos o correlaciones de `CMP-11` en identidad, grant,
  autenticación o autorización;
- demuestra robustez frente a un modelo GenAI real.

`CTL-07` permanece `PARCIAL`: el contrato ya autentica y vincula un principal
sintético, caduca y consume cada aprobación, pero una futura interfaz deberá
mostrar el contenido y usar un autenticador con presencia humana verificable.
