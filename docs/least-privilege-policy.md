# Política de mínimo privilegio

- **ID:** `GSL-LEAST-PRIVILEGE-001`
- **Versión:** 1.0
- **Fecha:** 2026-07-25
- **Microtarea:** PGS-04-M03
- **Ámbito:** identidades lógicas, datos y herramientas del runtime local

## Resultado

El laboratorio aplica mínimo privilegio **dentro de la aplicación** mediante
cuatro límites independientes:

1. cada operación recibe un principal y un scope lógicos;
2. cada grant autoriza exactamente una herramienta;
3. la búsqueda retiene únicamente los documentos referenciados por el
   incidente validado;
4. preparar un borrador y crear el archivo son autoridades distintas.

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

`DraftWriterTool` aplica dos autoridades:

1. `prepare_grant` permite validar una petición `draft_create` y producir una
   propuesta sin I/O;
2. `DraftEffectGrant` permite crear una vez el archivo exacto después de
   `authorize_effect()`.

El grant de efecto queda ligado al principal, scope, instancia, raíz,
identidad del objeto propuesta y huella de su contenido. Antes de cualquier
I/O se rechazan:

- propuestas construidas directamente;
- propuestas de otra instancia o raíz;
- grants fabricados o de otro scope;
- huellas distintas y replays.

La raíz `sandbox/drafts/` se abre y conserva mediante un descriptor de
directorio. El destino se crea respecto a ese descriptor con
`O_EXCL | O_NOFOLLOW` y modo `0600`. No se admiten rutas, sobrescritura,
borrado ni seguimiento de symlinks.

`confirmed_by_user: true` sigue siendo una declaración literal no autenticada.
Por eso `ADV-TOL-005` continúa como residual de PGS-04-M04 incluso después de
emitir correctamente el grant de efecto.

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
  extranjeros, propuesta fabricada o cruzada, efecto, replay, symlinks,
  carrera de ruta y modo `0600`.
- `tests/test_benign_flow.py`: integración del principal y scope por incidente.
- `tests/test_validation_policy.py`: una salida del modelo no puede emitir un
  grant.
- `tests/test_jailbreak_disclosure_evaluation.py`: entorno ambiental cerrado
  del subproceso.
- Suite completa y baseline benigna canónica: regresión funcional.

## Estado del control y límites

`CTL-06` permanece `PARCIAL`. PGS-04-M03 demuestra mínimo privilegio lógico en
la aplicación, pero no:

- reduce los permisos de `IDN-01` sobre el checkout;
- crea un usuario, proceso o sandbox de sistema operativo;
- autentica a la persona que confirma;
- protege frente a ejecución arbitraria de Python bajo la cuenta local;
- incorpora filtros M05, cuotas M06 o recuperación M08;
- demuestra robustez frente a un modelo GenAI real.

La siguiente mejora es PGS-04-M04: autenticar y vincular la confirmación humana
sin ampliar las capacidades del modelo.
