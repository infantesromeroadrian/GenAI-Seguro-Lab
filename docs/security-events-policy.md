# Política de eventos y señales de seguridad

## Identidad y alcance

- **ID:** `GSL-SECURITY-EVENTS-001`
- **Versión:** `1.1.0`
- **Microtareas:** `PGS-04-M07` y `PGS-06-M05`
- **Propietario:** `ACT-02`, mantenedor del laboratorio
- **Ámbito:** operaciones `analyze`, `cloud_analyze` y `baseline`, flujo
  benigno, búsqueda autorizada, política de salida, límites de recursos y
  sesión interna de borradores

Esta política añade observabilidad de producto sin crear una nueva autoridad
ni un canal de telemetría. El journal vive únicamente en memoria durante una
operación o sesión. No reutiliza los eventos históricos de
`GSL-BASELINE-ADVERSARIAL-001`, no escribe ficheros y no envía datos por red.

## Contrato cerrado

Cada `SecurityEvent` es inmutable, rechaza campos adicionales y admite solo:

| Campo | Contenido permitido |
|---|---|
| `control_id`, `version` | Identidad fija del contrato |
| `sequence` | Secuencia global contigua de la operación |
| `correlation_id` | Identificador opaco aleatorio, independiente del contenido |
| `elapsed_ms` | Tiempo monotónico acotado, sin fecha, zona o dato del usuario |
| `kind`, `source`, `outcome` | Valores de taxonomías cerradas |
| `signal` | Regla determinista allowlisted o `null` |
| `previous_event_sha256`, `event_sha256` | Enlace y huella de la cadena canónica |

No existe ningún campo de texto libre. Se prohíben expresamente prompts,
respuestas, argumentos, conocimiento recuperado, resúmenes, títulos, cuerpos,
rutas, entorno, credenciales, identidad presentada, tokens de autoridad,
mensajes de excepción y tracebacks. Cada evento ocupa como máximo 2 KiB.

## Correlación y ciclo de vida

1. El journal crea una correlación primaria opaca y registra
   `operation_started`.
2. `analyze` y `cloud_analyze` usan esa correlación durante todo el caso.
3. `baseline` mantiene la correlación primaria para el inicio y el cierre, y
   crea una correlación hija opaca distinta para cada uno de sus 12 casos. El
   ID del incidente no entra en el evento.
4. Todos los eventos comparten una única secuencia global contigua y una
   cadena SHA-256 canónica.
5. El journal termina una sola vez con `operation_completed` o
   `operation_failed`. En la sesión de borrador, `TOL-02.stop()` deriva el
   terminal del estado conocido y lo emite una sola vez.

Las correlaciones ordenan evidencia dentro de una operación. No enlazan
sesiones distintas, no derivan de datos y no son credenciales, grants ni
prueba de identidad.

## Perfiles y límites

| Perfil | Eventos máximos | Bytes acumulados máximos | Uso |
|---|---:|---:|---|
| `analyze` | 32 | 32 KiB | Un incidente benigno |
| `cloud_analyze` | 32 | 32 KiB | Un incidente sintético con proveedor alojado |
| `baseline` | 256 | 256 KiB | Doce casos en una operación |
| `draft` | 32 | 32 KiB | Una sesión interna de borrador |

El journal reserva capacidad para el evento terminal antes de cada append. En
la escritura de un borrador reserva atómicamente dos eventos —intento y
resultado— antes de consumir el grant o iniciar I/O. Si no puede conservar la
evidencia necesaria, la operación falla cerrada y no devuelve salida ni inicia
el efecto. No existe reintento ni emisión recursiva de un evento de error.

Estos límites son propios de `CMP-11`; complementan, pero no se suman a los
contadores de `GSL-RESOURCE-POLICY-001`.

## Señales implementadas

| Señal | Condición observable |
|---|---|
| `unexpected_flow_sequence` | Cardinalidad, orden o consistencia imposible en el flujo |
| `unknown_model_request` | Petición de modelo no guionizada o herramienta desconocida |
| `tool_denied` | Nombre, grant, scope o referencias de herramienta rechazados |
| `output_policy_intervention` | `CMP-09` redacta o rechaza una salida |
| `resource_limit_exceeded` | `CMP-10` rechaza tamaño, tiempo, iteración o consumo |
| `lock_conflict` | La CLI no puede adquirir su lock cooperativo |
| `authentication_failures_repeated` | Tercer fallo de autenticación en la misma correlación |
| `authorization_replay_or_context_mismatch` | Token reutilizado, caducado, ajeno o ligado a otro contexto |
| `sandbox_violation` | Raíz, destino o condición no-follow del borrador rechazada |
| `data_integrity_violation` | Corpus benigno no disponible, malformado o incoherente |
| `provider_error` | El proveedor alojado no está configurado, no responde o devuelve un contrato rechazado |

Son reglas deterministas sobre decisiones ya tomadas por la aplicación. Una
señal no demuestra un ataque, compromiso, autoría o anomalía universal, y no
activa por sí misma respuesta, bloqueo adicional, rollback o comunicación.
PGS-04-M08 conserva este límite: `CMP-12` actúa por la condición real de su
transacción y no por releer una señal de `CMP-11`.

## Exposición por CLI

El comportamiento predeterminado permanece byte a byte compatible:

```bash
uv run --frozen python main.py analyze --incident INC-BEN-001
uv run --frozen python main.py analyze --incident INC-BEN-001 --provider ollama
uv run --frozen python main.py baseline
```

La opción explícita `--security-report` devuelve por `stdout` un sobre JSON
con dos claves: `result` y `security_report`.

```bash
uv run --frozen python main.py analyze --incident INC-BEN-001 --security-report
uv run --frozen python main.py analyze --incident INC-BEN-001 --provider ollama --security-report
uv run --frozen python main.py baseline --security-report
```

El informe es una copia inmutable y saneada del journal. No se escribe
automáticamente, no se mezcla con `stderr`, no se configura mediante variables
de entorno y no se exporta a un SIEM o servicio externo.

## Integridad y límites de la garantía

La serialización canónica, la secuencia, los enlaces y las huellas SHA-256
permiten detectar alteraciones accidentales o internas del snapshot. La cadena
no está firmada ni anclada fuera del proceso: no ofrece autenticidad,
no repudio o resistencia frente a código hostil con autoridad dentro del mismo
proceso.

Quedan fuera de esta microtarea:

- logging persistente, búsqueda o correlación entre sesiones;
- SIEM, métricas remotas, alertas, telemetría o exportación automática;
- detección de anomalías mediante ML o cobertura universal de secretos y PII;
- respuesta operativa general, comunicación, rollback de un final publicado o
  retirada en el runtime; el procedimiento humano se define en
  [`GSL-AI-IR-001`](./ai-incident-response-runbook.md);
- usar el journal como estado duradero o autoridad de recuperación;
- acreditar un modelo GenAI real, proveedor, MCP o aislamiento de SO.

## Política de logs, redacción, conservación y eliminación

PGS-06-M05 gobierna el ciclo de vida de los datos observables sin añadir
persistencia a la aplicación. La regla por defecto es **no recopilar** texto
libre ni conservar automáticamente una salida. Todo dato se reduce al mínimo
antes de abandonar el componente que lo origina.

### Redacción antes de emitir

1. El contrato de `SecurityEvent` es una allowlist; un campo no declarado se
   rechaza en lugar de serializarse.
2. Prompts, respuestas, argumentos, conocimiento, contenido de borradores,
   rutas, entorno, credenciales, tokens, excepciones y tracebacks nunca son
   campos permitidos.
3. `CMP-09` redacta la salida de producto antes de entregarla o incorporarla a
   una propuesta. La señal solo registra que hubo intervención, no el valor.
4. Los runners que producen evidencia versionable conservan únicamente
   proyecciones y agregados declarados; la salida bruta no se convierte
   automáticamente en artefacto.
5. Si una revisión encuentra un secreto, dato personal o ruta privada, se
   detiene la publicación. La redacción posterior no convierte una exposición
   previa en inexistente.

### Matriz de ciclo de vida

<!-- log-lifecycle:start -->
| ID | Clase | Persistencia y acceso | Conservación | Eliminación o cierre | Verificación y límite |
|---|---|---|---|---|---|
| `LOG-01` | Journal de seguridad en memoria | Solo proceso local durante `analyze`, `baseline` o sesión de borrador | Hasta terminar la operación o proceso; sin retención entre sesiones | La aplicación libera su referencia al finalizar; no implementa borrado seguro de RAM | Un proceso nuevo no puede consultar el journal anterior. El SO y el runtime pueden conservar copias fuera del control demostrable |
| `LOG-02` | Resultado e informe opcional por `stdout` | No se almacena por la aplicación; visible al operador que ejecuta la CLI | Cero retención automática | El operador controla cualquier redirección, historial o captura externa y debe eliminarla según su propio sistema | El proyecto puede demostrar que no abre un fichero, no que terminales o herramientas externas no capturen la salida |
| `LOG-03` | Temporales de evaluación y reconstrucción | Directorio temporal local, accesible al proceso y al mantenedor | Solo durante la ejecución autorizada que lo crea | Cierre normal elimina el árbol temporal; ante fallo se comprueba y elimina antes de publicar evidencia | No usar un checkout temporal como registro canónico ni incluir su ruta en artefactos públicos |
| `LOG-04` | Evidencia saneada y manifiestos versionados | Git público tras revisión deliberada; lectura pública | Sin caducidad automática mientras sustente reproducibilidad, resultados o decisiones | Un commit puede retirarla del árbol actual, pero no purga el historial; reescribir historia, release o remoto exige autoridad separada | Conservar ID, commit, hashes, fuentes, resultado y límites. `DAT-25` no se regenera, sobrescribe ni elimina durante este cierre |
| `LOG-05` | Corpus y documentación sintéticos | Git público tras revisión; mantenidos por `ACT-02` | Hasta ser sustituidos por una versión trazable | Sustitución mediante commit que conserva procedencia y relación con evidencia previa | No introducir datos reales; una versión nueva no reinterpreta artefactos históricos |
| `LOG-06` | Borrador final del sandbox | Fichero local ignorado por Git, modo `0600`, accesible por la cuenta host | Hasta eliminación deliberada del operador | El producto no borra ni sobrescribe un borrador publicado; el operador elimina el fichero cuando ya no sea necesario | La cuenta host no está aislada. La eliminación local no demuestra borrado seguro del soporte |
| `LOG-07` | Staging y estado transaccional del sandbox | Local e interno a `TOL-02` | Solo mientras la transacción está abierta o requiere reconciliación | `stop()` revoca autoridad y limpia staging; el siguiente arranque reconcilia metadatos con un final ya publicado | No republica staging, restaura grants ni reintenta efectos |
| `LOG-08` | Registro humano de gobierno | Nota saneada separada del runtime y de la evidencia canónica | Mientras sea necesario para continuidad del proyecto | Corrección o retirada deliberada por el owner de ese registro | No es log de aplicación, autoridad técnica ni sustituto de Git y puede quedar desactualizado |
<!-- log-lifecycle:end -->

### Acceso y responsabilidades

- `ACT-01` puede ver la salida de su proceso y eliminar capturas que haya
  creado. No publica evidencia ni cambia la política.
- `ACT-02` revisa y decide qué proyección saneada se versiona; conserva hashes
  y dependencias, y registra cualquier retirada.
- `ACT-03` no recibe acceso a logs: solo interviene en el challenge sintético
  ligado a una propuesta.
- `REV-01` no está asignado. Una revisión futura recibe evidencia saneada, no
  secretos, datos reales o salida bruta.

No se ha fijado un plazo legal de conservación porque no hay un tratamiento
real ni una obligación aplicable determinada. Una obligación futura prevalece
solo tras documentar su fuente, ámbito, owner y efecto sobre esta matriz.

### Procedimiento de retirada

1. Clasificar el material con un `LOG-*` y detener cualquier publicación
   pendiente si puede contener un secreto o dato real.
2. Identificar qué evaluación, riesgo, decisión o referencia depende de él.
3. Conservar únicamente una descripción saneada del incidente y las huellas
   necesarias cuando hacerlo sea seguro y esté autorizado.
4. Eliminar la copia controlada por el owner adecuado. Para Git, una retirada
   del árbol actual no equivale a purga del historial.
5. Verificar ausencia en el destino que estaba bajo control y registrar los
   destinos no verificables. No afirmar borrado seguro del soporte, terminal,
   copias externas o remoto sin evidencia específica.
6. Si hubo secreto o dato real, seguir el runbook de incidentes, rotar o
   revocar el secreto en su sistema de origen y reevaluar el alcance antes de
   continuar.

La ventana de borrador entre I/O parcial y resultado queda cerrada por
[`GSL-SANDBOX-RECOVERY-001`](./sandbox-recovery-policy.md): `CMP-12` publica
atómicamente, conserva un efecto ya publicado y reconcilia metadatos internos
en el siguiente arranque. Esa capacidad es independiente y no convierte este
journal en persistente.

## Evidencia ejecutable

- `tests/test_security_events.py`: esquema cerrado, cadena, concurrencia,
  límites, correlaciones por caso, señales, reserva antes de I/O, canarios y
  sobre CLI.
- `tests/test_cli_smoke.py`: interfaz predeterminada y errores saneados.
- `tests/test_sandbox_recovery.py`: terminal coherente, conflictos de lock,
  recuperación independiente de señales y ausencia de canarios.
- `evaluations/benign-baseline-v1.json`: permanece idéntica byte a byte.
- `evaluations/adversarial-baseline-v1/`: evidencia histórica inmutable y
  separada del journal de producto.
