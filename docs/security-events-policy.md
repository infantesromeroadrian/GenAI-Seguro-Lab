# Política de eventos y señales de seguridad

## Identidad y alcance

- **ID:** `GSL-SECURITY-EVENTS-001`
- **Versión:** `1.0.0`
- **Microtarea:** `PGS-04-M07`
- **Propietario:** `ACT-02`, mantenedor del laboratorio
- **Ámbito:** operaciones `analyze` y `baseline`, flujo benigno, búsqueda
  autorizada, política de salida, límites de recursos y sesión interna de
  borradores

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
2. `analyze` usa esa correlación durante todo el caso.
3. `baseline` mantiene la correlación primaria para el inicio y el cierre, y
   crea una correlación hija opaca distinta para cada uno de sus 12 casos. El
   ID del incidente no entra en el evento.
4. Todos los eventos comparten una única secuencia global contigua y una
   cadena SHA-256 canónica.
5. El journal termina una sola vez con `operation_completed` o
   `operation_failed`.

Las correlaciones ordenan evidencia dentro de una operación. No enlazan
sesiones distintas, no derivan de datos y no son credenciales, grants ni
prueba de identidad.

## Perfiles y límites

| Perfil | Eventos máximos | Bytes acumulados máximos | Uso |
|---|---:|---:|---|
| `analyze` | 32 | 32 KiB | Un incidente benigno |
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

Son reglas deterministas sobre decisiones ya tomadas por la aplicación. Una
señal no demuestra un ataque, compromiso, autoría o anomalía universal, y no
activa por sí misma respuesta, bloqueo adicional, rollback o comunicación.

## Exposición por CLI

El comportamiento predeterminado permanece byte a byte compatible:

```bash
uv run --frozen python main.py analyze --incident INC-BEN-001
uv run --frozen python main.py baseline
```

La opción explícita `--security-report` devuelve por `stdout` un sobre JSON
con dos claves: `result` y `security_report`.

```bash
uv run --frozen python main.py analyze --incident INC-BEN-001 --security-report
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

- logging persistente, retención, búsqueda o correlación entre sesiones;
- SIEM, métricas remotas, alertas, telemetría o exportación automática;
- detección de anomalías mediante ML o cobertura universal de secretos y PII;
- respuesta a incidentes, rollback, recuperación o retirada;
- eliminar la ventana de crash entre un I/O completado y su evento final;
- finalizar el journal de borrador si el llamador abandona el objeto sin
  `close()` explícito;
- acreditar un modelo GenAI real, proveedor, MCP o aislamiento de SO.

## Evidencia ejecutable

- `tests/test_security_events.py`: esquema cerrado, cadena, concurrencia,
  límites, correlaciones por caso, señales, reserva antes de I/O, canarios y
  sobre CLI.
- `tests/test_cli_smoke.py`: interfaz predeterminada y errores saneados.
- `evaluations/benign-baseline-v1.json`: permanece idéntica byte a byte.
- `evaluations/adversarial-baseline-v1/`: evidencia histórica inmutable y
  separada del journal de producto.
