# Política de parada y recuperación del sandbox

## Identidad y alcance

- **ID:** `GSL-SANDBOX-RECOVERY-001`
- **Versión:** `1.0.0`
- **Microtarea:** `PGS-04-M08`
- **Propietario:** `ACT-02`, mantenedor del laboratorio
- **Ámbito:** efecto interno `draft_create` de `TOL-02` sobre
  `sandbox/drafts/`

Esta política convierte la creación del borrador en una transacción local con
un único punto de publicación. Permite detener una sesión, revocar su
autoridad efímera y reconciliar en el siguiente arranque los artefactos
internos que hayan quedado tras un fallo.

No crea una ruta nueva de producto: `TOL-02` continúa desconectada de la CLI y
del flujo benigno. Tampoco convierte `CMP-11` en autoridad de recuperación.

## Invariantes

1. Antes de la publicación atómica, el nombre final no existe.
2. Después de la publicación, el Markdown final se considera creado y nunca
   se elimina como rollback, aunque la limpieza interna quede pendiente.
3. El destino se crea una sola vez, con modo `0600`, sin seguimiento de
   symlinks y sin sobrescritura.
4. Una recuperación nunca publica el staging ni reconstituye una propuesta,
   challenge, aprobación, grant o cuota consumida.
5. La recuperación solo puede retirar artefactos del namespace reservado
   `.gsl-txn-<32 hex>.(json|stage)`.
6. Un estado que no pueda validarse sin ambigüedad deja el sandbox intacto y
   bloquea nuevas escrituras.
7. No existen retry, watcher, daemon, polling o recuperación por red.

## Estado duradero mínimo

Cada transacción usa:

- un marker JSON canónico y estricto;
- un staging con el Markdown exacto ya permitido, redactado, ligado y
  autorizado;
- el nombre final validado.

El marker solo conserva:

| Campo | Contenido |
|---|---|
| `control_id`, `version` | Identidad cerrada del control |
| `transaction_id` | Identificador aleatorio opaco de 32 caracteres hex |
| `final_name` | Nombre Markdown ya validado, nunca una ruta |
| `bytes`, `sha256` | Tamaño y huella del staging esperado |

El marker excluye contenido, principal, scope, identidad, credencial,
challenge, aprobación, grant, token, ruta absoluta, excepción y traceback.
Marker y staging son regulares, pertenecen al usuario efectivo, tienen modo
`0600` y se abren respecto al descriptor de la raíz.

## Publicación

`CMP-12` ejecuta una vez esta secuencia bajo un `flock` exclusivo y no
bloqueante sobre el descriptor de `sandbox/drafts/`:

1. valida el descriptor de raíz, los límites y la ausencia de artefactos
   internos previos;
2. comprueba que el nombre final no exista;
3. crea y sincroniza el marker;
4. crea, completa y sincroniza el staging;
5. publica mediante un hard link create-only entre staging y nombre final;
6. sincroniza el directorio;
7. retira staging y marker y vuelve a sincronizar el directorio.

La creación del hard link es el único punto de linealización. Un fallo previo
termina sin efecto final. Un fallo posterior devuelve `created: true` con
`recovery_pending: true`, preserva el final y detiene de forma controlada la
sesión.

## Reconciliación de arranque

Cada nueva instancia de `DraftWriterTool` ejecuta una sola reconciliación
antes de registrar su autoridad:

| Estado validado | Acción |
|---|---|
| Sin artefactos internos | Informe `clean`; no muta el sandbox |
| Marker válido, staging válido y final ausente | Retira staging y marker; registra una transacción sin efecto |
| Marker y final válidos; staging enlazado o ya retirado | Preserva el final y retira solo los artefactos internos |
| Marker parcial, esquema desconocido, symlink, FIFO, owner o modo incorrectos, hash/tamaño/inode/nlinks incoherentes o lock ocupado | Falla cerrado, no muta el estado y no registra el writer |

El informe `SandboxRecoveryReport` es estricto, inmutable y saneado. Solo
expone identidad y versión del control, estado `clean|recovered` y conteos de
transacciones sin efecto, finales preservados y artefactos internos retirados.

## Parada y autoridad

`DraftWriterTool.stop()` es idempotente:

- marca la instancia como cerrada;
- revoca propuestas, challenges, aprobaciones y grants de la sesión;
- cierra el descriptor de raíz;
- rechaza cualquier operación posterior antes de I/O;
- termina `CMP-11` de forma coherente con el resultado conocido.

Un fallo previo a publicación consume la autoridad ya utilizada y termina la
operación como fallida. Un efecto publicado sigue siendo creado aunque una
excepción posterior abandone el contexto. Cualquier nuevo intento exige una
instancia, propuesta y aprobación nuevas.

## Límites

| Recurso | Máximo |
|---|---:|
| Entradas examinadas en la raíz | 256 |
| Artefactos internos reservados | 16 |
| Transacciones reconciliadas | 8 |
| Marker canónico | 1 KiB |
| Staging y Markdown final | 16 KiB |

Superar un límite provoca cierre seguro. El lock es cooperativo y no espera o
reintenta.

## Relación con eventos de seguridad

La condición real del control decide la parada o recuperación. `CMP-11` puede
observar un conflicto de lock, una violación del sandbox o una incoherencia de
datos, pero una señal no dispara la recuperación, no demuestra un ataque y no
concede autoridad.

El marker no sustituye un audit log: solo permite reconciliar el efecto local
create-only. El journal sigue siendo efímero y la recuperación no correlaciona
sesiones.

## Evidencia ejecutable

- `src/genai_seguro_lab/sandbox_recovery.py`: transacción, publicación,
  reconciliación, validación y reporte.
- `src/genai_seguro_lab/local_tools.py`: integración con autoridad, eventos y
  ciclo de vida de `TOL-02`.
- `tests/test_sandbox_recovery.py`: atomicidad, concurrencia, fault injection,
  reinicio, corrupción, lock, canarios y parada.
- `tests/test_local_tools.py`, `tests/test_resource_control.py` y
  `tests/test_security_events.py`: regresión de autoridad, cuotas y eventos.
- `evaluations/benign-baseline-v1.json`: salida funcional predeterminada
  conservada byte a byte.

## Límites de la garantía

- Requiere primitivas POSIX, hard links, `dir_fd`, `O_NOFOLLOW`, `fsync` y
  `flock` en un filesystem local compatible.
- `flock` coordina procesos cooperantes; no impide que código arbitrario bajo
  la misma cuenta ignore el protocolo.
- SHA-256, owner, modo, inode y nlinks detectan incoherencias observables, pero
  no protegen frente a un actor con ejecución Python hostil y los mismos
  permisos de `IDN-01`.
- No instala handlers globales de `SIGINT` o `SIGTERM`, no reanuda trabajo y
  no ofrece una ruta CLI, MCP o remota de recuperación.
- No aporta aislamiento del sistema operativo, autenticación humana real,
  logging persistente, telemetría, SIEM o respuesta operativa. El
  procedimiento humano completo sigue planificado en `PGS-06-M07`.
