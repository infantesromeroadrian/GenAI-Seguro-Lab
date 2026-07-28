# Procedimiento de parada y recuperación — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-STOP-RECOVERY-001` |
| Versión | `1.0.0` |
| Fecha | 2026-07-28 |
| Estado | `VIGENTE_ALCANCE_ACTUAL` |
| Owner | `ACT-02` |
| Microtarea | `PGS-06-M07` |
| Alcance | CLI local de solo lectura y sesión interna `TOL-02` |

Este procedimiento explica cómo una persona detiene y recupera el laboratorio
sin confundir tres mecanismos distintos:

- terminar un proceso CLI local;
- ejecutar `DraftWriterTool.stop()` y reconciliar el sandbox;
- revertir una versión mediante una decisión de Git posterior.

No añade handlers de `SIGINT` o `SIGTERM`, una ruta CLI de recuperación,
watcher, daemon, retry, rollback automático ni borrado de un final publicado.
La implementación técnica canónica sigue en
[`GSL-SANDBOX-RECOVERY-001`](./sandbox-recovery-policy.md).

## Condiciones de parada

Detener la operación si se observa:

- un resultado terminal inesperado o una señal relevante;
- un efecto no previsto, destino desconocido o discrepancia de sandbox;
- un límite de recursos, lock ocupado o fallo de integridad;
- un secreto, dato real o ruta privada;
- drift de código, lock, corpus, hash o dependencia;
- un target que no puede identificarse con precisión.

Una señal no concede autoridad ni prueba ataque. Si aparece secreto, dato
real, tercero o publicación afectada, aplicar `IR-SEV-3` del
[runbook](./ai-incident-response-runbook.md) y no ampliar la investigación.

## Niveles de parada

<!-- stop-levels:start -->
| ID | Superficie | Acción | Resultado esperado | Límite |
|---|---|---|---|---|
| `STOP-01` | `analyze` o `baseline` sin efecto | Dejar terminar si falla cerrado; ante ejecución anómala, interrumpir el proceso local y comprobar que terminó | No hay escritura de producto; el lock de CLI queda disponible al salir el proceso | No existe handler global ni garantía de evento terminal ante terminación del SO |
| `STOP-02` | Sesión interna `TOL-02` todavía viva | Invocar `DraftWriterTool.stop()` una vez dentro de `finally`; las llamadas repetidas son idempotentes | Instancia cerrada, propuestas, aprobaciones y grants revocados, descriptor y journal terminados | No deshace un final ya publicado ni restaura cuotas o autoridad |
| `STOP-03` | Proceso interno ya terminado de forma abrupta | No editar `.gsl-txn-*`; iniciar una instancia nueva solo para activar reconciliación validada | Staging sin efecto se retira o final publicado se preserva; reporte `clean` o `recovered` | No existe ruta CLI; requiere código autorizado y filesystem POSIX compatible |
| `STOP-04` | Integridad ambigua, corrupción, secreto o ámbito externo | Congelar publicación y nuevas escrituras, preservar proyección saneada y abrir `GSL-AI-IR-001` | Estado intacto para análisis y decisión de autoridad | No reparar, borrar, reintentar, rotar o comunicar fuera sin owner y autoridad |
<!-- stop-levels:end -->

## Secuencia operativa

<!-- stop-recovery-workflow:start -->
| Paso | Operador | Acción verificable | Condición de salida |
|---|---|---|---|
| `SR-01` Identificar | `ACT-01` o `ACT-02` | Anotar operación, target, commit, control y síntoma sin copiar contenido sensible | El target pertenece al laboratorio y la acción está autorizada |
| `SR-02` Detener | `ACT-01` o `ACT-02` | Aplicar el nivel `STOP-*` mínimo suficiente y evitar nuevos efectos o publicaciones | El proceso terminó o la sesión interna rechazará toda operación posterior |
| `SR-03` Revocar | `ACT-02` | Invalidar la autoridad efímera de la sesión mediante `stop()`; no reutilizar challenge, aprobación o grant | Cualquier reanudación necesitará instancia y autoridad nuevas |
| `SR-04` Inspeccionar | `ACT-02` | Comprobar proceso, lock, final, marker y staging por nombre y metadato; no leer o publicar contenido innecesario | El estado coincide con un caso conocido o queda clasificado como ambiguo |
| `SR-05` Reconciliar | `ACT-02` | Crear una nueva instancia en la raíz validada y dejar que `CMP-12` reconcilie una sola vez | Reporte `clean` o `recovered`; si falla cerrado, no hubo mutación |
| `SR-06` Verificar | `ACT-02` | Confirmar ausencia de artefactos internos, preservar finales legítimos y ejecutar pruebas focales | Invariantes create-only, no-follow, modo, lock y autoridad satisfechos |
| `SR-07` Reanudar | `ACT-02` | Iniciar una operación nueva desde fuente fijada; no reanudar la transacción anterior | Nuevo ID de sesión, sin grants ni staging heredados |
| `SR-08` Registrar | `ACT-02` | Conservar resultado saneado, límites, incidentes y riesgos abiertos | Evidencia y decisión no reescriben `DAT-25` ni cierran riesgos por sí solas |
<!-- stop-recovery-workflow:end -->

## Matriz de recuperación del sandbox

| Estado observado por `CMP-12` | Resultado permitido | Acción humana |
|---|---|---|
| Sin artefactos internos | `clean` | Continuar solo si el resto de criterios de reanudación pasan |
| Marker y staging válidos, sin final | `recovered`; retirar ambos y registrar transacción sin efecto | Confirmar que no apareció un final y usar una sesión nueva |
| Marker y final válidos, staging enlazado o retirado | `recovered`; preservar final y retirar internos | Tratar el efecto como creado; no borrarlo ni recrearlo como rollback |
| Marker parcial, esquema desconocido, symlink, FIFO, owner, modo, hash, tamaño, inode o nlinks incoherentes | Fallo cerrado sin mutación | Aplicar `STOP-04`, preservar metadatos saneados y escalar |
| Lock ocupado | Fallo cerrado sin espera | Identificar el proceso cooperante; no romper el lock ni iniciar reintentos |

Nunca se eliminan manualmente artefactos `.gsl-txn-*`: su namespace está
reservado y su validez depende de varias invariantes conjuntas. Una limpieza
manual puede destruir la única información necesaria para decidir si hubo
efecto. `CMP-12` conserva las primitivas `O_NOFOLLOW` y `flock`; este
procedimiento no las sustituye por comprobaciones manuales.

## Criterios de reanudación

La operación puede reanudarse únicamente cuando:

1. proceso anterior terminado y lock disponible;
2. reporte `clean` o `recovered`, sin artefactos internos pendientes;
3. finales publicados preservados y ningún destino sobrescrito;
4. ninguna propuesta, challenge, aprobación, grant o cuota reutilizada;
5. commit, `uv.lock`, esquemas, corpus y hashes elegidos identificados;
6. pruebas focales de parada, recuperación, autoridad y eventos superadas;
7. no existe secreto, dato real, target externo o drift sin resolver;
8. incidentes, riesgos y límites restantes están registrados.

Las cuatro fixtures DOS/SC siguen inertes. Este procedimiento no autoriza
ejecutarlas para probar parada o recuperación.

## Rollback y retirada

- Un final create-only ya publicado no se sobrescribe ni se borra como
  rollback técnico. Una retirada deliberada del borrador pertenece al operador
  y a la política `LOG-06`.
- Un cambio de código se revierte mediante un nuevo cambio Git revisable sobre
  un commit identificado; no se reescribe silenciosamente la evidencia.
- `DAT-25` permanece inmutable y no se reejecuta para demostrar recuperación.
- Un cambio arquitectónico, despliegue, release o rollback externo exige su
  propia autoridad y, cuando proceda, un ADR sucesor.

## Evidencia

- `tests/test_sandbox_recovery.py`: publicación atómica, fault injection,
  concurrencia, corrupción, reinicio, lock y parada idempotente.
- `tests/test_security_events.py`: terminal, señales y límites del journal.
- `tests/test_local_tools.py`: revocación de autoridad y operaciones
  posteriores rechazadas.
- `GSL-AI-IR-001`: clasificación, contención, preservación y cierre.

## Relación con Tecture

El procedimiento utiliza las superficies y flujos existentes. No añade
componente, servicio, canal, interfaz, almacén, despliegue o trust boundary,
por lo que no modifica `architecture/`.
