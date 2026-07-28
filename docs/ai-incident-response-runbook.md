# Runbook de respuesta a incidentes de IA — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-AI-IR-001` |
| Versión | `1.0.0` |
| Fecha | 2026-07-28 |
| Estado | `VIGENTE_ALCANCE_ACTUAL` |
| Owner | `ACT-02` |
| Microtarea | `PGS-06-M06` |
| Alcance | proceso local, datos sintéticos, doble determinista y sandbox de borradores |

Este runbook convierte observaciones en una respuesta humana reproducible. No
añade un SIEM, monitorización persistente, respuesta automática, SLA,
guardia, comunicación externa ni capacidad de producción. Una señal
`GSL-SECURITY-EVENTS-001` es un indicador de triage: no demuestra por sí sola
un ataque, compromiso, intención, autoría o impacto.

## Cuándo se activa

Se abre un registro de incidente candidato si ocurre al menos uno de estos
hechos:

- una señal cerrada del journal o un fallo terminal inesperado;
- una diferencia entre el estado del sandbox y su metadato transaccional;
- un secreto, dato real, ruta privada o salida no saneada en un artefacto;
- drift de commit, lock, hash, corpus, dependencia o fuente;
- una prueba autorizada produce un efecto no previsto;
- `ACT-01`, `ACT-02` o un futuro `REV-01` comunica una anomalía verificable.

`ACT-02` clasifica el caso. Si la observación no puede reproducirse o carece de
impacto, se registra como `OBSERVACION_NO_CONFIRMADA`; no se borra ni se
presenta como incidente confirmado.

## Severidad y declaración

<!-- incident-severity:start -->
| ID | Estado | Criterio observable | Acción inicial |
|---|---|---|---|
| `IR-SEV-0` | `OBSERVACION_NO_CONFIRMADA` | Señal aislada o reporte sin efecto, exposición o drift demostrado | Conservar proyección saneada, validar contexto y cerrar o elevar con justificación |
| `IR-SEV-1` | `INCIDENTE_LOCAL_MENOR` | Operación local falla cerrada o se degrada sin efecto, secreto, dato real ni corrupción persistente | Parar la operación afectada, preservar evidencia mínima y corregir solo con autoridad vigente |
| `IR-SEV-2` | `INCIDENTE_LOCAL_RELEVANTE` | Efecto no autorizado, fuga saneable antes de publicar, integridad alterada, replay, escape o supply-chain sospechosa dentro del host | Detener el laboratorio, revocar autoridad sintética, aislar el candidato y no publicar |
| `IR-SEV-3` | `ESCALADO_FUERA_DE_ALCANCE` | Posible secreto real, dato personal, tercero, remoto, repositorio publicado afectado, obligación legal o impacto físico/económico | Detener, no ampliar la investigación, preservar de forma segura y solicitar autoridad y especialistas competentes |
<!-- incident-severity:end -->

La severidad describe el máximo impacto observado, no la intención del actor.
Solo `ACT-02` declara o cambia la severidad dentro del laboratorio. Una
notificación legal, a terceros o pública requiere una obligación o autoridad
externa identificada; el runbook no la presupone.

## Roles

| Rol | Durante la respuesta | Límite |
|---|---|---|
| `ACT-01` | Detiene su ejecución, conserva la salida saneada disponible y comunica qué operación observó | No modifica controles, riesgo, Git ni evidencia canónica |
| `ACT-02` | Declara severidad, coordina, contiene, decide corrección autorizada, verifica recuperación y mantiene el registro | No acepta riesgo automáticamente ni se atribuye independencia |
| `ACT-03` | Su autoridad sintética se revoca o deja caducar; no participa en análisis | No representa presencia o aprobación humana real |
| `REV-01` | Futuro consultado para revisión independiente de evidencia saneada | Sigue sin asignar y no puede figurar como participante actual |

## Flujo obligatorio

<!-- incident-workflow:start -->
| Paso | Acción | Evidencia mínima | Criterio de avance |
|---|---|---|---|
| `IR-01` Detectar | Anotar fuente, operación, commit y señal o síntoma sin copiar payloads | ID opaco, commit, control, resultado terminal y hashes disponibles | La observación está acotada a un target |
| `IR-02` Triaje | Verificar alcance, estado real, posible impacto y si existe secreto, dato real, tercero o publicación | Severidad provisional y hechos observados frente a inferencias | Existe responsable y decisión de continuar, elevar o cerrar como no confirmada |
| `IR-03` Contener | Detener la operación, impedir nuevas publicaciones o efectos y revocar grants de la sesión | Acción de parada, target aislado y estado de autoridad | No se producen nuevos efectos dentro del alcance controlado |
| `IR-04` Preservar | Guardar solo proyecciones saneadas, hashes, commits, versiones y pasos de reproducción seguros | Inventario de evidencia con procedencia y límites | La investigación no depende de secretos, payloads o rutas privadas |
| `IR-05` Erradicar o corregir | Corregir únicamente la causa demostrada y autorizada; no reescribir evidencia histórica | Diff, decisión, tests focales y vínculo al riesgo/control | La corrección está separada de la evidencia que demostró el defecto |
| `IR-06` Recuperar | Reconstruir desde fuente fijada, reconciliar sandbox y ejecutar comprobaciones proporcionales | Commit candidato, lock, tests, corpus permitido y resultado | Criterios de reanudación satisfechos y no hay drift |
| `IR-07` Comunicar | Informar a roles actuales y documentar destinos externos pendientes | Mensaje saneado con hechos, impacto, límites y siguiente decisión | Cada comunicación tiene owner y autoridad |
| `IR-08` Aprender | Actualizar riesgo, AIA, ADR, política o corpus si el hecho activa un trigger | Decisión trazable y nueva evidencia; la anterior queda intacta | El cierre distingue corregido, riesgo abierto y trabajo futuro |
<!-- incident-workflow:end -->

Está prohibido regenerar `DAT-25`, modificar un resultado para que “pase”,
copiar un secreto al registro, ejecutar las cuatro fixtures DOS/SC inertes sin
autorización o ampliar el target para investigar.

## Playbooks por familia

<!-- incident-playbooks:start -->
| ID | Familia o señal | Comprobación inicial | Contención | Evidencia y recuperación |
|---|---|---|---|---|
| `IR-PB-01` | Prompt injection, jailbreak, `unknown_model_request` | Confirmar entrada autorizada, frontera de instrucciones y decisión exacta del adaptador | Parar el caso; no reutilizar su contenido en otra petición | ID de fixture, commit, regla y triple observado; repetir solo el caso autorizado tras corregir |
| `IR-PB-02` | Exfiltración u `output_policy_intervention` | Distinguir redacción preventiva de una salida ya expuesta | Bloquear publicación; si existe secreto real, elevar a `IR-SEV-3` y revocarlo en origen | Conservar patrón y hash, nunca el valor; validar salida, journal y destino controlado |
| `IR-PB-03` | `tool_denied` o `authorization_replay_or_context_mismatch` | Verificar grant, principal, scope, binding, TTL y consumo único | Revocar sesión y evitar todo efecto posterior | Registrar decisión saneada; recuperar con una sesión nueva, no restaurar el grant |
| `IR-PB-04` | `sandbox_violation`, `lock_conflict` o estado inconsistente | Comparar destino final, staging y metadato sin seguir enlaces | Ejecutar `stop()`, mantener final publicado y no republicar staging | Aplicar reconciliación de `GSL-SANDBOX-RECOVERY-001`; verificar no-follow, create-only y ausencia de staging |
| `IR-PB-05` | `resource_limit_exceeded` o agotamiento | Identificar límite excedido sin ejecutar carga DOS inerte | Terminar cooperativamente el proceso y liberar lock | Registrar límite y terminal; no elevar presupuesto ni repetir carga sin decisión humana |
| `IR-PB-06` | `data_integrity_violation` | Comparar esquema, procedencia, tamaño y hash con la fuente fijada | No cargar, entrenar, evaluar ni versionar el dato afectado | Restaurar desde fuente verificada o crear versión nueva; nunca sobrescribir evidencia histórica |
| `IR-PB-07` | Dependencia o supply chain | Fijar paquete, versión, origen, hash, commit y superficie afectada | Congelar publicación y no actualizar a ciegas | Evaluar alcance, sustituir o fijar versión autorizada, reconstruir limpio y actualizar registro de riesgos |
| `IR-PB-08` | Secreto, dato real o ruta privada | Confirmar solo la clase y el destino; no volver a imprimir el valor | Detener commit/push y ejecución; revocar secreto en origen si está autorizado | Escanear destinos controlados, registrar límites y reevaluar AIA/cumplimiento antes de continuar |
<!-- incident-playbooks:end -->

## Evidencia y registro

El registro mínimo de cada caso contiene:

- identificador opaco y fecha del registro humano;
- reporter y owner por rol, no datos innecesarios;
- target, commit, versión, control, señal y severidad;
- hechos observados, inferencias separadas y alcance no verificado;
- hashes o recuentos saneados, nunca valores secretos o payloads;
- contención, corrección, pruebas, resultado, riesgos y decisiones pendientes;
- comunicaciones realizadas y las que requieren nueva autoridad.

La [política de logs](./security-events-policy.md) gobierna conservación y
retirada. Git o una nota humana no sustituyen el estado real del sistema.

## Criterios de recuperación y cierre

El [procedimiento de parada y
recuperación](./stop-recovery-procedure.md) detalla la ejecución de estos
criterios. Una operación solo se reanuda si:

1. el target y el commit están identificados;
2. no quedan grants o staging reutilizables;
3. el sandbox está reconciliado y el lock disponible;
4. esquemas, hashes y dependencias coinciden con la fuente elegida;
5. pasan las pruebas focales y cualquier corpus autorizado proporcional;
6. no se ejecuta `DAT-25` ni una fixture inerte;
7. los riesgos y límites que siguen abiertos están registrados.

El registro puede cerrarse como `NO_CONFIRMADO`, `CONTENIDO`,
`CORREGIDO_VERIFICADO` o `ESCALADO`. Cerrar el incidente no acepta ni cierra
automáticamente `RR-01` a `RR-06`, no certifica el sistema y no autoriza
producción.

## Relación con Tecture

El runbook opera sobre los componentes, almacenes, flujos y trust boundaries
existentes. No añade un servicio de observabilidad, SIEM, canal externo,
interfaz, despliegue o integración, por lo que no modifica `architecture/`.
