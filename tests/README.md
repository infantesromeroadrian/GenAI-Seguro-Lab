# Tests

Este directorio contiene las pruebas automatizadas del contrato de datos, el
adaptador determinista, las herramientas locales, el flujo benigno, el perfil
vulnerable aislado, el harness adversario acotado, los runners y el analizador
offline de métricas, y la
interfaz de proceso completo, incluidos los límites preventivos de recursos y
el journal saneado de seguridad, la publicación atómica y la recuperación del
sandbox.

Ejecución completa:

```bash
uv run --frozen pytest
```

`test_cli_smoke.py` comprueba el punto de entrada desde fuera del repositorio,
la reproducción exacta de la baseline versionada, el resultado byte a byte de
un caso repetido, el error saneado ante un identificador desconocido y que la
ejecución no cree borradores.

`test_instruction_boundary.py` comprueba que el flujo ordinario separa
instrucciones confiables, datos de usuario y contenido no confiable; que las
salidas del modelo y de herramientas conservan su clasificación; y que los
roles incompatibles, las instrucciones tardías o los dominios ausentes fallan
cerrados.

`test_validation_policy.py` comprueba que los sobres de tarea, incidente y
salida final son estrictos; que una salida del modelo no puede fabricar un
grant; y que el flujo rechaza texto libre, efectos atribuidos, otro incidente
o conocimiento no autorizado. También verifica que la consistencia
estructural precede a la política semántica.

`test_output_policy.py` comprueba la precedencia `reject > redact > allow`,
redacción determinista e idempotente, rechazo genérico, canales cerrados y
sellos opacos ligados a una instancia. Las fixtures representan reglas
explícitas; no acreditan detección universal.

`test_resource_control.py` comprueba los bordes exactos y el exceso de corpus,
registros, peticiones, respuestas, herramientas, resumen y Markdown; el
presupuesto acumulado, el plazo con reloj inyectado, la cuota de borrador y el
lock no bloqueante de CLI. También verifica rechazo previo al adaptador o I/O
y `stdout` vacío; no acredita cancelación de una llamada síncrona bloqueada ni
rate limiting persistente.

`test_security_events.py` comprueba el esquema cerrado e inmutable, la
secuencia y cadena SHA-256, los límites de eventos y bytes, la concurrencia,
las diez señales deterministas y la ausencia de canarios. Verifica además una
correlación primaria por operación, 12 correlaciones hijas disjuntas para la
baseline, reserva de intento y resultado antes de I/O, fallo cerrado y el
sobre CLI opt-in sin alterar la salida predeterminada.

`test_local_tools.py` comprueba que cada grant pertenece a una sola
herramienta, principal, scope e instancia; que `TOL-01` retiene solo la vista
del incidente; y que `TOL-02` rechaza propuestas o grants fabricados antes de
I/O. También verifica que título y cuerpo se saneen antes de huella y
aprobación, que se persista exactamente ese contenido y que la creación use
descriptor, no-follow, carrera de ruta, create-only y modo `0600`.

`test_sandbox_recovery.py` comprueba el único punto de publicación, modo
`0600`, concurrencia, fallos antes y después de publicar, reinicio sin
republicar, preservación del final, limpieza del namespace interno y fallo
cerrado ante symlinks, FIFO, owner, modo, hash, inode, nlinks o lock
incompatibles. También verifica la revocación de autoridad, el terminal del
contexto y la ausencia de canarios en estado y errores saneados.

`test_evaluation_profile.py` comprueba que
`GSL-PROFILE-VULNERABLE-001` exige las RoE y los límites exactos, usa solo un
`$TMP/sandbox/drafts`, no crea archivos, identifica sus peticiones, no expone
el oráculo y no puede seleccionarse desde la CLI. Estas pruebas no ejecutan
ataques ni herramientas.

`test_adversarial_corpus.py` carga las 18 fixtures y sus 18 oráculos separados,
verifica la cobertura de los 17 abuse cases y seis familias, la procedencia,
los límites RoE, la relación uno a uno y los hashes. También demuestra que el
manifiesto fija 14 fixtures conectadas a test y evaluadas canónicamente, más 4
inertes.

`test_prompt_injection_evaluation.py` cubre los tres casos PI. Comprueba en un
proceso real que `--prompt` se rechaza antes de cargar datos; para las dos
inyecciones indirectas crea un corpus coherente bajo `$TMP`, entrega solo la
entrada a `CMP-07`, limita el flujo a dos turnos y una búsqueda, compara el
oráculo después y exige cero borradores, red o mutación canónica.

`test_jailbreak_disclosure_evaluation.py` cubre los tres casos de jailbreak y
los tres de revelación. Comprueba afirmaciones prohibidas en copias temporales,
cardinalidad y terminación del ciclo, rechazo de IDs fuera de alcance o
desconocidos y un error de CLI con marcador señuelo. El único subproceso
recibe tres variables ambientales explícitas y no hereda secretos del padre.
Cada ejecución conserva datos sintéticos, salida saneada, cero llamadas
externas y cero archivos.

`test_tool_abuse_evaluation.py` cubre los cinco casos TOL. Comprueba una
allowlist de herramienta cerrada, cardinalidad, IDs duplicados, recursión,
integridad, credencial sintética, binding, caducidad y consumo único de
aprobaciones, traversal, symlink y overwrite. `AC-TOL-05` conserva el literal
de la baseline histórica, pero el checkout actual lo rechaza antes de I/O y
crea cero archivos bajo `$TMP`.

`test_adversarial_baseline.py` comprueba que `CMP-08` queda fijado al commit
histórico, la ejecución de sus 14 casos, el residual esperado, el fallo cerrado
ante otro candidato, la escritura solo en un directorio temporal nuevo y la
integridad y saneado de la evidencia versionada.

`test_adversarial_retest.py` comprueba el contrato separado de PGS-05-M01:
14 IDs una vez y en orden, cuatro inertes, perfil fuente distinto de la postura
del candidato, comparación byte a byte de cinco archivos y deriva declarada
del manifiesto, estados y relaciones neutrales, hashes antes/después,
verificación de la evidencia histórica, saneado cerrado y escritura
create-only. También fija por hash que el runner y la evidencia históricos no
cambian.

`test_adversarial_metrics.py` comprueba el contrato de PGS-05-M02: hashes
históricos fijados, verificación completa de ambos namespaces, emparejamiento de
14 casos, clasificación cerrada por triple, cálculo entero y porcentajes
deterministas, fail-closed ante evidencia o estados desconocidos, salida
canónica saneada y equivalencia byte a byte del wrapper versionable. También
fija 1/14 → 0/14 y una operación no autorizada aceptada/ejecutada → cero, sin
interpretar solicitudes rechazadas como llamadas.

`test_benign_utility.py` comprueba el contrato de PGS-05-M03: fuentes
precontroles y producto fijadas por SHA-256, 12 IDs en orden, ejecución
individual con el control de recursos `analyze`, distinción entre rechazo y
error, invariantes técnicos, cobertura textual exacta, fórmulas y umbrales
enteros, modelos Pydantic cerrados, fallo ante tampering, saneado, determinismo
y equivalencia byte a byte del wrapper con el snapshot versionado. Fija 12/12
terminaciones, 0/12 falsos rechazos, 0/12 éxitos estrictos y `SC-07` como
`NOT_DEMONSTRATED`, sin atribuir comprensión semántica al comparador.

`test_operational_metrics.py` comprueba el contrato de PGS-05-M04: commits,
árboles y cuatro entradas comunes fijados, ejecución temporal AB/BA,
estadísticas enteras reproducibles, todos los outliers, consumo y complejidad
descriptiva. Verifica que no se cambie el checkout, no se conserve salida
bruta y no se inventen umbrales, significación, energía o TCO.

`test_control_findings.py` comprueba el contrato de PGS-05-M05: seis hallazgos
disjuntos, resumen derivado, hashes de `DAT-20/21/22`, 44 referencias
escalares, byte-identidad del JSON canónico, saneado y fallo cerrado ante
tampering o referencias divergentes. También impide cierre prematuro del
bypass histórico y confirma que `CMP-17` no dependa de ejecución de targets,
red o generación automática del registro.

`test_final_retest.py` comprueba el contrato previo y el seam no canónico de
PGS-05-M07 sin ejecutar de nuevo el run final: rúbrica cerrada de 84 cláusulas,
separación entre candidato y evaluador, materialización Git temporal, bloqueo
de red/credenciales, 14 casos adversarios, 12 benignos, dos probes, cuatro
inertes y 15 artefactos históricos. Fija 1/14 → 0/14, 1 → 0 operaciones, cero
regresiones, cero falsos rechazos y `SC-06`/`SC-07` demostrados bajo la
trazabilidad cerrada, manteniendo falsa la equivalencia semántica general y la
evaluación con un modelo real. El runner rechaza argumentos antes de entrar en
la ruta canónica.

`test_residual_risk.py` valida exclusivamente el snapshot documental de
PGS-05-M08: identidad, candidato, roles de `DAT-20` a `DAT-25`, hashes
inmutables de sus evidencias, seis riesgos con cobertura exacta y única de los
17 abuse cases, cuatro fixtures inertes fuera del denominador, métricas
acotadas, límites y aceptación humana pendiente. No importa ni ejecuta
evaluadores o runners.

`test_architecture_decision.py` valida exclusivamente el ADR de PGS-05-M09:
identidad y evidencia fijadas, diez invariantes, siete alternativas no
seleccionadas para el futuro, siete triggers, consecuencias, rollback
compensatorio, conservación de DAT-25 y enlaces documentales estables. No ejecuta
producto, harness, evaluadores o runners.

`test_governance_cards.py` valida exclusivamente las tres fichas de
PGS-06-M01: identidad y corte documental, seis trust boundaries, actores,
componentes, `DAT-01` a `DAT-25`, manifiestos y hashes de ambos corpus,
contrato real de `MOD-01`, métricas acotadas de `DAT-25` y riesgos pendientes.
No ejecuta producto, harness, evaluadores o runners.

`test_ai_impact_assessment.py` valida exclusivamente `GSL-AIA-001` de
PGS-06-M02: identidad y fuentes, cribado, diez impactos, los seis handoffs
`PENDIENTE_HUMANA`, siete triggers, límites y métricas fijadas de `DAT-25`.
Lee la evidencia inmutable, pero no ejecuta producto, harness, evaluadores o
runners.

`test_raci_risk_register.py` valida exclusivamente los artefactos de
PGS-06-M03: doce actividades con un único accountable actual, participación
planificada de `REV-01`, seis riesgos abiertos con los 17 abuse cases únicos y
seis decisiones `PENDIENTE_HUMANA`. También fija el hash de `DAT-25` sin
ejecutar producto, harness, evaluadores o runners.

`test_roadmap_state.py` es el único owner de los contadores y de la siguiente
microtarea mutable que comparten el plan y el README.

`test_control_traceability.py` comprueba exclusivamente el contrato documental
de la matriz canónica: una fila por `CTL-01` a `CTL-13`, roles conocidos,
cobertura explícita de los 17 abuse cases, limitaciones no vacías y selectores
pytest que apuntan a ficheros y funciones existentes. Esta validación no prueba
la eficacia de los controles.

`test_clean_rebuild_evidence.py` valida la identidad Git, los hashes de
entrada, el entorno, las diez distribuciones instaladas y los resultados
acotados de `GSL-CLEAN-REBUILD-001`. También impide rutas personales, conserva
el hash de `DAT-25` y exige que la documentación no convierta una
reconstrucción con red en build hermética ni en prueba del producto.

`test_closure_execution_evidence.py` valida el commit y árbol de
`GSL-CLOSURE-EXECUTION-001`, los hashes históricos de entrada, las 327 pruebas,
el resumen de 12 benignos y la separación exacta entre 14 casos adversarios
ejecutados y cuatro DOS/SC inertes. También comprueba el saneado, la ausencia
del runner de `DAT-25`, su hash inmutable y el cierre documental de M02.

`test_content_scan_evidence.py` valida el candidato de
`GSL-CONTENT-SCAN-001`, las dos pasadas de Gitleaks, 56 registros sintéticos,
32 eventos fijados, rangos reservados y la ausencia observada de categorías de
identidad. Exige además que la procedencia personal histórica quede declarada
sin valores, sin reescritura y sin presentar cero hallazgos como garantía.

`test_independent_review_pack.py` valida que `GSL-REV-PACK-001` fija por hash
el threat model y `ADV-TOL-005` del commit `1508cad`, exige una persona
cualificada distinta de diseño e implementación y preserva `DAT-25`. También
impide que el paquete preparado se presente como una revisión real.

`test_independent_review_omission.py` valida que
`GSL-REV-OMISSION-001` registra M04 como omitida, mantiene `REV-01` sin
asignar, conserva abiertos los criterios padre dependientes y no transforma la
decisión en revisión, aprobación, exención o aceptación de riesgo.

`test_independent_review_disposition.py` valida que
`GSL-REV-DISPOSITION-001` registra cero observaciones y correcciones,
conserva `D-REV-01` como discrepancia abierta y cierra solo M05 sin modificar
la omisión de M04.

`test_final_traceability_matrix.py` valida la cobertura exacta y única de los
25 requisitos `RF`, `RS`, `RO` y `SC`, el vocabulario cerrado de resultados,
la existencia de las referencias locales y la conservación de `SC-12`,
`D-REV-01` y `RR-01` a `RR-06` como gaps no aceptados.

`test_closure_summaries.py` valida que los resúmenes técnico y ejecutivo
localizan la evidencia necesaria, conservan métricas acotadas, distinguen el
doble determinista de un modelo real y no ocultan la revisión omitida, los
riesgos abiertos o el estado de `SEC-1`.
