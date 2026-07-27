# Mapa de responsabilidades y controles NIST

## Ficha del mapeo

| Campo | Valor |
|---|---|
| Identificador | `GSL-NIST-CONTROLS-001` |
| Versión | `1.12.0` |
| Fecha de corte | 2026-07-27 |
| Baseline adversaria histórica | commit evaluado `93aefa45eac687d219bfed32f03be4e60e4a13ed` + evidencia PGS-03-M07 |
| Control vigente | PGS-05-M07, retest final canónico; PGS-05-M08 añade solo el snapshot documental de riesgo residual |
| Threat model de origen | [`GSL-ABUSE-CASES-001`](./abuse-cases.md), [`GSL-RISK-PRIORITY-001`](./risk-prioritization.md) y [`GSL-THREAT-CROSSWALK-001`](./threat-crosswalk.md) |
| Autoridad de origen | [`GSL-AUTH-MATRIX-001`](./authority-matrix.md) |
| Baseline normativa | [NIST AI RMF 1.0 y NIST SP 800-218A](./framework-versions.md) |
| Alcance | responsabilidades humanas y controles del laboratorio local actual y de las fases ya planificadas |

Este documento convierte los 17 abuse cases en un registro canónico de
controles con responsable, estado, evidencia, pruebas, limitación y destino de
verificación. El mapeo selecciona resultados de NIST AI RMF 1.0 y tareas de
NIST SP 800-218A que ayudan a estructurar el trabajo; no acredita conformidad,
certificación ni eficacia.

## Cómo interpretar el estado

| Estado | Significado en este documento |
|---|---|
| `PRESENTE` | Existe un mecanismo observable para el sistema determinista actual y se identifica su evidencia. No demuestra por sí solo eficacia adversaria. |
| `PARCIAL` | Existe una parte del mecanismo, pero falta alcance, separación, automatización o evidencia necesaria para tratar el riesgo completo. |
| `PLANIFICADO` | El control todavía no existe o no posee evidencia suficiente; se vincula a una microtarea futura concreta. |

Los estados describen el commit de corte. Solo una nueva revisión del sistema y
de su evidencia puede cambiarlos.

## Alcance correcto de las referencias NIST

- **NIST AI RMF 1.0** se usa como marco voluntario para gobernar, mapear,
  medir y gestionar el riesgo del sistema completo.
- **NIST SP 800-218A** es un perfil de desarrollo seguro de modelos de IA que
  complementa SSDF 1.1 y debe utilizarse junto con NIST SP 800-218.
- SP 800-218A incluye el desarrollo y la integración de modelos en software,
  pero deja fuera la operación y el despliegue del sistema, así como la mayor
  parte del ciclo general de gobierno de datos.
- El laboratorio todavía no entrena ni ajusta un modelo. Los mapeos a tareas
  sobre datos de entrenamiento o modelos adquiridos son, por tanto, parciales
  hasta incorporar un modelo real o reutilizar esas tareas para el futuro
  corpus de evaluación.

En la tabla NIST, `D` indica correspondencia directa con una tarea de
desarrollo seguro y `P` una correspondencia parcial por estos límites de
alcance. La marca no describe el estado de implementación, que se conserva
separado en el registro de controles.

## Roles y responsabilidad

| Rol | Estado | Responsabilidad acotada |
|---|---|---|
| `ACT-02` — mantenedor y ejecutor de pruebas | Actual | Responsable último del riesgo del laboratorio, sus requisitos, cambios, dependencias, pruebas, evidencias y decisiones de aceptación. Su autoridad procede de la cuenta local y Git. |
| `ACT-01` — operador local | Actual | Ejecuta únicamente los escenarios autorizados, respeta las Rules of Engagement y comunica resultados, anomalías y necesidad de parada. No acepta riesgo residual ni cambia controles. |
| `ACT-03` — confirmador de un borrador | Actual, interno | Autentica un principal sintético configurado y aprueba una propuesta concreta antes de un efecto `C2`. No acredita presencia ni identidad de una persona real. |
| `REV-01` — revisor independiente | Planificado | Persona cualificada distinta de quien diseñó e implementó el candidato. Revisará threat model y al menos una prueba en PGS-07-M04; todavía no hay una persona asignada. |

### Distribución preliminar del ciclo

`A`, `R`, `C` e `I` son abreviaturas documentales de la distribución actual, no
una RACI formal ni un registro de aceptación. PGS-06-M03 conserva la creación
de ambos artefactos. Las marcas de `REV-01` solo se activarán cuando exista una
persona independiente.

| Actividad | `ACT-02` | `ACT-01` | `ACT-03` | `REV-01` |
|---|---|---|---|---|
| Requisitos, tolerancia, priorización y aceptación de riesgo residual | `A/R` | `C` | `C` | `I` planificado |
| Inventario, threat model, arquitectura y diseño de controles | `A/R` | `C` | `C` | `C` planificado |
| Código, datos, dependencias, build y evidencia de release | `A/R` | `I` | `I` | `C` planificado |
| Operación autorizada y comunicación de anomalías | `A` | `R` | `I` | `I` planificado |
| Confirmación humana de una acción con efecto | `A` | `I` | `R` | `C` planificado |
| Diseño del harness, ejecución de pruebas, métricas y retest | `A/R` | `C` | `I` | `C` planificado |
| Parada inicial, respuesta, recuperación y análisis de causa | `A/R` | `R` | `I` | `C` planificado |
| Revisión independiente | `A`, solo la encarga | `I` | `I` | `R` planificado |
| Cambio, release, rollback y retirada del sistema | `A/R` | `I` | `I` | `C` planificado |

La concentración actual de `A` y `R` en `ACT-02` es una limitación conocida
del laboratorio individual. No se presenta como separación de funciones.
`ACT-03` constituye una identidad sintética autenticada, no una identidad
humana real. Si se incorpora un proveedor, repositorio remoto o servicio
operado por un tercero, deberá
definirse entonces el modelo de responsabilidad compartida; hoy no existe.

## Registro de controles

Esta tabla marcada es la única matriz canónica de trazabilidad de controles.
`tests/test_control_traceability.py` valida su estructura y sus referencias
documentales; no prueba que un control sea eficaz frente a un atacante.

<!-- control-traceability:start -->
| ID | Control | Estado | Responsable | Amenazas | Evidencia actual | Pruebas actuales | Limitación | Próxima evidencia prevista |
|---|---|---|---|---|---|---|---|---|
| `CTL-01` | Requisitos de seguridad, tolerancia y tratamiento de riesgo | `PARCIAL` | `A/R ACT-02` | `AC-PI-01`, `AC-PI-02`, `AC-PI-03`, `AC-JB-01`, `AC-JB-02`, `AC-EX-01`, `AC-EX-02`, `AC-EX-03`, `AC-TOL-01`, `AC-TOL-02`, `AC-TOL-03`, `AC-TOL-04`, `AC-TOL-05`, `AC-DOS-01`, `AC-DOS-02`, `AC-DOS-03`, `AC-SC-01` | README, criterios de éxito, catálogo y priorización fijan límites; `GSL-RESIDUAL-RISK-001` documenta seis tratamientos posteriores a `DAT-25` sin cambiar scores | `tests/test_control_traceability.py::test_control_traceability_matrix_is_complete_and_well_formed`<br>`tests/test_adversarial_corpus.py::test_corpus_covers_all_abuse_cases_and_six_families`<br>`tests/test_residual_risk.py::test_six_primary_risks_cover_each_abuse_case_exactly_once` | El snapshot valida trazabilidad y cobertura documental, no eficacia ni aceptación; faltan la evaluación de impacto, la RACI, el registro formal, las decisiones humanas y la revisión periódica | PGS-06-M02 a M04 |
| `CTL-02` | Inventario, límites, autoridad, threat model y disparadores de cambio | `PRESENTE` | `A/R ACT-02`; `C REV-01` planificado | `AC-PI-01`, `AC-PI-02`, `AC-PI-03`, `AC-JB-01`, `AC-JB-02`, `AC-EX-01`, `AC-EX-02`, `AC-EX-03`, `AC-TOL-01`, `AC-TOL-02`, `AC-TOL-03`, `AC-TOL-04`, `AC-TOL-05`, `AC-DOS-01`, `AC-DOS-02`, `AC-DOS-03`, `AC-SC-01` | Inventario, C4, autoridad, catálogo y priorización incorporan `CMP-06` y el alcance PI/JB/EX/TOL de `CMP-07` | `tests/test_control_traceability.py::test_control_traceability_matrix_is_complete_and_well_formed`<br>`tests/test_adversarial_corpus.py::test_manifest_fixes_scope_counts_and_partial_test_wiring` | La coherencia documental no sustituye revisar el threat model cuando el harness conecte nuevos casos, cambie el target o aparezca un disparador | Revisión en cada disparador y matriz final PGS-07-M06 |
| `CTL-03` | Procedencia, esquema e integridad del corpus y artefactos | `PRESENTE` para los corpus sintéticos actuales | `A/R ACT-02` | `AC-PI-02`, `AC-PI-03`, `AC-JB-01`, `AC-DOS-02`, `AC-DOS-03`, `AC-SC-01` | Los corpus aplican esquemas estrictos, procedencia, conteos y SHA-256; `CMP-18` fijó 22 fuentes del runtime, 6 fuentes de corpus y 15 artefactos históricos, mantuvo entradas, oráculos y rúbrica fuera del candidato y conservó sus hashes en `DAT-25` | `tests/test_data_contract.py::test_manifest_hashes_counts_and_references`<br>`tests/test_adversarial_corpus.py::test_inputs_and_oracles_are_strictly_separated_and_joined`<br>`tests/test_final_retest.py::test_candidate_is_exact_isolated_and_all_sources_are_hashed`<br>`tests/test_final_retest.py::test_historical_artifacts_are_pinned_and_dat22_is_not_final_performance` | No hay firma ni control de acceso propio, y los límites actuales no sustituyen una política para futuros corpus o datos reales | Supply chain PGS-06-M08 |
| `CTL-04` | Separación de instrucciones y contenido no confiable, resistencia a inyección y jailbreak | `PARCIAL` | `A/R ACT-02` | `AC-PI-01`, `AC-PI-02`, `AC-PI-03`, `AC-JB-01` | `ModelMessage` clasifica los dominios de confianza; `ModelRequest` exige una instrucción confiable inicial, datos de usuario y contenido no confiable, y las salidas de herramienta vuelven como no confiables; `DAT-25` conserva 14/14 casos adversarios completados, reduce el éxito observado de 1/14 a 0/14 y mantiene 12/12 casos benignos sin regresión técnica | `tests/test_instruction_boundary.py::test_initial_request_separates_every_trust_domain`<br>`tests/test_prompt_injection_evaluation.py::test_indirect_prompt_injection_completes_safely_in_a_temporary_copy`<br>`tests/test_final_retest.py::test_final_adversarial_metrics_are_observation_derived`<br>`tests/test_final_retest.py::test_final_benign_rubric_demonstrates_sc07_without_semantic_claim` | La comparación cubre un doble determinista y una rúbrica cerrada, no paráfrasis generales, equivalencia semántica, ataques desconocidos o un modelo GenAI real | Evaluación con modelo real posterior |
| `CTL-05` | Validación de entradas, salidas y argumentos; allowlist de herramientas | `PARCIAL` | `A/R ACT-02` | `AC-JB-02`, `AC-EX-01`, `AC-EX-02`, `AC-TOL-01`, `AC-TOL-02` | Los sobres Pydantic cierran entradas y salida; `ToolExecutionGrant` limita una herramienta, `CMP-09` aplica reglas semánticas antes de entrega o aprobación y `DAT-25` conserva el resultado final con validación cerrada y fail-closed | `tests/test_validation_policy.py::test_benign_input_envelopes_are_strict_and_omit_oracles`<br>`tests/test_model_adapter.py::test_request_rejects_unknown_advertised_tools`<br>`tests/test_tool_abuse_evaluation.py::test_forbidden_tool_name_is_rejected_before_execution`<br>`tests/test_final_retest.py::test_snapshot_is_closed_sanitized_and_metrics_fail_closed` | La validación cubre contratos y casos programados del doble determinista, no todas las entradas de un modelo real | Modelo real posterior |
| `CTL-06` | Mínimo privilegio y separación modelo–identidad–datos–herramientas | `PARCIAL` | `A/R ACT-02` | `AC-TOL-01`, `AC-TOL-02`, `AC-TOL-05`, `AC-SC-01` | `IDN-05` liga grants a principal, scope, herramienta e instancia; `TOL-01` retiene la vista exacta del incidente, `TOL-02` separa preparación y efecto, EX-003 recibe un entorno allowlisted y `DAT-25` conserva 0 operaciones no autorizadas en los 14 casos finales | `tests/test_local_tools.py::test_model_request_cannot_expand_the_knowledge_grant`<br>`tests/test_tool_abuse_evaluation.py::test_excess_agency_guards_are_exercised_independently`<br>`tests/test_final_retest.py::test_final_adversarial_metrics_are_observation_derived` | `IDN-01` conserva permisos amplios en la misma cuenta macOS y no existe identidad de servicio ni aislamiento de SO | Revisión de aislamiento cuando cambie el runtime |
| `CTL-07` | Confirmación humana autenticada, ligada al contenido y no reutilizable | `PARCIAL` | `A ACT-02`; `R ACT-03` | `AC-TOL-03`, `AC-TOL-05` | `DraftApprovalAuthority` autentica una identidad sintética, liga challenge, aprobación y grant a todo el contexto, aplica TTL y consumo único; `DAT-25` confirma que `ADV-TOL-005` termina sin aceptación ni efecto no autorizado y conserva el bypass histórico por separado | `tests/test_local_tools.py::test_approval_is_bound_to_proposal_writer_root_scope_and_sessions`<br>`tests/test_local_tools.py::test_challenge_approval_and_grant_expiry_fail_before_io`<br>`tests/test_local_tools.py::test_effect_grant_is_consumed_before_io_and_not_restored`<br>`tests/test_final_retest.py::test_final_adversarial_metrics_are_observation_derived` | No verifica presencia ni identidad humana real ni muestra el contenido en una interfaz | Interfaz/autenticador con presencia humana |
| `CTL-08` | Efectos de filesystem confinados, creación exclusiva, parada y recuperación segura | `PARCIAL` | `A/R ACT-02`; `R ACT-01` para parada | `AC-TOL-03`, `AC-TOL-04`, `AC-TOL-05` | `CMP-07` comprueba rechazo de traversal, symlink y overwrite; `CMP-12` añade marker y staging `0600`, publicación atómica create-only, lock no bloqueante, parada idempotente y reconciliación preautoridad; `DAT-25` no observa regresiones ni efectos no autorizados | `tests/test_tool_abuse_evaluation.py::test_filesystem_escape_preserves_sentinels_and_existing_file`<br>`tests/test_sandbox_recovery.py::test_create_is_atomic_owner_only_and_leaves_no_internal_artifacts`<br>`tests/test_sandbox_recovery.py::test_stop_is_idempotent_revokes_authority_and_context_failure_is_terminal`<br>`tests/test_final_retest.py::test_final_adversarial_metrics_are_observation_derived` | La recuperación se limita al efecto local de borrador; faltan procedimiento operativo y aislamiento de SO | PGS-06-M07 |
| `CTL-09` | Política de salida, redacción, errores saneados y detección de fugas | `PARCIAL` | `A/R ACT-02` | `AC-JB-01`, `AC-EX-03` | `CMP-09` aplica `reject > redact > allow`, sustituye correo y rutas por marcadores fijos, rechaza categorías de alta señal y evita conservar texto bruto; `DAT-25` conserva 12/12 casos benignos, 0 falsos rechazos y demuestra SC-07 solo mediante las 84 reglas cerradas predeclaradas en `DAT-24` | `tests/test_output_policy.py::test_redaction_is_deterministic_idempotent_and_value_free`<br>`tests/test_jailbreak_disclosure_evaluation.py::test_knowledge_disclosure_is_rejected_without_content_or_enumeration`<br>`tests/test_final_retest.py::test_final_benign_rubric_demonstrates_sc07_without_semantic_claim`<br>`tests/test_final_retest.py::test_m06_oracle_boundary_probe_is_repeated_without_leakage` | La cobertura literal continúa en cero y la rúbrica cerrada no demuestra equivalencia semántica general, detección universal ni comportamiento de un modelo real | Evaluación semántica autorizada y modelo real posterior |
| `CTL-10` | Límites de tamaño, tiempo, iteraciones, concurrencia y consumo | `PARCIAL` | `A/R ACT-02` | `AC-JB-02`, `AC-TOL-02`, `AC-DOS-01`, `AC-DOS-03` | `CMP-10` implementa preflight benigno, límites UTF-8, presupuestos por operación, consumo previo, checkpoints y lock advisory; `CMP-16` conserva 30 pares operativos, `DAT-25` fija cuatro fixtures DOS/SC inertes y `GSL-RESIDUAL-RISK-001` conserva esa exposición sin ejecutarla | `tests/test_resource_control.py::test_operation_budget_is_cumulative_and_observable`<br>`tests/test_resource_control.py::test_cli_lock_conflict_is_immediate_and_keeps_stdout_empty`<br>`tests/test_operational_metrics.py::test_reduced_real_smoke_verifies_both_candidates_without_repo_mutation`<br>`tests/test_final_retest.py::test_noncanonical_seam_cannot_masquerade_as_final` | El plazo no cancela llamadas síncronas, la API puede omitir el lock y no hay rate limit persistente, cuota distribuida, límite RSS o aislamiento de SO; los cuatro casos DOS/SC no se ejecutaron y M08 no mide su consumo | PGS-06-M07 y PGS-07-M02, bajo autorización posterior |
| `CTL-11` | Integridad de código, dependencias, cambios y releases | `PARCIAL` | `A/R ACT-02`; `C REV-01` planificado | `AC-DOS-02`, `AC-SC-01` | Git, remoto público, `uv.lock`, hashes del corpus y commits granulares permiten detectar diferencias en los artefactos cubiertos | `tests/test_adversarial_baseline.py::test_run_rejects_candidate_drift`<br>`tests/test_adversarial_baseline.py::test_versioned_evidence_is_reviewed_sanitized_and_internally_consistent` | No existen firma, CI, SBOM, revisión independiente ni política de release; las pruebas no cubren toda la cadena de suministro | PGS-06-M08 y PGS-07-M01/M03/M04 |
| `CTL-12` | Harness adversario, métricas, regresión y revisión independiente | `PARCIAL` | `A/R ACT-02`; `R REV-01` solo para revisión independiente | `AC-PI-01`, `AC-PI-02`, `AC-PI-03`, `AC-JB-01`, `AC-JB-02`, `AC-EX-01`, `AC-EX-02`, `AC-EX-03`, `AC-TOL-01`, `AC-TOL-02`, `AC-TOL-03`, `AC-TOL-04`, `AC-TOL-05`, `AC-DOS-01`, `AC-DOS-02`, `AC-DOS-03`, `AC-SC-01` | `CMP-07` conecta 14 fixtures PI/JB/EX/TOL con oráculos separados; `CMP-08` fija la baseline histórica; `CMP-13` a `CMP-17` conservan las comparaciones intermedias; `CMP-18` produjo `DAT-25` con 14/14 adversarios, 12/12 benignos y SC-06/SC-07 demostrados en su alcance cerrado; `GSL-RESIDUAL-RISK-001` documenta seis exposiciones sin aceptar riesgo | `tests/test_adversarial_corpus.py::test_manifest_fixes_scope_counts_and_partial_test_wiring`<br>`tests/test_control_findings.py::test_verifier_checks_all_pinned_sources_and_evidence_assertions`<br>`tests/test_final_retest.py::test_pre_run_rubric_is_closed_complete_and_hash_pinned`<br>`tests/test_final_retest.py::test_final_adversarial_metrics_are_observation_derived`<br>`tests/test_final_retest.py::test_final_benign_rubric_demonstrates_sc07_without_semantic_claim`<br>`tests/test_final_retest.py::test_historical_artifacts_are_pinned_and_dat22_is_not_final_performance`<br>`tests/test_final_retest.py::test_snapshot_is_closed_sanitized_and_metrics_fail_closed` | Cuatro casos DOS/SC siguen inertes; `CF-002` no es computable; no se evalúan equivalencia semántica general, ataques desconocidos ni un LLM real; `DAT-22` es histórico, de un host/sesión y sin energía, TCO o significación; faltan el registro formal, decisiones humanas y revisión independiente | PGS-05-M09, PGS-06-M03 y PGS-07-M01 a M06 |
| `CTL-13` | Eventos, monitorización, respuesta, rollback, comunicación y retirada | `PARCIAL` | `A/R ACT-02`; `R ACT-01` para avisos y parada | `AC-EX-03`, `AC-DOS-01`, `AC-DOS-02`, `AC-DOS-03`, `AC-SC-01` | `CMP-11` aporta observabilidad efímera y saneada; `CMP-12` detiene y reconcilia únicamente el efecto local de borrador según su condición real | `tests/test_security_events.py::test_event_and_report_are_closed_frozen_and_canonically_chained`<br>`tests/test_security_events.py::test_resource_and_lock_failures_emit_sanitized_signals`<br>`tests/test_sandbox_recovery.py::test_stop_is_idempotent_revokes_authority_and_context_failure_is_terminal` | No hay logging persistente, telemetría o monitor externo, alertas, runbook, respuesta general, comunicación o retirada; una señal no confirma un ataque ni activa la recuperación | PGS-06-M05 a M07 y PGS-07 |
<!-- control-traceability:end -->

## Mapeo de controles a NIST

| Control | NIST AI RMF 1.0 | NIST SP 800-218A | Correspondencia y límite |
|---|---|---|---|
| `CTL-01` | `GOVERN 1.3`, `1.4`, `2.1`; `MAP 1.5`, `1.6`; `MANAGE 1.2`–`1.4` | `D PO.1.1`, `PO.1.2`, `PO.2.1`, `PW.1.2` | Define requisitos, propietarios, prioridades, respuestas y riesgo residual; todavía no completa el gobierno formal |
| `CTL-02` | `GOVERN 1.5`, `1.6`, `4.2`; `MAP 2.1`, `2.2`, `3.3`, `4.2` | `D PW.1.1`, `PW.1.2`, `PO.3.3` | Inventaría el sistema, documenta límites y mantiene threat model y evidencia |
| `CTL-03` | `MAP 2.3`, `4.1`, `4.2`; `MEASURE 2.1`, `2.7`; `MANAGE 3.1` | `P PS.1.2`, `PS.3.2`, `PW.3.1`, `PW.3.2` | Aplica directamente al corpus de pruebas del laboratorio, pero no demuestra seguridad de datos de entrenamiento porque no se entrena un modelo |
| `CTL-04` | `MAP 2.2`, `3.3`; `MEASURE 2.7`; `MANAGE 1.3` | `D PW.1.1`, `PW.5.1`, `PW.8.1`, `PW.8.2` | Lleva amenazas de inyección al diseño, manejo de entradas y pruebas ejecutables |
| `CTL-05` | `MAP 2.1`, `4.2`; `MEASURE 2.7`; `MANAGE 1.3` | `D PW.5.1`, `PW.9.1`, `PW.9.2` | Exige manejo seguro y configuración por defecto de entradas, salidas y capacidades |
| `CTL-06` | `GOVERN 3.2`; `MAP 3.5`, `4.2`; `MEASURE 2.7` | `D PO.5.1`, `PW.1.1`, `PW.9.1` | Separa supervisión y autoridad y aplica mínimo privilegio; la identidad macOS compartida mantiene un gap |
| `CTL-07` | `GOVERN 3.2`; `MAP 3.5`; `MEASURE 2.8` | `D PO.1.2`, `PW.1.1`, `PW.9.1` | Define responsabilidad y aprobación; autentica un principal sintético, pero falta presencia e identidad humana real |
| `CTL-08` | `MAP 4.2`; `MEASURE 2.6`, `2.7`; `MANAGE 2.4` | `D PO.5.1`, `PW.5.1`, `PW.9.1`, `PW.9.2`; `P RV.2.2` | La publicación y reconciliación create-only son controles de desarrollo; el procedimiento de parada y recuperación operativa atraviesa una frontera que 800-218A no cubre completamente |
| `CTL-09` | `MEASURE 2.7`, `2.8`; `MANAGE 1.3` | `D PW.5.1`; `P RV.1.1` | Validar y sanear salidas es desarrollo; monitorizarlas durante operación solo tiene correspondencia parcial en el perfil |
| `CTL-10` | `MEASURE 1.1`, `2.7`; `MANAGE 1.2`, `1.3`, `4.1` | `D PO.5.1`, `PW.1.1`, `PW.9.1`; `P RV.1.1` | Los límites se diseñan y prueban antes del uso; rate limiting y consumo de runtime exceden parte del alcance de 800-218A |
| `CTL-11` | `GOVERN 6.1`, `6.2`; `MAP 4.1`, `4.2`; `MANAGE 3.1` | `D PO.1.3`, `PS.1.1`, `PS.2.1`, `PS.3.1`, `PS.3.2`, `PW.4.4` | Cubre requisitos a terceros, protección, procedencia, integridad y archivo de release |
| `CTL-12` | `MEASURE 1.1`–`1.3`, `2.1`, `2.7`, `2.13`; `MANAGE 1.1`–`1.4` | `D PO.3.3`, `PO.4.1`, `PW.2.1`, `PW.8.1`, `PW.8.2`, `RV.1.2` | Convierte amenazas en métricas, pruebas repetibles, revisión distinta del diseño y decisiones de riesgo |
| `CTL-13` | `GOVERN 1.5`, `4.3`; `MEASURE 2.4`, `3.1`–`3.3`; `MANAGE 2.3`, `2.4`, `4.1`, `4.3` | `D PO.5.3`, `RV.1.1`, `RV.1.3`, `RV.2.1`, `RV.2.2`, `RV.3.1` para desarrollo y vulnerabilidades; `P` para operación | El perfil apoya monitorización del entorno de desarrollo y respuesta a vulnerabilidades; el runbook operativo requiere controles complementarios |

## Mapeo específico de responsabilidades a NIST

| Decisión de responsabilidad | NIST AI RMF 1.0 | NIST SP 800-218A | Estado del laboratorio |
|---|---|---|---|
| Documentar propietario, ejecutores y comunicación | `GOVERN 2.1` | `PO.2.1` | `ACT-02`, `ACT-01` y `ACT-03` están definidos; falta incorporar formalmente `REV-01` |
| Formar a cada rol según amenazas y mitigaciones | `GOVERN 2.2` | `PO.2.2` | El curso aporta base formativa, pero todavía no existe un registro de competencia por rol |
| Mantener compromiso de la autoridad que acepta el riesgo | `GOVERN 2.3` | `PO.2.3` | En este laboratorio individual, `ACT-02` actúa como autoridad del proyecto; no se equipara a gobierno ejecutivo empresarial |
| Separar responsabilidades humanas y de la IA | `GOVERN 3.2`, `MAP 3.5` | `PW.1.1` | La matriz distingue propuesta, aprobación y ejecución; el principal sintético está autenticado, pero no existe prueba de presencia humana |
| Usar revisión independiente | `MEASURE 1.3` | `PW.2.1` | `REV-01` está planificado y sin asignar; `ACT-02` no puede revisar de forma independiente su propio diseño |
| Definir comunicación y respuesta ante fallos | `GOVERN 4.3`, `MANAGE 4.3` | `RV.1.3`, `RV.2.2` | Responsabilidad asignada, pero procedimientos y evidencia permanecen planificados |

## Cobertura y decisiones

- Los 17 abuse cases están vinculados al menos a un control técnico o de
  evaluación, además de los controles transversales `CTL-01`, `CTL-02` y
  `CTL-12`.
- Los controles existentes conservan sus límites actuales: un camino ausente
  o un adaptador determinista no equivale a resistencia de un modelo GenAI.
- `AC-TOL-05` permanece como residual de la baseline histórica. El checkout
  actual rechaza su literal, aunque `CTL-07` sigue parcial por no verificar
  presencia humana real.
- `AC-DOS-01` queda mitigado solo entre procesos que cooperan mediante la CLI;
  faltan cuota persistente y control sobre llamadas directas a la API.
- `AC-DOS-03` ya encuentra límites globales preventivos en el corpus benigno,
  pero sigue sin ejecutarse por las RoE y no acredita consumo real ni un límite
  frente a quien puede cambiar código y política.
- `CMP-11` hace observables rechazos, intervenciones y secuencias anómalas
  mediante reglas cerradas, pero no cambia por sí mismo la probabilidad,
  eficacia o alcance de ningún abuse case y no sustituye el retest.
- `CMP-12` cierra la ventana de archivo final parcial para `TOL-02` y conserva
  la no reutilización de autoridad. No implementa respuesta general,
  aislamiento de SO ni el runbook operativo.
- `DAT-23` registra seis hallazgos contra fuentes fijadas y mantiene sus
  categorías separadas: un control `PARCIAL`, una fixture inerte, un dato
  `NOT_COMPUTABLE`, un criterio `NOT_DEMONSTRATED` o un overhead sin umbral no
  se presentan como fallo. `CMP-17` verifica ese registro sin generar la
  clasificación ni reejecutar componentes.
- `DAT-25` conserva el retest final canónico ejecutado una sola vez por
  `CMP-18`: 14/14 casos adversarios completados, éxito observado 1/14 → 0/14,
  operaciones no autorizadas 1 → 0 y 12/12 casos benignos sin falsos rechazos
  ni regresión técnica. SC-07 solo queda demostrado bajo la rúbrica cerrada
  fijada en `DAT-24`; no se afirma equivalencia semántica general ni eficacia
  frente a un modelo GenAI real.
- `GSL-RESIDUAL-RISK-001` documenta seis riesgos y tratamientos posteriores,
  pero no completa `CTL-07`, `CTL-10` o `CTL-12`, no acredita revisión humana y
  no crea el registro formal o la aceptación reservados a PGS-06-M03.
- `AC-SC-01` no puede cerrarse solo con Git local y un lockfile.
- PGS-02-M08 no implementó por sí sola los controles de PGS-04. Con la
  implementación y verificación documental de PGS-04-M09, PGS-04 y el hito
  padre P01-M08 quedan cerrados.

## Fuentes oficiales

- [NIST AI Risk Management Framework 1.0](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF 1.0, NIST AI 100-1](https://doi.org/10.6028/NIST.AI.100-1)
- [NIST AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/)
- [NIST SP 800-218A, publicación final](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [NIST SP 800-218A, DOI](https://doi.org/10.6028/NIST.SP.800-218A)
- [NIST SP 800-218, SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)

## Próximo tratamiento

[`GSL-ROE-001`](./rules-of-engagement.md) ya delimita los 17 casos, la
autorización por ejecución, los targets, los presupuestos y la parada.
`GSL-PROFILE-VULNERABLE-001` ya está aislado y sin capacidad de ejecución.
`GSL-ADVERSARIAL-CORPUS-001` ya fija entradas y oráculos sintéticos separados,
y `CMP-08` fija la baseline canónica de 14 fixtures PI/JB/EX/TOL con
configuración, resultados, eventos y manifiesto saneados.
[`GSL-FINDINGS-ADVERSARIAL-001`](./adversarial-baseline-findings.md) documenta
los hallazgos, impacto, reproducción y límites. PGS-04-M01 añade la separación
estructural de dominios de confianza; PGS-04-M02 aplica los sobres estrictos y
PGS-04-M03 liga los grants, datos y efectos descritos en
[`GSL-VALIDATION-POLICY-001`](./validation-policy.md) y
[`GSL-LEAST-PRIVILEGE-001`](./least-privilege-policy.md). PGS-04-M04 añade la
aprobación sintética ligada y de un solo uso. PGS-04-M05 añade
[`GSL-OUTPUT-POLICY-001`](./output-safety-policy.md). PGS-04-M06 añade
[`GSL-RESOURCE-POLICY-001`](./resource-limits-policy.md) mediante `CMP-10`;
PGS-04-M07 añade
[`GSL-SECURITY-EVENTS-001`](./security-events-policy.md) mediante `CMP-11`.
PGS-04-M08 añade
[`GSL-SANDBOX-RECOVERY-001`](./sandbox-recovery-policy.md) mediante `CMP-12`.
PGS-04-M09 completa la matriz canónica con amenazas explícitas, responsables,
selectores pytest existentes y limitaciones verificadas documentalmente. El
PGS-05-M01 repite exactamente los 14 IDs y conserva su proyección neutral en
`evaluations/adversarial-retest-v1/`; PGS-05-M02 fija la comparación en
`evaluations/adversarial-metrics-v1.json`; PGS-05-M03 fija la comparación
funcional en `evaluations/benign-utility-v1.json`, sin afirmar equivalencia
semántica. PGS-05-M04 fija latencia, CPU, RSS, consumo y complejidad
descriptiva en `evaluations/operational-metrics-v1.json`. PGS-05-M05 consolida
seis hallazgos revisados en `evaluations/control-findings-v1.json` y `CMP-17`
los verifica contra 44 referencias escalares sin reejecutar las fuentes.
PGS-05-M06 corrige el tratamiento de utilidad sin ampliar autoridad;
PGS-05-M07 fija la rúbrica `DAT-24`, ejecuta una sola vez el retest mediante
`CMP-18` y conserva el resultado saneado en `DAT-25`. PGS-05-M08 añade
[`GSL-RESIDUAL-RISK-001`](./residual-risk-and-tradeoffs.md) sin reinterpretar
los cuatro casos inertes, la ausencia de un modelo real o la rúbrica cerrada
como garantías más amplias. El siguiente tratamiento es PGS-05-M09; la RACI,
el registro formal y cualquier aceptación continúan en PGS-06-M03.
