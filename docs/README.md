# Documentación

Este directorio contiene la documentación estable que describe las fuentes,
arquitectura, threat model, decisiones, riesgos, fichas y runbooks del sistema
real.

## Inventario actual

- [Baseline de marcos y fuentes](./framework-versions.md): versiones oficiales
  fijadas para OWASP, MITRE ATLAS y NIST, con fecha de consulta y regla de
  actualización.
- [Inventario del sistema actual](./system-inventory.md): actores, datos,
  componentes, modelo, herramientas, identidades, dependencias,
  infraestructura, integraciones y ausencias verificadas.
- [System card](./system-card.md): propósito, usuarios, usos, arquitectura,
  autoridad, evidencia, límites y riesgos del sistema local observado.
- [Data card](./data-card.md): inventario de `DAT-01` a `DAT-25`, procedencia,
  sensibilidad, calidad, acceso, ciclo de vida y límites de los datos
  sintéticos y de la evidencia.
- [Model card](./model-card.md): contrato y límites de `MOD-01`, identificado
  expresamente como doble determinista sin entrenamiento ni proveedor real.
- [Evaluación de impacto de IA](./ai-impact-assessment.md): cribado del alcance
  actual, partes afectadas, diez dimensiones de impacto, handoff de los seis
  riesgos pendientes y triggers de reevaluación; no autoriza producción,
  ampliaciones ni aceptación de riesgo.
- [Matriz RACI](./raci.md): doce actividades con exactamente un accountable
  actual, responsabilidades ejercidas y planificadas separadas, límites de
  decisión y concentración de funciones explícita.
- [Registro formal de riesgos](./risk-register.md): seguimiento vivo de
  `RR-01` a `RR-06`, owner, controles, brecha, respuesta propuesta, targets,
  triggers y seis decisiones `PENDIENTE_HUMANA`.
- [Mapa de cumplimiento](./compliance-map.md): nueve fuentes y decisiones
  clasificadas como obligación potencial, estándar o guía voluntaria y
  decisión interna, con estado, evidencia, trigger y límites frente a
  conformidad, certificación o asesoramiento jurídico.
- [Mapa C4 de arquitectura](../architecture/manifest.json): contexto,
  contenedores locales, componentes, flujo de datos y seis trust boundaries
  sustentados por el inventario.
- [Matriz de autoridad y consecuencias](./authority-matrix.md): cadenas
  verificadas entre actores, modelo, identidades, datos, herramientas, acciones
  y efectos máximos actuales, incluidas las rutas que no existen.
- [Catálogo de abuse cases](./abuse-cases.md): 17 escenarios de prompt
  injection, jailbreak, exfiltración, abuso de herramientas, disponibilidad y
  supply chain, separados por alcanzabilidad actual.
- [Priorización de abuse cases](./risk-prioritization.md): método reproducible
  que combina impacto, probabilidad condicionada y capacidad real, con los 17
  casos ordenados como backlog de pruebas.
- [Crosswalk de amenazas](./threat-crosswalk.md): correspondencias directas,
  parciales y gaps explícitos entre los 17 casos, OWASP LLM 2025, OWASP
  Agentic 2026 y MITRE ATLAS `v2026.06`.
- [Mapa de responsabilidades y controles
  NIST](./control-responsibility-mapping.md): matriz canónica con una fila por
  control, amenazas explícitas, propietarios, pruebas actuales, limitaciones y
  correspondencias seleccionadas con NIST AI RMF 1.0 y NIST SP 800-218A, sin
  atribuir conformidad ni eficacia no demostrada.
- [Rules of Engagement](./rules-of-engagement.md): autorización por ejecución,
  targets, acciones, datos, presupuestos, evidencias y condiciones de parada
  para los 17 abuse cases del laboratorio propio.
- [Corpus adversario sintético](../data/adversarial/README.md): 18 entradas y
  18 oráculos separados para los 17 casos y seis familias; 14 fixtures están
  conectadas al harness interno, evaluadas canónicamente y 4 permanecen
  inertes.
- [Baseline adversaria histórica](../evaluations/adversarial-baseline-v1/README.md):
  candidato exacto, reproducción, 13 `PASS`, 1 `RESIDUAL`, métricas, artefactos
  saneados y límites de interpretación.
- [Retest adversario v1](../evaluations/adversarial-retest-v1/README.md):
  candidato endurecido exacto, 14 ejecuciones completas, triples observados,
  relaciones neutrales, comparabilidad de corpus e integridad saneada; declara
  `final_retest: false`.
- [Métricas adversarias v1](../evaluations/adversarial-metrics-v1.json):
  14 pares verificados, clasificación cerrada, 1/14 → 0/14 de éxito y una
  operación no autorizada aceptada/ejecutada → cero.
- [Utilidad benigna v1](../evaluations/benign-utility-v1.json): comparación
  saneada de 12 casos antes/después, con terminación técnica, cumplimiento
  textual estricto, falsos rechazos, deltas y límites de interpretación.
- [Métricas operativas v1](../evaluations/operational-metrics-v1.json): 30
  pares pre/post con pared, CPU, RSS, consumo, complejidad y límites sin
  umbral universal.
- [Registro canónico de hallazgos M05](../evaluations/control-findings-v1.json):
  seis observaciones revisadas sobre `DAT-20/21/22`, con 0 fallos actuales
  observados, 1 bypass histórico, 2 resultados negativos y 3 gaps; no
  sustituye la matriz canónica de controles ni el riesgo residual de M08.
- [Rúbrica cerrada del retest final M07](../evaluations/final-retest-rubric-v1.json):
  `DAT-24`, fijada antes del run con 84 cláusulas, fuentes e invariantes
  autorizados, sin juez LLM ni entrega al target.
- [Evidencia del retest final M07](../evaluations/final-retest-v1.json):
  `DAT-25`, 14 casos adversarios y 12 benignos sobre el candidato `77edd640`,
  con `SC-06` y `SC-07` demostrados dentro del contrato cerrado y límites
  explícitos frente a generalización, semántica y modelo real.
- [Riesgo residual y compensaciones](./residual-risk-and-tradeoffs.md):
  `GSL-RESIDUAL-RISK-001` agrupa los 17 abuse cases una sola vez en seis
  riesgos posteriores a `DAT-25`, distingue fuentes finales, históricas e
  inertes y mantiene pendiente toda decisión humana sin recalcular scores; es
  el snapshot de entrada del registro formal.
- [ADR de la baseline local-first](./architecture-decision-record.md):
  `GSL-ADR-001` acepta la arquitectura determinista para el alcance actual,
  compara alternativas y fija triggers, consecuencias, rollback compensatorio
  y supersesión sin seleccionar capacidades futuras ni aceptar riesgo.
- [Hallazgos de la baseline adversaria](./adversarial-baseline-findings.md):
  uso actual del laboratorio, impacto de las variantes observadas,
  reproducción, residual conocido y límites de la evidencia.
- [Política de validación y allowlists](./validation-policy.md): sobres
  estrictos de entrada y salida, grants de ejecución, comportamiento de fallo
  cerrado y límites de PGS-04-M02/M03/M04.
- [Política de mínimo privilegio](./least-privilege-policy.md): principales y
  scopes lógicos, proyección de conocimiento, grants de herramienta y efecto,
  aprobación sintética autenticada, entorno mínimo de subproceso y límites de
  PGS-04-M03/M04.
- [Política de seguridad de salida](./output-safety-policy.md): canales
  cerrados, precedencia de rechazo, redacción determinista, binding opaco,
  inserción antes de entrega o aprobación y límites de PGS-04-M05.
- [Política de límites de recursos](./resource-limits-policy.md): topes
  preventivos de bytes, registros, tiempo cooperativo, iteraciones, consumo,
  borradores y procesos cooperantes de la CLI para PGS-04-M06.
- [Política de eventos y señales de seguridad](./security-events-policy.md):
  journal cerrado y acotado en memoria, correlación por operación y caso,
  cadena SHA-256, señales deterministas, salida CLI opt-in y límites de
  PGS-04-M07.
- [Política de parada y recuperación del
  sandbox](./sandbox-recovery-policy.md): publicación atómica create-only,
  revocación de autoridad, reconciliación preautoridad y límites de
  PGS-04-M08.

La documentación se añade junto al hito técnico correspondiente y debe
distinguir el estado implementado de las decisiones o trabajos futuros.
