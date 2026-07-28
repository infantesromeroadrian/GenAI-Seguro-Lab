# Política de cambios de modelo y reevaluación — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-MODEL-CHANGE-001` |
| Versión | `1.0.0` |
| Fecha | 2026-07-28 |
| Estado | `VIGENTE_ALCANCE_ACTUAL` |
| Owner | `ACT-02` |
| Microtarea | `PGS-06-M09` |
| Modelo actual | `MOD-01`, doble determinista `deterministic/scripted-v1` |

Esta política decide qué revisiones exige un cambio antes de presentarlo como
parte del sistema evaluado. “Modelo” incluye el adaptador, sus intercambios,
mensajes, esquemas y fronteras; no implica que el proyecto tenga pesos,
entrenamiento o un proveedor real.

Clasificar un cambio no lo autoriza. Introducir modelo o proveedor real, red,
cloud, datos reales, usuarios externos, gasto, release o una nueva superficie
requiere autoridad específica antes de materializarlo.

## Catálogo de reevaluación

<!-- reevaluation-catalog:start -->
| ID | Paquete mínimo | Resultado esperado |
|---|---|---|
| `REEVAL-01` | Contratos, esquema, unitarias, smoke y regresión focal | El cambio cumple su contrato y no rompe la superficie afectada |
| `REEVAL-02` | Corpus benigno completo y utilidad | Terminación, éxito, falsos rechazos y cláusulas bajo criterio predeclarado |
| `REEVAL-03` | Corpus adversario autorizado PI/JB/EX/TOL | Triple observado, efectos y métricas con oráculos separados; no ejecuta DOS/SC inerte |
| `REEVAL-04` | Recursos, operación, parada y recuperación | Latencia, consumo, límites y recuperación proporcionales al cambio |
| `REEVAL-05` | Fichas, AIA, riesgos, RACI, cumplimiento y ADR | Alcance, impacto, decisiones, owners y afirmaciones reflejan el estado real |
| `REEVAL-06` | Dependencias, lock, procedencia, secretos y reconstrucción limpia | Toolchain y supply chain identificadas; ausencia o gaps registrados |
| `REEVAL-07` | Threat model, autoridad, RoE y arquitectura afectada | Actores, datos, herramientas, efectos, trust boundaries y límites coherentes |
| `REEVAL-08` | Revisión independiente humana | Persona cualificada distinta del diseñador/implementador reproduce evidencia saneada y registra discrepancias |
<!-- reevaluation-catalog:end -->

Los paquetes son acumulativos según la tabla de cambios. Una prueba documental
no sustituye una ejecución cuando el comportamiento cambia, y una ejecución
no sustituye la decisión humana o la actualización de gobierno.

## Clasificación de cambios

<!-- model-change-classes:start -->
| ID | Clase y ejemplos | Trigger heredado | Reevaluación mínima | Decisión previa |
|---|---|---|---|---|
| `MCHG-01` | Prosa, enlace o formato sin alterar contrato, afirmación, código, datos o evidencia | Ninguno si el diff demuestra ese límite | `REEVAL-01` documental focal | `SIN_REEVALUACION_PRODUCTO`; revisión del diff |
| `MCHG-02` | Refactor interno que pretende conservar comportamiento, API, esquema y límites | `ADR-TRG-06` / `AIA-TRG-06` si aparece drift o regresión | `REEVAL-01`, `REEVAL-02`, `REEVAL-03`; añadir `REEVAL-04` si toca concurrencia, tiempo, filesystem o estado | `REEVALUACION_FOCAL` sobre candidato exacto |
| `MCHG-03` | Intercambio guionizado, instrucción, mensaje, esquema, parser, salida o versión de `MOD-01` | `ADR-TRG-01`, `ADR-TRG-06`; `AIA-TRG-01`, `AIA-TRG-06` | `REEVAL-01`, `REEVAL-02`, `REEVAL-03`, `REEVAL-05`, `REEVAL-07` | `REEVALUACION_COMPLETA` del comportamiento afectado |
| `MCHG-04` | Corpus, manifiesto, expected result, oráculo, rúbrica, idioma o distribución de entradas | `ADR-TRG-01`, `ADR-TRG-03`, `ADR-TRG-06`; `AIA-TRG-01`, `AIA-TRG-03`, `AIA-TRG-06` | `REEVAL-01`, `REEVAL-02`, `REEVAL-03`, `REEVAL-05`, `REEVAL-07`; nueva baseline si cambia comparabilidad | `REEVALUACION_COMPLETA`; evidencia histórica inmutable |
| `MCHG-05` | Modelo real, proveedor, parámetros probabilísticos, prompt libre, RAG, memoria o fine-tuning | `ADR-TRG-01`, `ADR-TRG-04`; `AIA-TRG-01`, `AIA-TRG-04` | `REEVAL-01`, `REEVAL-02`, `REEVAL-03`, `REEVAL-04`, `REEVAL-05`, `REEVAL-06`, `REEVAL-07` y `REEVAL-08`, incluyendo privacidad, coste, egress, datos y nuevas amenazas | `NECESITA_AUTORIDAD` antes de diseño o llamada |
| `MCHG-06` | UI, API, listener, usuario remoto, autenticador o nueva parte afectada | `ADR-TRG-02`; `AIA-TRG-02` | `REEVAL-01` a `REEVAL-08`, con accesibilidad, contestabilidad, identidad y concurrencia | `NECESITA_AUTORIDAD` y cambio arquitectónico |
| `MCHG-07` | Herramienta, efecto, principal, scope, secreto, dato o sandbox | `ADR-TRG-03`; `AIA-TRG-03` | `REEVAL-01` a `REEVAL-08`, con mínimo privilegio, aprobación, parada, recuperación y consecuencias | `NECESITA_AUTORIDAD` si amplía efecto o datos |
| `MCHG-08` | Dependencia, runtime, red, cloud, contenedor, servicio, identidad o distribución | `ADR-TRG-04`, `ADR-TRG-05`; `AIA-TRG-04`, `AIA-TRG-05` | `REEVAL-01`, `REEVAL-03` a `REEVAL-08`; añadir `REEVAL-02` para un candidato de producto | `NECESITA_AUTORIDAD` para infraestructura, red, gasto o release |
| `MCHG-09` | Control, harness, métrica, umbral, afirmación, bypass, fuga, incidente o pérdida de reproducibilidad | `ADR-TRG-06`, `ADR-TRG-07`; `AIA-TRG-06`, `AIA-TRG-07` | `REEVAL-01` a `REEVAL-08` según impacto; el incidente usa además `GSL-AI-IR-001` | `REEVALUACION_COMPLETA`; corrección separada de la evidencia |
<!-- model-change-classes:end -->

Si un cambio encaja en varias clases, se aplica la unión más exigente. Una
clasificación dudosa se eleva, no se rebaja por comodidad.

## Proceso de cambio

1. **Proponer:** identificar target, motivo, owner, diff previsto, clase
   `MCHG-*`, triggers y autoridad existente o necesaria.
2. **Fijar contrato:** declarar criterios, corpus, oráculos, métricas,
   presupuesto y candidato antes de ejecutar la evaluación.
3. **Actualizar diseño:** revisar solo las fichas, riesgos, RoE, cumplimiento,
   ADR y área de Tecture realmente afectadas.
4. **Implementar:** mantener el cambio separado de sus oráculos y de la
   evidencia histórica; una corrección no altera el dato que la motivó.
5. **Evaluar:** ejecutar los paquetes `REEVAL-*` sobre un commit exacto. Las
   cuatro fixtures DOS/SC siguen inertes sin decisión humana expresa.
6. **Registrar:** crear IDs y artefactos nuevos con fuentes, hashes, resultado
   y límites. No sobrescribir una evidencia anterior.
7. **Revisar:** cuando corresponda, `REV-01` debe ser una persona cualificada
   distinta; un autorrecheck o agente del mismo proceso no sustituye
   `REEVAL-08`.
8. **Decidir y publicar:** la evidencia informa; `ACT-02` decide dentro de su
   autoridad. Cloud, gasto, release y canales externos conservan autorización
   separada.

## Evidencia histórica y comparabilidad

- `DAT-25` es el único retest final de su candidato y contrato. No se
  regenera, reejecuta, sobrescribe ni presenta como resultado de un candidato
  posterior.
- Un cambio de comportamiento produce una evidencia nueva con otro ID. Si
  altera corpus, oráculo, rúbrica o semántica de una métrica, se declara no
  comparable o se crea una baseline nueva.
- Un nuevo resultado no corrige retrospectivamente un bypass, hallazgo o
  resultado negativo histórico.
- Cambiar solo el evaluador exige demostrar que no recibe el oráculo el target,
  fijar su commit separado y volver a validar sus invariantes.
- Las afirmaciones públicas se limitan al candidato, corpus, entorno y fecha
  efectivamente medidos.

## Rollback, incidentes y cierre

Un rollback sigue `GSL-ADR-001` y
[`GSL-STOP-RECOVERY-001`](./stop-recovery-procedure.md): detiene la exposición,
publica un cambio compensatorio revisable y conserva los resultados previos.
No borra un efecto ya ocurrido ni reescribe `main`.

Un bypass, fuga, secreto, dato real o drift activa
[`GSL-AI-IR-001`](./ai-incident-response-runbook.md) antes de continuar. Cerrar
el change record no acepta ni cierra automáticamente `RR-01` a `RR-06`.

## Relación con Tecture

La política no materializa ninguno de sus triggers y no modifica
`architecture/`. Una implementación que cambie componentes, interfaces,
almacenes, integraciones, despliegues, flujos o trust boundaries exige
actualizar únicamente el área afectada.
