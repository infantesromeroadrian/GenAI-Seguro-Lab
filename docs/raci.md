# Matriz RACI — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-RACI-001` |
| Versión | `1.0.0` |
| Fecha | 2026-07-28 |
| Estado | `VIGENTE_ALCANCE_ACTUAL` |
| Corte de las fuentes | commit `648dd9afe9ef696388257ebf8dda4b59ece1aeb5` |
| Alcance | laboratorio local, determinista, sintético y sin red |

Esta matriz formaliza quién responde por las actividades de gobierno, cambio,
operación y verificación del sistema actual. No amplía la autoridad descrita en
la [matriz de autoridad](./authority-matrix.md), no asigna una persona a
`REV-01` y no acepta ninguno de los riesgos del
[registro formal](./risk-register.md).

## Roles

| Rol | Estado | Límite |
|---|---|---|
| `ACT-02` — mantenedor y tester | Actual | Controla requisitos, código, corpus, dependencias, pruebas, Git y decisiones de riesgo. Su autoridad de mantenimiento no demuestra separación de funciones. |
| `ACT-01` — operador local | Actual | Ejecuta escenarios autorizados, detiene su proceso y comunica anomalías. No cambia controles ni decide riesgo residual. |
| `ACT-03` — confirmador sintético | Actual, interno | Autentica un principal sintético para una propuesta concreta. No demuestra presencia, comprensión ni identidad humana real. |
| `REV-01` — revisor independiente | Planificado y sin asignar | Solo estará activo cuando una persona cualificada distinta de quien diseñó e implementó el candidato acepte la revisión. |

## Convención de la matriz

- `A`: accountable actual; responde por el resultado y la decisión. Cada fila
  tiene exactamente uno.
- `R`: responsable actual de ejecutar la actividad.
- `C`: consultado antes de decidir o ejecutar.
- `I`: informado después del hito o ante una incidencia.
- `P-R`, `P-C` y `P-I`: participación planificada, todavía inactiva.
- `—`: sin responsabilidad asignada en el alcance actual.

`A/R` concentra ambas funciones en el mismo rol. Las marcas planificadas no
cuentan como responsabilidad ejercida ni como revisión realizada.

## Matriz formal

<!-- raci-matrix:start -->
| ID | Actividad | `ACT-02` | `ACT-01` | `ACT-03` | `REV-01` | Evidencia o trigger |
|---|---|---|---|---|---|---|
| `RACI-01` | Definir requisitos de seguridad, alcance y criterios de tolerancia | `A/R` | `C` | `C` | `P-C` | README, `GSL-AIA-001`, `GSL-ADR-001` y cambio de alcance |
| `RACI-02` | Mantener inventario, fichas y evaluación de impacto | `A/R` | `C` | `C` | `P-I` | `GSL-SYSTEM-CARD-001`, `GSL-DATA-CARD-001`, `GSL-MODEL-CARD-001` y `GSL-AIA-001` |
| `RACI-03` | Mantener threat model, priorización y diseño de controles | `A/R` | `C` | `C` | `P-C` | `GSL-ABUSE-CASES-001`, `GSL-RISK-PRIORITY-001` y cambio de amenaza |
| `RACI-04` | Cambiar código, datos, dependencias o configuración | `A/R` | `I` | `I` | `P-C` | diff, pruebas, procedencia y microtarea autorizada |
| `RACI-05` | Operar escenarios autorizados y comunicar anomalías | `A` | `R` | `I` | `P-I` | `GSL-ROE-001`, salida saneada y condición de parada |
| `RACI-06` | Confirmar una propuesta antes de un efecto `C2` | `A` | `I` | `R` | `P-C` | challenge, binding, TTL y consumo único de `TOL-02` |
| `RACI-07` | Diseñar y ejecutar pruebas, métricas y retest | `A/R` | `C` | `I` | `P-C` | suite, rúbrica cerrada y evidencia versionada |
| `RACI-08` | Mantener el registro de riesgos y seguir tratamientos | `A/R` | `C` | `C` | `P-C` | `GSL-RISK-REGISTER-001` y triggers por riesgo |
| `RACI-09` | Decidir si mitigar, evitar, transferir, aceptar, diferir o escalar un riesgo | `A/R` | `C` | `C` | `P-C` | decisión humana explícita y evidencia indicada en `RDEC-01` a `RDEC-06` |
| `RACI-10` | Detener, responder, recuperar y analizar una incidencia | `A/R` | `R` | `I` | `P-C` | señal saneada, estado real, runbook y recuperación |
| `RACI-11` | Realizar una revisión independiente | `A` | `I` | `I` | `P-R` | asignación nominal futura y evidencia de `PGS-07-M04` |
| `RACI-12` | Aprobar cambio, release, rollback o retirada | `A/R` | `I` | `I` | `P-C` | ADR, pruebas, registro de riesgos y autoridad externa específica cuando aplique |
<!-- raci-matrix:end -->

## Derechos de decisión y límites no delegados

1. Solo `ACT-02` puede registrar hoy una decisión humana sobre `RR-01` a
   `RR-06`. El estado actual de las seis decisiones es
   `PENDIENTE_HUMANA`.
2. `ACT-01` puede parar su ejecución y escalar una anomalía sin esperar una
   decisión de aceptación; esa parada no cierra ni reclasifica el riesgo.
3. `ACT-03` solo confirma técnicamente una propuesta ligada al contexto. Su
   intervención no sustituye aprobación humana, revisión independiente o
   aceptación de riesgo.
4. `REV-01` no tiene una persona asignada. Sus marcas `P-*` no permiten afirmar
   que el sistema o sus pruebas hayan sido revisados de forma independiente.
5. Publicar releases, usar cloud, incurrir en gasto, introducir datos reales o
   probar terceros requiere autoridad específica fuera de esta matriz.

## Concentración y separación de funciones

`ACT-02` es el único accountable actual en las doce actividades y además
ejecuta diez de ellas. Es una limitación explícita del laboratorio individual,
no un modelo objetivo para producción. Antes de cualquier uso externo o de
alto impacto deben asignarse personas distintas para operación, decisión de
riesgo y revisión independiente, y actualizar esta matriz.

## Revisión

Revisar `GSL-RACI-001` si se incorpora una persona, proveedor, repositorio
operado por terceros, interfaz, modelo real, dato real, nuevo efecto,
despliegue, obligación aplicable o cambio de autoridad. El cambio de una marca
planificada a actual exige identificar a la persona y conservar evidencia de
su aceptación del rol.
