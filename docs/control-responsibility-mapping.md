# Mapa de responsabilidades y controles NIST

## Ficha del mapeo

| Campo | Valor |
|---|---|
| Identificador | `GSL-NIST-CONTROLS-001` |
| Versión | `1.5.0` |
| Fecha de corte | 2026-07-26 |
| Baseline adversaria histórica | commit evaluado `93aefa45eac687d219bfed32f03be4e60e4a13ed` + evidencia PGS-03-M07 |
| Control vigente | PGS-04-M08 en esta revisión; el commit exacto se obtiene del historial Git |
| Threat model de origen | [`GSL-ABUSE-CASES-001`](./abuse-cases.md), [`GSL-RISK-PRIORITY-001`](./risk-prioritization.md) y [`GSL-THREAT-CROSSWALK-001`](./threat-crosswalk.md) |
| Autoridad de origen | [`GSL-AUTH-MATRIX-001`](./authority-matrix.md) |
| Baseline normativa | [NIST AI RMF 1.0 y NIST SP 800-218A](./framework-versions.md) |
| Alcance | responsabilidades humanas y controles del laboratorio local actual y de las fases ya planificadas |

Este documento convierte los 17 abuse cases en un registro de controles con
responsable, estado, evidencia y destino de verificación. El mapeo selecciona
resultados de NIST AI RMF 1.0 y tareas de NIST SP 800-218A que ayudan a
estructurar el trabajo; no acredita conformidad, certificación ni eficacia.

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

### Matriz RACI del ciclo

`A` es quien responde por el resultado, `R` quien lo ejecuta, `C` quien es
consultado e `I` quien recibe información. Las marcas de `REV-01` solo se
activarán cuando exista una persona independiente.

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

| ID | Control | Estado | Responsable | Abuse cases tratados | Evidencia actual y límite | Próxima evidencia prevista |
|---|---|---|---|---|---|---|
| `CTL-01` | Requisitos de seguridad, tolerancia y tratamiento de riesgo | `PARCIAL` | `A/R ACT-02` | Los 17 casos de `GSL-ABUSE-CASES-001` | README, criterios de éxito, catálogo y priorización fijan límites; falta un registro formal de riesgos, aceptación residual y revisión periódica | PGS-06-M02 a M04 y PGS-05-M08 |
| `CTL-02` | Inventario, límites, autoridad, threat model y disparadores de cambio | `PRESENTE` | `A/R ACT-02`; `C REV-01` planificado | Los 17 casos de `GSL-ABUSE-CASES-001` | Inventario, C4, autoridad, catálogo y priorización incorporan `CMP-06` y el alcance PI/JB/EX/TOL de `CMP-07`; deberán revisarse cuando el harness conecte nuevos casos o cambie de target | Revisión en cada disparador y matriz final PGS-07-M06 |
| `CTL-03` | Procedencia, esquema e integridad del corpus y artefactos | `PRESENTE` para los corpus sintéticos actuales | `A/R ACT-02` | `AC-PI-02`, `AC-PI-03`, `AC-JB-01`, `AC-DOS-02`, `AC-DOS-03`, `AC-SC-01` | Los corpus aplican esquemas estrictos, procedencia, conteos y SHA-256; entradas y oráculos adversarios están separados. `CMP-10` limita el corpus benigno antes de parsear o hashear a 64 KiB, 8 KiB por registro y 32+32 registros. No hay firma ni control de acceso propio, y el límite no sustituye una política para futuros corpus o datos reales | Supply chain PGS-06-M08 y retest PGS-05-M04 |
| `CTL-04` | Separación de instrucciones y contenido no confiable, resistencia a inyección y jailbreak | `PARCIAL` | `A/R ACT-02` | `AC-PI-01`, `AC-PI-02`, `AC-PI-03`, `AC-JB-01` | `ModelMessage` clasifica instrucciones confiables, datos de usuario, contenido no confiable y salidas del modelo; `ModelRequest` exige los tres dominios de entrada y una única instrucción confiable inicial. El flujo ordinario declara `separated`, las salidas de herramienta vuelven como no confiables y el perfil aislado conserva `deliberately_merged`. La evidencia es estructural y determinista: todavía falta el retest y un modelo GenAI real | Retest PGS-05-M01 a M03 |
| `CTL-05` | Validación de entradas, salidas y argumentos; allowlist de herramientas | `PARCIAL` | `A/R ACT-02` | `AC-JB-02`, `AC-EX-01`, `AC-EX-02`, `AC-TOL-01`, `AC-TOL-02` | Los sobres Pydantic cierran entradas y salida; `ToolExecutionGrant` limita una herramienta; `CMP-09` añade reglas semánticas explícitas antes de entrega o aprobación. La evidencia sigue limitada al doble determinista y a los casos programados | Retest y modelo real en PGS-05 |
| `CTL-06` | Mínimo privilegio y separación modelo–identidad–datos–herramientas | `PARCIAL` | `A/R ACT-02` | `AC-TOL-01`, `AC-TOL-02`, `AC-TOL-05`, `AC-SC-01` | `IDN-05` liga grants opacos a principal, scope, herramienta e instancia; `TOL-01` retiene la vista exacta del incidente; `TOL-02` separa preparación y efecto, autentica `IDN-03` de forma sintética y crea por descriptor no-follow `0600`; EX-003 recibe un entorno allowlisted. `IDN-01` conserva permisos amplios y no existe identidad de servicio | Retest PGS-05 y revisión de aislamiento cuando cambie el runtime |
| `CTL-07` | Confirmación humana autenticada, ligada al contenido y no reutilizable | `PARCIAL` | `A ACT-02`; `R ACT-03` | `AC-TOL-03`, `AC-TOL-05` | `DraftApprovalAuthority` autentica una identidad sintética mediante credencial local, liga challenge, aprobación y grant a todo el contexto, aplica TTL y consumo único y rechaza el literal histórico antes de I/O. No verifica presencia humana real ni muestra el contenido en una interfaz | Interfaz/autenticador con presencia humana y retest PGS-05 |
| `CTL-08` | Efectos de filesystem confinados, creación exclusiva, parada y recuperación segura | `PARCIAL` | `A/R ACT-02`; `R ACT-01` para parada | `AC-TOL-03`, `AC-TOL-04`, `AC-TOL-05` | `CMP-07` verifica en `$TMP` el rechazo de traversal, symlink y overwrite. `CMP-12` añade marker/staging `0600`, publicación atómica create-only, lock no bloqueante, `stop()` idempotente y reconciliación preautoridad que nunca republica o borra el final. Sigue faltando el procedimiento operativo y el retest adversario | PGS-06-M07 y PGS-05 |
| `CTL-09` | Política de salida, redacción, errores saneados y detección de fugas | `PARCIAL` | `A/R ACT-02` | `AC-JB-01`, `AC-EX-03` | `CMP-09` es obligatorio en resumen y borradores, aplica `reject > redact > allow`, sustituye correo y rutas por marcadores fijos, rechaza categorías de alta señal y evita conservar texto bruto en la proyección de invocaciones. La cobertura es léxica, no universal, y aún no existe retest ni modelo real | Retest, bypasses y modelo real en PGS-05 |
| `CTL-10` | Límites de tamaño, tiempo, iteraciones, concurrencia y consumo | `PARCIAL` | `A/R ACT-02` | `AC-JB-02`, `AC-TOL-02`, `AC-DOS-01`, `AC-DOS-03` | `CMP-10` implementa `GSL-RESOURCE-POLICY-001`: preflight benigno, límites UTF-8, presupuestos `analyze`/`baseline`/`draft`, consumo previo, checkpoints y lock advisory no bloqueante. Sigue parcial porque el plazo no cancela llamadas síncronas, la API puede omitir el lock y no hay rate limit persistente, cuota distribuida, RSS o aislamiento de SO. `GSL-ROE-001` continúa siendo autoridad separada de evaluación | Medición y retest PGS-05-M04 |
| `CTL-11` | Integridad de código, dependencias, cambios y releases | `PARCIAL` | `A/R ACT-02`; `C REV-01` planificado | `AC-DOS-02`, `AC-SC-01` | Git, remoto público, `uv.lock`, hashes del corpus y commits granulares permiten detectar diferencias; faltan firma, CI, SBOM, revisión independiente y política de release | PGS-06-M08 y PGS-07-M01/M03/M04 |
| `CTL-12` | Harness adversario, métricas, regresión y revisión independiente | `PARCIAL` | `A/R ACT-02`; `R REV-01` solo para revisión independiente | Los 17 casos de `GSL-ABUSE-CASES-001` | `CMP-07` cubre 14 fixtures PI/JB/EX/TOL con oráculos separados; `CMP-08` fija una baseline reproducible con 13 `PASS`, 1 `RESIDUAL`, métricas y evidencia saneada, y `GSL-FINDINGS-ADVERSARIAL-001` documenta impacto, reproducción y límites. Faltan 4 casos, retest y revisor independiente | PGS-05 y PGS-07-M01 a M06 |
| `CTL-13` | Eventos, monitorización, respuesta, rollback, comunicación y retirada | `PARCIAL` | `A/R ACT-02`; `R ACT-01` para avisos y parada | `AC-EX-03`, `AC-DOS-01`, `AC-DOS-02`, `AC-DOS-03`, `AC-SC-01` | `CMP-11` aporta observabilidad efímera y `CMP-12` detiene/reconcilia únicamente el efecto local de borrador a partir de su condición real. No hay logging persistente, telemetría o monitor externo, alertas, runbook, respuesta general, comunicación o retirada; una señal no confirma un ataque ni activa la recuperación | PGS-06-M05 a M07 y PGS-07 |

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
- `AC-SC-01` no puede cerrarse solo con Git local y un lockfile.
- PGS-02-M08 no implementa controles de PGS-04 ni cierra P01-M08. El hito padre
  exige tanto este diseño como la implementación y verificación posterior.

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
El siguiente tratamiento es asociar cada control con amenaza, responsable,
prueba y limitación en PGS-04-M09.
