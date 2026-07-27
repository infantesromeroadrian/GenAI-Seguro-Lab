# Riesgo residual y compensaciones

## Ficha del snapshot

| Campo | Valor |
|---|---|
| Identificador | `GSL-RESIDUAL-RISK-001` |
| Versión | `1.0.0` |
| Fecha de corte | 2026-07-27 |
| Candidato final | commit `77edd64037bb0e41edffa58cae2682ba7d2694d2`, árbol `bc09b78f7f3d85f94241f9955e79abb264bd89de` |
| Evaluador final | commit `636e1dbb8cac21c8c7bfc0709bf1d88b4b56304e` |
| Evidencia final | `DAT-25`, SHA-256 `05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d` |
| Priorización heredada | `GSL-RISK-PRIORITY-001` v2.4.0, corte 2026-07-26 |
| Estado de decisión | `PENDIENTE_HUMANA` para los seis riesgos |
| Alcance | sistema determinista local, corpus sintético y rúbrica cerrada fijados |

Este snapshot documenta el riesgo residual observado después de PGS-05-M07 y
las compensaciones que deben decidirse después. No recalcula `I`, `L`, `K`,
`S`, bandas o posiciones de la priorización heredada; no constituye un registro
formal de riesgos, no crea una RACI formal y no acepta ningún riesgo. Los
tratamientos y targets citados ya existen en el plan, pero su mención no
autoriza ejecución, cambia su owner ni adelanta PGS-06-M03.

## Rol de las fuentes

<!-- residual-risk-sources:start -->
| Fuente | Rol en este corte | Uso permitido |
|---|---|---|
| `DAT-25` | `FINAL` | Única observación final del candidato `77edd640` bajo el contrato cerrado de M07 |
| `DAT-24` | `CLOSED_RUBRIC` | Contrato pre-run para interpretar las 84 cláusulas cerradas; no es un resultado |
| `DAT-20` | `HISTORICAL_ONLY` | Comparación adversaria M02 derivada de las ejecuciones anteriores; no sustituye `DAT-25` |
| `DAT-21` | `HISTORICAL_ONLY` | Comparación benigna M03 anterior a la corrección y al retest final |
| `DAT-22` | `HISTORICAL_ONLY` | Comparación operativa `df13683` → `ba600ca`; no mide el candidato final |
| `DAT-23` | `HISTORICAL_ONLY` | Clasificación revisada M05 sobre `DAT-20/21/22`; no acepta riesgo ni declara el resultado final |
<!-- residual-risk-sources:end -->

Las cuatro fixtures `AC-DOS-01`, `AC-DOS-02`, `AC-DOS-03` y `AC-SC-01`
permanecen `INERT`, `OUTSIDE_DENOMINATOR` y con 0 ejecutadas. No se infiere de
su ausencia de ejecución que el control sea eficaz o que el riesgo esté
aceptado.

## Resultados finales que sí soporta DAT-25

- 14/14 casos adversarios completados: éxito observado 1/14 → 0/14,
  operaciones no autorizadas aceptadas o ejecutadas 1 → 0, 1 caso mejorado y
  0 regresiones.
- 12/12 casos benignos completados y 0/12 falsos rechazos.
- 24/24 hallazgos, 36/36 acciones recomendadas y 24/24 prohibiciones
  preservados bajo las reglas cerradas y predeclaradas de `DAT-24`.
- La presencia literal es 0/24 hallazgos y 0/36 acciones. El texto literal
  prohibido está presente en 0/24 cláusulas; su ausencia es el resultado
  deseable de esas reglas.
- `SC-07` está `DEMONSTRATED` solo para el candidato, corpus, hashes,
  invariantes y rúbrica cerrada fijados. `CF-002` permanece
  `NOT_COMPUTABLE`.

Estos recuentos no demuestran comprensión o equivalencia semántica general ni
comportamiento frente a ataques desconocidos.

## Registro de seis riesgos primarios

<!-- residual-risk-register:start -->
| ID y casos asignados | Amenaza y activo | Estado observado y rol de evidencia | Control actual | Exposición restante | Incertidumbre | Tratamiento propuesto | Target existente | Decisión o aceptación humana |
|---|---|---|---|---|---|---|---|---|
| `RR-01` — `AC-DOS-01` | Agotamiento repetido de recursos; disponibilidad del proceso y host local | `INERT`, `OUTSIDE_DENOMINATOR`, 0 ejecutadas; `DAT-25 FINAL` solo conserva la no ejecución | `CMP-10` aplica presupuestos, checkpoints y lock advisory a procesos CLI cooperantes | Una llamada Python puede omitir el lock; no hay cuota persistente, rate limit, cancelación síncrona ni aislamiento de SO | No se midieron concurrencia, carga sostenida, RSS bajo ataque ni recuperación tras agotamiento | Diseñar una ejecución DOS separada y autorizada con topes, parada y recuperación antes de valorar el residual | `PGS-06-M07`, `PGS-07-M02` | `PENDIENTE_HUMANA` — decidir si se autoriza la prueba y qué exposición se tolera |
| `RR-02` — `AC-DOS-02`, `AC-DOS-03` | Corpus corrupto o sobredimensionado; integridad del corpus y disponibilidad de carga | Ambas fixtures están `INERT`, `OUTSIDE_DENOMINATOR`, 0 ejecutadas; `DAT-25 FINAL` no las convierte en evidencia de eficacia | Esquemas estrictos, procedencia, hashes y límites preventivos de tamaño y registros con fallo cerrado | La autoridad de mantenimiento puede versionar datos, código o política incompatibles; el consumo bajo los casos no fue medido | No se probaron corrupciones independientes ni un corpus materializado al límite bajo el candidato final | Verificar procedencia y reconstrucción, y ejecutar solo copias temporales bajo una autorización que conserve límites y parada | `PGS-06-M08`, `PGS-07-M01`, `PGS-07-M02` | `PENDIENTE_HUMANA` — decidir condiciones de prueba y tolerancia a indisponibilidad local |
| `RR-03` — `AC-SC-01` | Compromiso de supply chain o abuso de autoridad de mantenimiento; código, dependencias, corpus y evidencia | `INERT`, `OUTSIDE_DENOMINATOR`, 0 ejecutadas; `DAT-25 FINAL` fija hashes, mientras `DAT-20/21/22/23` son `HISTORICAL_ONLY` | Git, `uv.lock`, manifiestos y SHA-256 permiten detectar drift en los artefactos cubiertos | No hay firma, CI, SBOM, política de release, separación de funciones ni revisión independiente humana | No se ha ejercitado un cambio malicioso o comprometido ni una recuperación de release | Registrar dependencias y riesgo de supply chain, reconstruir desde limpio y someter un cambio y una prueba a revisión independiente | `PGS-06-M08`, `PGS-07-M01`, `PGS-07-M04` | `PENDIENTE_HUMANA` — decidir requisitos de procedencia, revisión y aceptación antes de publicar otro artefacto |
| `RR-04` — `AC-TOL-05` | Aprobación sin presencia humana real; autoridad sobre la creación confinada de un borrador | `DAT-25 FINAL` observa mejora de `ADV-TOL-005`, rechazo y cero efecto no autorizado; `DAT-20/23` solo conservan el contexto histórico | Identidad sintética autenticada, challenge, binding de contexto, TTL y grant de un solo uso consumido antes de I/O | El flujo no prueba que una persona estuviera presente, comprendiera el contenido o controlara una interfaz | No se midieron error humano, fatiga de confirmación, accesibilidad ni flujo de autenticación real | Decidir si el laboratorio conserva la aprobación sintética o exige autenticador e interfaz con presencia humana antes de ampliar capacidades | `PGS-06-M02`, `PGS-06-M03`, `PGS-07-M04` | `PENDIENTE_HUMANA` — no hay aceptación de la aprobación sintética como equivalente humano |
| `RR-05` — `AC-TOL-03`, `AC-TOL-04` | Bypass del host local, replay o escape de filesystem; sandbox y archivos del usuario | `DAT-25 FINAL` completa ambos casos sin regresión observada bajo las variantes fijadas | Binding y consumo único, validación de ruta, descriptor no-follow, creación exclusiva `0600` y publicación/recuperación atómica | Todo comparte la cuenta macOS; procesos no cooperantes, otras rutas y condiciones desconocidas quedan fuera | No hay aislamiento de SO, prueba multiusuario ni campañas de carrera o filesystem distintas de las cerradas | Reconstruir y repetir las pruebas autorizadas, y documentar parada y recuperación antes de ampliar el efecto local | `PGS-06-M07`, `PGS-07-M01`, `PGS-07-M02` | `PENDIENTE_HUMANA` — decidir si el confinamiento lógico basta para el siguiente alcance |
| `RR-06` — `AC-PI-01`, `AC-PI-02`, `AC-PI-03`, `AC-JB-01`, `AC-JB-02`, `AC-EX-01`, `AC-EX-02`, `AC-EX-03`, `AC-TOL-01`, `AC-TOL-02` | Generalización no demostrada; límites de instrucciones, conocimiento, salida y autoridad de herramientas | `DAT-25 FINAL` completa las diez variantes dentro del denominador y conserva las reglas cerradas; `DAT-20/21/23` son `HISTORICAL_ONLY` | Dominios de confianza, sobres estrictos, allowlists, mínimo privilegio, política de salida, presupuestos y harness con oráculos separados | No existe prompt libre ni modelo real; otras formulaciones, idiomas, codificaciones, herramientas o ataques desconocidos no están cubiertos | No se evaluaron semántica general, juez LLM, proveedor real, entrada remota ni distribución adversaria distinta | Repetir la evaluación cuando cambien modelo o interfaz, reconstruir el corpus autorizado y obtener revisión independiente de una prueba | `PGS-06-M09`, `PGS-07-M02`, `PGS-07-M04`, `PGS-07-M06` | `PENDIENTE_HUMANA` — decidir el alcance adicional antes de afirmar robustez o ampliar el producto |
<!-- residual-risk-register:end -->

Los 17 abuse cases aparecen exactamente una vez en el registro anterior. Los
targets futuros son referencias al plan existente, no nuevos compromisos,
owners o decisiones.

## Compensaciones observables

### Seguridad y funcionalidad cerrada

La mejora adversaria final no introdujo falsos rechazos técnicos en los 12
casos benignos y preservó las 84 cláusulas cerradas. La compensación es que ese
resultado depende de un adaptador determinista, entradas enumeradas, reglas
predeclaradas y comparadores acotados. Mantener esa certeza reduce la superficie
medida, pero no informa cómo respondería un modelo real o una entrada libre.

### Coste operativo histórico

`DAT-22` es solo `HISTORICAL_ONLY`: midió `df13683` → `ba600ca`, no el candidato
`77edd640`. En 30 pares, un único host y una única sesión:

| Métrica | Mediana pre | Mediana post | Delta emparejado post − pre |
|---|---:|---:|---:|
| Pared | 189693584 ns | 259169250 ns | +67387688 ns |
| CPU total | 167383000 ns | 223382500 ns | +60542500 ns |
| RSS high-water | 36315136 B | 41172992 B | +4907008 B |

No existe umbral operacional, análisis de significación ni atribución de estos
deltas a `DAT-25`. Tampoco se midieron energía, TCO, concurrencia o carga
sostenida, por lo que M08 no califica estos cambios como aceptables.

## Límites de decisión

No se evaluaron un modelo GenAI real, prompt libre, equivalencia semántica
general, ataques desconocidos, producción, umbral operacional, significación,
energía, TCO, concurrencia o carga sostenida. Tampoco hay revisión humana
independiente ni registro formal de aceptación.

[`GSL-ADR-001`](./architecture-decision-record.md) conserva la decisión
arquitectónica, alternativas, triggers, consecuencias y rollback.
PGS-06-M03 conserva la creación de la RACI y el registro formal de riesgos.
Hasta una decisión humana explícita posterior, los seis riesgos permanecen
`PENDIENTE_HUMANA`; M08 únicamente documenta el corte.
