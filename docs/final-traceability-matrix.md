# Matriz final de trazabilidad

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-FINAL-TRACEABILITY-001` |
| Microtarea | `PGS-07-M06` |
| Fecha de corte | 2026-07-28 |
| Requisitos fuente | [README — requisitos mínimos](../README.md#requisitos-mínimos) y [criterios de éxito](../README.md#criterios-de-éxito) |
| Retest final | `DAT-25`, candidato `77edd640`, SHA-256 `05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d` |
| Cierre técnico posterior | `GSL-CLEAN-REBUILD-001`, `GSL-CLOSURE-EXECUTION-001` y `GSL-CONTENT-SCAN-001` |
| Estado | `COMPLETE_WITH_DECLARED_GAPS` |

## Estados

| Estado | Significado |
|---|---|
| `DEMONSTRATED` | La evidencia citada satisface el requisito en su alcance declarado. |
| `DEMONSTRATED_BOUNDED` | El resultado satisface el requisito solo para el candidato, datos, host o contrato fijados. |
| `PARTIAL` | Existe evidencia positiva, pero una parte material del requisito continúa abierta. |
| `NOT_DEMONSTRATED` | Falta la evidencia exigida; no se sustituye por una inferencia. |

## Requisito, evidencia, resultado y límite

<!-- final-traceability:start -->
| ID | Versión y prueba | Resultado | Control y riesgo | Límite conservado |
|---|---|---|---|---|
| `RF-01` | Producto `77edd640`; [`DAT-25`](../evaluations/final-retest-v1.json) y [`test_benign_flow.py`](../tests/test_benign_flow.py) | `DEMONSTRATED_BOUNDED`: 12/12 incidentes sintéticos terminaron y 84/84 cláusulas de la rúbrica se preservaron | `CTL-04`, `CTL-09`; `RR-06` | Doble determinista y rúbrica cerrada; no demuestra calidad semántica general ni un modelo real |
| `RF-02` | Producto `77edd640`; [`test_local_tools.py`](../tests/test_local_tools.py) y [`DAT-25`](../evaluations/final-retest-v1.json) | `DEMONSTRATED_BOUNDED`: cada caso usa una vista exacta del conocimiento autorizado y una búsqueda | `CTL-03`, `CTL-06`; `RR-06` | Catálogo local sintético; no cubre RAG remoto, embeddings o fuentes dinámicas |
| `RF-03` | Producto `77edd640`; [`test_local_tools.py`](../tests/test_local_tools.py) y [política de sandbox](./sandbox-recovery-policy.md) | `DEMONSTRATED_BOUNDED`: el efecto create-only queda confinado al sandbox y ligado a un grant de un solo uso | `CTL-07`, `CTL-08`; `RR-04`, `RR-05` | API interna, misma cuenta del host y sin aislamiento de sistema operativo |
| `RF-04` | Producto `77edd640`; [`test_local_tools.py`](../tests/test_local_tools.py) y [mínimo privilegio](./least-privilege-policy.md) | `PARTIAL`: toda creación exige aprobación sintética autenticada, ligada y efímera | `CTL-07`; `RR-04` | No acredita presencia, comprensión o identidad de una persona real |
| `RS-01` | Baseline `93aefa45`; [evidencia adversaria](../evaluations/adversarial-baseline-v1/README.md) | `DEMONSTRATED`: `ADV-TOL-005` produjo el residual de efecto no autorizado fijado | `CTL-12`; `RR-04` | Fallo sintético de una variante conocida; no representa todas las amenazas |
| `RS-02` | Baseline `93aefa45` y retest `77edd640`; [`DAT-25`](../evaluations/final-retest-v1.json) | `DEMONSTRATED`: las 14 entradas ejecutadas y sus fuentes permanecen fijadas por hash | `CTL-03`, `CTL-12`; `RR-06` | Los cuatro casos DOS/SC permanecen inertes y fuera de la comparación ejecutada |
| `RS-03` | Producto `77edd640`; [`DAT-25`](../evaluations/final-retest-v1.json) | `DEMONSTRATED_BOUNDED`: 0 operaciones no autorizadas aceptadas o ejecutadas en los 14 casos | `CTL-05` a `CTL-09`, `CTL-12`; `RR-04` a `RR-06` | Solo variantes PI/JB/EX/TOL autorizadas; no hay robustez general |
| `RS-04` | Cierre `7f007a9`; [`GSL-CONTENT-SCAN-001`](../evaluations/content-scan-v1.json) | `DEMONSTRATED_BOUNDED`: 0 hallazgos Gitleaks, 56/56 registros sintéticos y 0 marcadores en 32 eventos | `CTL-03`, `CTL-09`, `CTL-11`; `RR-03` | Escaneo finito, no DLP universal; Git conserva procedencia personal histórica declarada |
| `RS-05` | Producto `77edd640`; [`test_evaluation_profile.py`](../tests/test_evaluation_profile.py) | `DEMONSTRATED`: el perfil vulnerable no tiene ruta CLI, llamadas, herramientas, red o efectos | `CTL-02`, `CTL-12`; `RR-06` | Cambiar el punto de entrada o el perfil exige reevaluación |
| `RS-06` | Producto `77edd640`; [`test_resource_control.py`](../tests/test_resource_control.py) | `DEMONSTRATED_BOUNDED`: los límites se aplican por defecto y fallan cerrado en las rutas probadas | `CTL-10`; `RR-01`, `RR-02` | Tiempo y lock cooperativos; sin cancelación síncrona, cuota persistente o aislamiento de SO |
| `RO-01` | Cierre `93d9a05`; [`GSL-CLEAN-REBUILD-001`](../evaluations/clean-rebuild-v1.json) | `DEMONSTRATED_BOUNDED`: clon público nuevo, `uv sync --frozen`, lock y smoke terminaron correctamente | `CTL-11`, `CTL-12`; `RR-02`, `RR-03` | Descargó repositorio y paquetes por red; no es una reconstrucción hermética |
| `RO-02` | Corte documental `e7509cc`; esta matriz y [mapa de controles](./control-responsibility-mapping.md) | `DEMONSTRATED`: los claims de cierre remiten a requisitos, versiones, pruebas, resultados, controles, riesgos y límites | `CTL-01`, `CTL-02`, `CTL-12`; `RR-01` a `RR-06` | Trazabilidad documental no equivale a eficacia, certificación o aceptación de riesgo |
| `SC-01` | Cierre `93d9a05`; [`GSL-CLEAN-REBUILD-001`](../evaluations/clean-rebuild-v1.json) | `DEMONSTRATED_BOUNDED`: Python 3.12, lock congelado, diez distribuciones y smoke sin pasos manuales ocultos | `CTL-11`; `RR-02`, `RR-03` | Un host Darwin arm64 y uso de red; no demuestra portabilidad universal |
| `SC-02` | Cierre `6d4f132`; [`GSL-CLOSURE-EXECUTION-001`](../evaluations/closure-execution-v1.json) | `DEMONSTRATED_BOUNDED`: 327/327 pruebas del candidato fijado terminaron sin fallos | `CTL-12`; `RR-01` a `RR-06` | Resultado de un commit, host y sesión; pruebas posteriores no amplían la semántica cubierta |
| `SC-03` | Corpus `GSL-DATASET-001` y `GSL-ADVERSARIAL-CORPUS-001`; [contrato](../tests/test_adversarial_corpus.py) | `DEMONSTRATED`: 12 casos benignos y 18 adversarios de seis familias | `CTL-03`, `CTL-12`; `RR-01` a `RR-03`, `RR-06` | Solo 14 adversarios están conectados; tres DOS y uno de supply chain siguen inertes |
| `SC-04` | Baseline `93aefa45`; [resultados](../evaluations/adversarial-baseline-v1/results.json) | `DEMONSTRATED`: el residual `ADV-TOL-005` alcanzó un efecto create-only no autorizado | `CTL-07`, `CTL-12`; `RR-04` | Un fallo fijado y sintético; no es una estimación de incidencia real |
| `SC-05` | Producto `77edd640`; [`DAT-25`](../evaluations/final-retest-v1.json) | `DEMONSTRATED_BOUNDED`: 14/14 casos terminaron con 0 efectos o llamadas no autorizados | `CTL-05` a `CTL-12`; `RR-04` a `RR-06` | Los cuatro casos DOS/SC no se ejecutaron y no se evaluó un LLM real |
| `SC-06` | Baseline `93aefa45`, retest `77edd640`; [`DAT-25`](../evaluations/final-retest-v1.json) | `DEMONSTRATED_BOUNDED`: mismo corpus, éxito 1/14 → 0/14 y bypass histórico documentado | `CTL-03`, `CTL-12`; `RR-06` | Comparación cerrada de variantes conocidas, no robustez ante ataques desconocidos |
| `SC-07` | Producto `77edd640`; [`DAT-24`](../evaluations/final-retest-rubric-v1.json) y [`DAT-25`](../evaluations/final-retest-v1.json) | `DEMONSTRATED_BOUNDED`: 12/12 casos preservan resultado esperado y 0/12 son falsos rechazos | `CTL-04`, `CTL-09`, `CTL-12`; `RR-06` | 84 cláusulas predeclaradas; no hay juez LLM ni equivalencia semántica general |
| `SC-08` | Producto `77edd640`; [`test_evaluation_profile.py`](../tests/test_evaluation_profile.py) | `DEMONSTRATED`: el perfil vulnerable permanece interno, desactivado y ausente de la CLI | `CTL-02`, `CTL-12`; `RR-06` | Un cambio de interfaz o importación invalida esta conclusión |
| `SC-09` | Cierre `7f007a9`; [`GSL-CONTENT-SCAN-001`](../evaluations/content-scan-v1.json) | `PARTIAL`: árbol actual, eventos y corpus pasan; el historial conserva metadatos personales de procedencia declarados | `CTL-03`, `CTL-09`, `CTL-11`; `RR-03` | No hubo reescritura destructiva y cero matches no garantiza ausencia universal |
| `SC-10` | Producto pre/post fijado; [`GSL-OP-METRICS-001`](../evaluations/operational-metrics-v1.json) | `DEMONSTRATED_BOUNDED`: 30 pares miden pared, CPU, RSS, consumo y complejidad; coste externo 0 | `CTL-10`, `CTL-12`; `RR-01`, `RR-02` | Un host y sesión; sin energía, TCO, carga sostenida, umbral o significación |
| `SC-11` | Producto determinista; [`DAT-25`](../evaluations/final-retest-v1.json) y [métricas operativas](../evaluations/operational-metrics-v1.json) | `DEMONSTRATED_BOUNDED`: 0 llamadas externas y 0 €; no se hizo una prueba con proveedor real | `CTL-10`, `CTL-12`; `RR-06` | El tope de 5 € nunca autorizó gasto y no existe evidencia de un modelo real |
| `SC-12` | [`GSL-REV-OMISSION-001`](./independent-review-omission.md) y [`D-REV-01`](./independent-review-disposition.md) | `NOT_DEMONSTRATED`: no hubo persona revisora ni reproducción independiente benigna y adversaria | `CTL-11`, `CTL-12`; `RR-03`, `RR-04`, `RR-06` | M04 fue omitida; no se sustituye por tests, agentes o autoevaluación |
| `SC-13` | Esta matriz `GSL-FINAL-TRACEABILITY-001` | `DEMONSTRATED`: las 25 filas conservan requisito, versión, prueba, resultado, control, riesgo y límite | `CTL-01`, `CTL-02`, `CTL-12`; `RR-01` a `RR-06` | La matriz recopila evidencia; no certifica el sistema ni acepta riesgos |
<!-- final-traceability:end -->

## Resultado agregado

- `DEMONSTRATED`: 8 requisitos.
- `DEMONSTRATED_BOUNDED`: 14 requisitos.
- `PARTIAL`: 2 requisitos.
- `NOT_DEMONSTRATED`: 1 requisito (`SC-12`).
- Cuatro fixtures (`ADV-DOS-001` a `003` y `ADV-SC-001`) continúan inertes y
  no se presentan como ejecutadas.
- `D-REV-01` permanece abierta y `REV-01` no tiene persona asignada.
- `RR-01` a `RR-06` permanecen `ABIERTO` y sus decisiones
  `PENDIENTE_HUMANA`.

Esta matriz no demuestra conformidad legal integral, certificación, seguridad
universal, robustez semántica, preparación para producción o aceptación de
riesgo.
