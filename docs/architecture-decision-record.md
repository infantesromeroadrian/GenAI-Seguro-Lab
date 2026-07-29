# ADR — Baseline local-first determinista y autoridad fuera del modelo

## Ficha de la decisión

| Campo | Valor |
|---|---|
| Identificador | `GSL-ADR-001` |
| Versión | `1.0.0` |
| Estado | `ACEPTADA_ALCANCE_ACTUAL` |
| Fecha | 2026-07-28 |
| Checkout de referencia | commit `24626fbf3f4a70765cac1353252168f3a8ad4607` |
| Evidencia final | `DAT-25`, SHA-256 `05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d` |
| Candidato y evaluador medidos | candidato `77edd64037bb0e41edffa58cae2682ba7d2694d2`; evaluador `636e1dbb8cac21c8c7bfc0709bf1d88b4b56304e` |
| Sustituye | ninguna decisión anterior |
| Sustituida por | ninguna |

`ACEPTADA_ALCANCE_ACTUAL` significa que esta arquitectura se mantiene como
baseline del laboratorio que existe hoy. No significa que sea la arquitectura
final, que esté preparada para producción o que se hayan aceptado los seis
riesgos de [`GSL-RESIDUAL-RISK-001`](./residual-risk-and-tradeoffs.md).

## Contexto

El laboratorio necesita producir evidencia reproducible sobre controles de
prompt injection, jailbreak, divulgación y abuso de herramientas sin enviar
datos a terceros ni convertir el propio evaluador en parte del producto.
También debe conservar la utilidad benigna, limitar los efectos al sandbox y
mantener visibles los fallos, gaps y resultados negativos.

El checkout observado tiene una única CLI local, un proceso Python y un único
adaptador activo `deterministic/scripted-v1`. No hay modelo GenAI real,
listener, proveedor, red de runtime, Docker, cloud, identidad de servicio o
autenticación humana. `TB-02`, `TB-03` y `TB-04` son límites lógicos bajo la
misma cuenta macOS `IDN-01`, no aislamiento de sistema operativo.

Las fuerzas de la decisión son:

- reproducibilidad y trazabilidad entre candidato, prueba, resultado y límite;
- autoridad de herramientas separada de contenido y salida del modelo;
- corpus sintético, coste externo cero y mínima superficie de runtime;
- separación entre producto, perfil vulnerable, harness, oráculos y rúbrica;
- reversibilidad antes de incorporar interfaces, modelos o efectos nuevos;
- fidelidad limitada frente al comportamiento probabilístico de un modelo real.

## Decisión

Mantener la ruta canónica local, determinista y sin red como baseline revisable
del alcance actual. La aplicación conserva la propiedad de validación,
políticas, grants y ejecución de herramientas; la salida del modelo es siempre
un dato no confiable. El harness y toda la información evaluadora permanecen
fuera de la ruta de producto.

La decisión mantiene como opciones reversibles el doble determinista, la CLI
local y el proceso único. No selecciona ahora proveedor, modelo real, Docker,
UI, API, autenticador, servicio, contenedor o framework de agentes.

## Invariantes

<!-- adr-invariants:start -->
| ID | Invariante | Evidencia o límite actual |
|---|---|---|
| `ADR-INV-01` | La salida del modelo no crea identidad, grant, permiso o efecto | `MOD-01` solo devuelve datos tipados; `CMP-03` conserva la autoridad |
| `ADR-INV-02` | El catálogo anunciado informa capacidades, pero no concede autoridad ejecutable | `IDN-05` liga principal, scope, herramienta e instancia |
| `ADR-INV-03` | Entrada, salida y efectos fallan cerrado dentro de cada contrato explícito | `CMP-02`, `CMP-09`, `CMP-10` y `CMP-12`; no es una garantía global |
| `ADR-INV-04` | La ruta expuesta autoriza una única búsqueda confinada por incidente | `CMP-03` y `TOL-01`; `TOL-02` permanece interna |
| `ADR-INV-05` | Un efecto local exige propuesta saneada, aprobación sintética ligada y creación exclusiva | `TOL-02`, `IDN-03` y `CMP-12`; no acredita presencia humana real |
| `ADR-INV-06` | Perfil vulnerable, harness y evaluadores no son rutas de producto | `CMP-06`, `CMP-07`, `CMP-08` y `CMP-13` a `CMP-18` son soporte interno |
| `ADR-INV-07` | Oráculos, `expected_result` y `DAT-24` no entran en la petición o salida del target | Los probes cubren `expected_result`; la provenance de `DAT-25` declara `adversarial_oracles_delivered_to_target_case:false` y `rubric_delivered_to_target:false` |
| `ADR-INV-08` | La evidencia publicada es inmutable y una evaluación nueva usa otro ID y artefacto | Baseline histórica, `DAT-20` a `DAT-25` y Git |
| `ADR-INV-09` | Un cambio de modelo, interfaz, herramienta, identidad o runtime exige revisar alcance y threat model | Rules of Engagement y triggers de riesgo |
| `ADR-INV-10` | Ningún resultado se generaliza a semántica, ataques desconocidos, producción o un LLM real | Límites expresos de `DAT-25` y M08 |
<!-- adr-invariants:end -->

## Alcance medido

`DAT-25` sostiene únicamente que, para el candidato, corpus y rúbrica fijados:

- los 14 casos adversarios conectados terminaron y el éxito observado pasó de
  1/14 a 0/14, con una operación no autorizada observada antes y cero después;
- los 12 casos benignos terminaron sin falsos rechazos y conservaron las 84
  cláusulas cerradas;
- los oráculos y la rúbrica permanecieron fuera del target, sin red,
  credenciales, reintentos o escrituras automáticas de evidencia.

Los cuatro casos DOS/SC siguen inertes, `CF-002` no es computable y no se
evaluaron equivalencia semántica general, prompt libre, modelo real,
aislamiento de SO, presencia humana, concurrencia o carga sostenida. `DAT-22`
es una referencia histórica y no mide el rendimiento del candidato final.

## Alternativas consideradas

Los calificadores son comparativos para este alcance, no benchmarks ni
garantías universales.

<!-- adr-alternatives:start -->
| ID | Alternativa | Estado | Reproducibilidad | Superficie y autoridad | Seguridad y utilidad | Fidelidad GenAI | Coste y operación | Reversibilidad | Razón o trigger |
|---|---|---|---|---|---|---|---|---|---|
| `ADR-ALT-01` | Prompt o guardrail propiedad del modelo como único control | `RECHAZADA_ALCANCE_ACTUAL` | Menor por deriva de modelo | Mezcla contenido y control; no confina efectos | Control insuficiente para autoridad; utilidad no medida con modelo real | Depende del modelo | Baja al inicio, alta al investigar fallos | Media | Puede orientar comportamiento, pero nunca sustituye grants y validación de aplicación |
| `ADR-ALT-02` | Modelo real local y opt-in, incluido un posible Model Runner | `DIFERIDA_POR_TRIGGER` | Media; exige modelo y parámetros fijados | Añade proceso, endpoint y supply chain local | Permite medir semántica; controles y utilidad aún no demostrados | Mayor | Cómputo, almacenamiento y mantenimiento | Media-alta si nace desactivado | Solo si `RR-06` exige evidencia probabilística que el doble no puede producir |
| `ADR-ALT-03` | Proveedor o modelo alojado | `RECHAZADA_ALCANCE_ACTUAL` | Menor por versión y servicio externos | Añade red, credenciales, cuenta y salida de datos | Mayor realismo; introduce privacidad, deriva y dependencia | Mayor | Coste, disponibilidad, privacidad y dependencia | Media-baja | Requiere nueva autoridad, presupuesto, datos aprobados y ADR sucesor |
| `ADR-ALT-04` | UI, API o usuario remoto | `DIFERIDA_POR_TRIGGER` | Media | Añade listener, autenticación, concurrencia y entradas libres | Permite medir interacción; amplía ataque y no acredita presencia por sí sola | No mejora por sí sola | Operación y gobierno altos | Media | Solo ante una necesidad de usuario verificable y un autenticador real |
| `ADR-ALT-05` | Integrar perfil vulnerable, harness, rúbrica u oráculos en producto | `RECHAZADA_ESTRUCTURAL` | Contamina la evidencia | Expone conocimiento evaluador y rutas débiles | Debilita seguridad y contamina la evidencia de utilidad | Distorsionada | Complejidad sin valor defensivo | Baja | Viola `ADR-INV-06` y `ADR-INV-07` |
| `ADR-ALT-06` | Aislamiento por proceso, contenedor o servicio | `DIFERIDA_POR_TRIGGER` | Puede conservarse con build fijado | Añade IPC o API y supply chain; puede reducir autoridad de host | Puede contener impacto; no mejora semántica o utilidad por sí solo | Sin cambio por sí solo | Medio-alto | Media | Revisar si aparecen carga, efectos mayores, usuario remoto o requisito de contención |
| `ADR-ALT-07` | Framework de agentes o guardrails como nuevo owner de capacidades | `RECHAZADA_ALCANCE_ACTUAL` | Depende del framework | Puede duplicar dispatcher, política y autoridad | Puede aportar cobertura; arriesga duplicación y regresión de utilidad | Potencialmente mayor | Dependencias y operación adicionales | Media | Solo reconsiderar ante un gap concreto sin duplicar controles existentes |
<!-- adr-alternatives:end -->

## Consecuencias

### Positivas

- Evidencia altamente reproducible, saneada y enlazada a candidatos exactos.
- Superficie de runtime pequeña, sin secretos o llamadas externas.
- Separación explícita entre propuesta del modelo, autorización y efecto.
- Cambios futuros pueden nacer desactivados y compararse contra esta baseline.

### Negativas y deuda

- Baja fidelidad respecto a un modelo probabilístico, prompt libre o proveedor.
- Límites lógicos bajo `IDN-01`, sin contención de código hostil del mismo
  usuario.
- Aprobación sintética sin presencia humana real y borrador desconectado de la
  CLI.
- Política de salida léxica, journal efímero y límites cooperativos.
- Los riesgos `RR-01` a `RR-06` siguen `PENDIENTE_HUMANA`; este ADR no los
  acepta ni los puntúa.

## Triggers de revisión

Los triggers abren una decisión y autorización nuevas; no ejecutan ni aprueban
el cambio por sí mismos.

<!-- adr-triggers:start -->
| ID | Trigger | Revisión mínima previa |
|---|---|---|
| `ADR-TRG-01` | Necesidad de medir semántica o comportamiento probabilístico | Modelo, parámetros, corpus, umbrales y presupuesto fijados |
| `ADR-TRG-02` | Nueva UI, API, listener, usuario remoto o autenticador | Threat model, identidad, concurrencia, privacidad y presencia humana |
| `ADR-TRG-03` | Nueva herramienta, efecto, dato, secreto o scope | Matriz de autoridad, mínimo privilegio, RoE y tests |
| `ADR-TRG-04` | Proveedor, red, cloud, contenedor, servicio o identidad de runtime | Trust boundaries, supply chain, egress, coste y observabilidad |
| `ADR-TRG-05` | Evaluación DOS, carga sostenida o requisito de aislamiento | Topes, parada, recuperación, entorno reproducible y autorización |
| `ADR-TRG-06` | Regresión, bypass, fuga, deriva de hashes o pérdida de reproducibilidad | Contención, evidencia nueva y decisión de corrección separada |
| `ADR-TRG-07` | Umbral de utilidad u operación previamente aprobado e incumplido | Medición comparable del candidato afectado y responsable de rollback |
<!-- adr-triggers:end -->

## Rollback

El rollback arquitectónico no es `CMP-12.stop()`, no es una señal de
`CMP-11` y no elimina un efecto externo ya ocurrido.

<!-- adr-rollback:start -->
1. Detener la nueva exposición y bloquear nuevas entradas o llamadas del
   componente afectado mediante su mecanismo operativo autorizado.
2. Desactivar adaptador, listener, herramienta o integración futura y volver a
   la CLI determinista sin red. Revocar las credenciales introducidas y dejar
   inerte cualquier capacidad cuya retirada inmediata no sea segura.
3. Publicar un commit compensatorio o una reversión selectiva revisada. No
   reescribir la rama pública ni borrar commits para ocultar el cambio.
4. Verificar desde un checkout limpio la suite ordinaria y las pruebas focales,
   los invariantes `ADR-INV-01` a `ADR-INV-10`, Tecture y el hash de `DAT-25`,
   sin reejecutar su runner canónico.
5. Registrar el fallo y el rollback como evidencia nueva con otro identificador.
   `DAT-24`, `DAT-25`, la baseline histórica y los resultados negativos no se
   modifican, regeneran o presentan como restaurados.
6. Crear un ADR sucesor, marcar éste como `SUSTITUIDA` mediante un commit
   posterior y actualizar inventario, RoE, autoridad, riesgos y arquitectura
   al estado real.
7. Si hubo fuga, gasto o efecto externo, reconocer que la reversión no lo
   deshace y aplicar el runbook de incidente que corresponda cuando exista.
<!-- adr-rollback:end -->

## Revisión y supersesión

Este ADR se revisa ante cualquier `ADR-TRG-*` o evidencia que contradiga sus
hechos. [`GSL-MODEL-CHANGE-001`](./model-change-reevaluation-policy.md)
completa PGS-06-M09 y asigna paquetes de evaluación a esos triggers. Una
revisión sin cambio conserva `ACEPTADA_ALCANCE_ACTUAL`. Una decisión distinta
requiere un ADR sucesor y no autoriza automáticamente implementación, gasto,
despliegue o aceptación de riesgo.

## Relación con Tecture

El ADR documenta componentes, relaciones y límites ya presentes en
`architecture/manifest.json`; no añade servicio, interfaz, almacén,
integración, despliegue o trust boundary. Por ello M09 no modifica el mapa. Un
trigger materializado sí exige actualizar únicamente el área afectada.

## Fuentes

- [`GSL-SYS-INV-001`](./system-inventory.md)
- [`GSL-AUTH-MATRIX-001`](./authority-matrix.md)
- [`GSL-ROE-001`](./rules-of-engagement.md)
- [`GSL-RESIDUAL-RISK-001`](./residual-risk-and-tradeoffs.md)
- [`DAT-25`](../evaluations/final-retest-v1.json)
- [Mapa Tecture](../architecture/manifest.json)
- [Plan del proyecto](../plan-proyecto-GenAI-Seguro-Lab.md)

## Extensión posterior

[`GSL-ADR-002`](./ollama-cloud-adr.md) acepta de forma experimental el backend
Ollama opt-in después de `DAT-25`. No reescribe esta decisión ni cambia el
estado histórico de sus alternativas: conserva `MOD-01` como default y único
backend de baseline/evaluaciones, mientras limita `MOD-02` a un incidente
sintético, dos llamadas, una herramienta local y transporte falso en tests.
