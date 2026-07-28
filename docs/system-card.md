# System card — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-SYSTEM-CARD-001` |
| Versión | `1.1.0` |
| Fecha de corte | 2026-07-28 |
| Estado | `DESCRIPTIVA_ALCANCE_ACTUAL` |
| Corte de las fuentes del repositorio | commit `a4ab56c3f706ae1073f9006b2f74e96d3c187b17` |
| Candidato de producto evaluado | commit `77edd64037bb0e41edffa58cae2682ba7d2694d2`, árbol `bc09b78f7f3d85f94241f9955e79abb264bd89de` |
| Evidencia final | `DAT-25`, SHA-256 `05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d` |
| Ámbito | Laboratorio local, determinista y con datos exclusivamente sintéticos |

Esta ficha resume el sistema observado. No sustituye el
[inventario](./system-inventory.md), el
[mapa C4](../architecture/manifest.json), la
[matriz de autoridad](./authority-matrix.md), el
[ADR](./architecture-decision-record.md) ni `DAT-25`. Tampoco constituye una
fuente canónica. Esta ficha no constituye una certificación, una aprobación de
producción, una declaración de conformidad o una aceptación de riesgo.

## Propósito y usuarios

GenAI Seguro Lab permite aprender y demostrar, de forma reproducible, cómo una
aplicación con herramientas separa contenido no confiable, autoridad,
controles y evaluación. El producto actual analiza incidentes ficticios desde
una CLI y compara comportamiento benigno y adversario sobre entradas
enumeradas.

| Actor | Relación actual con el sistema |
|---|---|
| `ACT-01` | Operador local que ejecuta `analyze` o `baseline` y recibe JSON por `stdout`; la aplicación no ofrece login propio. |
| `ACT-02` | Mantenedor y ejecutor de pruebas que modifica, valida y versiona el laboratorio mediante su autoridad de sistema operativo y GitHub. La RACI formal sigue pendiente de `PGS-06-M03`. |
| `ACT-03` | Llamador interno del flujo de borradores; usa una identidad sintética, no una presencia humana verificada. Este flujo no está expuesto por la CLI. |

## Usos previstos y prohibidos

Usos previstos:

- aprendizaje y demostración sobre el laboratorio propio;
- análisis de los 12 incidentes sintéticos incluidos;
- reproducción controlada de las evaluaciones documentadas, excepto el retest
  final único e inmutable;
- revisión de límites de autoridad, controles y riesgo residual.

Usos no previstos o prohibidos:

- tratar incidentes reales, datos personales, secretos o información
  corporativa;
- probar sistemas de terceros o producir efectos fuera del sandbox autorizado;
- usar el resultado para decisiones médicas, legales, laborales, financieras
  o de seguridad física;
- presentar el doble determinista como un LLM, agente autónomo o modelo
  desplegado;
- extrapolar `DAT-25` a ataques, idiomas, interfaces o distribuciones que no
  fueron evaluados;
- volver a ejecutar o regenerar `DAT-25`.

## Arquitectura y límites de confianza

El runtime observado es un solo proceso Python local. No hay proveedor,
conexión de red de runtime, servicio web, interfaz gráfica, base de datos,
vector store, cloud, Docker, cuenta de servicio ni telemetría externa. La
cuenta macOS que inicia el proceso conserva la autoridad efectiva del host.

<!-- system-boundaries:start -->
| Frontera | Función | Aislamiento observado |
|---|---|---|
| `TB-01` | Host local y cuenta del sistema operativo | Frontera efectiva de infraestructura; no existe aislamiento adicional del host. |
| `TB-02` | Control de aplicación | Separación lógica dentro del mismo proceso mediante esquemas, políticas y grants. |
| `TB-03` | Salida del modelo | La respuesta se trata como datos no confiables dentro del mismo proceso. |
| `TB-04` | Autoridad de herramientas | La aplicación, no el modelo, valida y concede una operación acotada. |
| `TB-05` | Sandbox de borradores | Almacén local create-only con transacción y recuperación; no es aislamiento de sistema operativo. |
| `TB-06` | Datos sintéticos versionados | Manifiestos, esquemas y hashes detectan deriva; la autoridad de mantenimiento aún puede cambiar el repositorio. |
<!-- system-boundaries:end -->

## Componentes y superficies

| Grupo | Elementos | Papel |
|---|---|---|
| Ruta de producto | `CMP-01`, `CMP-02`, `CMP-03`, `CMP-04`, `CMP-05`, `CMP-09`, `CMP-10`, `CMP-11`, `MOD-01`, `TOL-01` | CLI, carga validada, flujo benigno, baseline, políticas, eventos efímeros, doble determinista y consulta de conocimiento de solo lectura. |
| Efecto interno no expuesto | `TOL-02`, `CMP-12`, `IDN-03` | Propuesta, aprobación sintética y creación confinada de un borrador; no hay ruta desde `CMP-01`. |
| Evaluación y soporte | `CMP-06`, `CMP-07`, `CMP-08`, `CMP-13`, `CMP-14`, `CMP-15`, `CMP-16`, `CMP-17`, `CMP-18` | Perfil vulnerable, harness y analizadores separados de la ruta de producto. |
| Identidad efectiva | `IDN-01`, `IDN-04`, `IDN-05` | Cuenta local del proceso, ausencia de autoridad en el modelo y grants lógicos por operación. |

Flujo de producto:

1. `ACT-01` selecciona un incidente mediante `CMP-01`.
2. `CMP-10` acota el snapshot y `CMP-02` valida manifiesto, registros y hashes.
3. `CMP-03` entrega a `MOD-01` una petición con instrucción, datos de usuario y
   contenido no confiable separados.
4. La aplicación emite un grant de una sola `knowledge_search`; `TOL-01`
   consulta únicamente las referencias del incidente.
5. `CMP-03` valida la segunda respuesta, aplica `CMP-09`, registra solo eventos
   saneados en memoria mediante `CMP-11` y devuelve `DAT-05`.

El modelo no autentica, concede permisos, ejecuta herramientas ni produce por
sí mismo efectos. El flujo de borradores es una API interna distinta y su
identidad sintética no demuestra presencia humana.

## Datos, modelo y efectos

- La [data card](./data-card.md) documenta `DAT-01` a `DAT-25`: corpus,
  estado efímero y evidencia son sintéticos o derivados de ejecuciones
  sintéticas.
- La [model card](./model-card.md) documenta `MOD-01`: un
  `DeterministicModelAdapter` `deterministic/scripted-v1`, sin entrenamiento,
  pesos, proveedor ni llamadas externas.
- `TOL-01` solo lee un catálogo físico reducido al incidente.
- `TOL-02` puede crear como máximo un borrador Markdown local cuando recibe
  autoridad interna válida; la CLI y el flujo benigno no lo alcanzan.
- `DAT-14` es un informe opt-in derivado de un journal en memoria. No existe
  logging persistente; su política formal de conservación queda para
  `PGS-06-M05`.

## Controles y autoridad

La matriz `CTL-01` a `CTL-13` de
[responsabilidades y controles](./control-responsibility-mapping.md) es la
fuente canónica de estado, owner técnico, pruebas y limitaciones. Esta ficha no
reclasifica controles parciales como completos ni atribuye conformidad con
NIST, OWASP, MITRE o ISO.

La autoridad de mantenimiento y del host queda fuera del modelo. Los grants de
aplicación reducen el efecto de operaciones cooperantes, pero no contienen a
un proceso con ejecución arbitraria de Python bajo `IDN-01`.

## Evidencia y comportamiento observado

`DAT-25` fijó un único retest canónico del candidato `77edd640`:

- 14/14 casos adversarios completados; éxito observado 1/14 a 0/14,
  operaciones no autorizadas aceptadas o ejecutadas 1 a 0, un caso mejorado y
  cero regresiones;
- 12/12 casos benignos completados, cero falsos rechazos, 24/24 hallazgos,
  36/36 acciones y 24/24 prohibiciones preservados bajo una rúbrica cerrada;
- cero llamadas de red o proveedor, cero reintentos y cero escrituras de
  evidencia por el runner;
- cuatro fixtures de disponibilidad y supply chain no ejecutadas.

Estos resultados pertenecen al candidato, corpus, oráculos e invariantes
fijados. No demuestran equivalencia semántica general, robustez frente a
ataques desconocidos, comportamiento de un LLM real ni adecuación para
producción.

## Riesgos y decisiones pendientes

| Riesgo | Estado que conserva esta ficha |
|---|---|
| `RR-01` | `PENDIENTE_HUMANA`: disponibilidad ante agotamiento repetido no probada. |
| `RR-02` | `PENDIENTE_HUMANA`: corpus corrupto o al límite no ejercitado. |
| `RR-03` | `PENDIENTE_HUMANA`: supply chain y autoridad de mantenimiento sin prueba adversaria. |
| `RR-04` | `PENDIENTE_HUMANA`: aprobación sintética sin presencia humana real. |
| `RR-05` | `PENDIENTE_HUMANA`: confinamiento lógico bajo una sola cuenta del host. |
| `RR-06` | `PENDIENTE_HUMANA`: generalización a modelo, entrada o ataques distintos no demostrada. |

La fuente completa es
[`GSL-RESIDUAL-RISK-001`](./residual-risk-and-tradeoffs.md). Ningún riesgo está
aceptado por esta ficha.

## Operación, cambios y revisión

Revisar esta ficha si cambia cualquiera de estos elementos:

- modelo, proveedor, prompt libre, interfaz, usuario o autenticación;
- herramienta, efecto, principal, grant o límite de sandbox;
- corpus, manifiesto, procedencia, sensibilidad o esquema;
- dependencia, runtime, red, almacenamiento o despliegue;
- control, resultado de evaluación, riesgo residual o decisión
  arquitectónica.

La [evaluación de impacto `GSL-AIA-001`](./ai-impact-assessment.md) completa
`PGS-06-M02` para el alcance actual sin autorizar una ampliación ni aceptar
riesgo. Todavía no existen la RACI y el registro formal de riesgos
(`PGS-06-M03`), el mapa de cumplimiento (`PGS-06-M04`) ni la política completa
de cambios de modelo y reevaluación (`PGS-06-M09`).
