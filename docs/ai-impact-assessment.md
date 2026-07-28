# Evaluación de impacto de IA — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-AIA-001` |
| Versión | `1.1.0` |
| Fecha | 2026-07-28 |
| Estado de la evaluación | `COMPLETADA_ALCANCE_ACTUAL` |
| Decisión que habilita | `CONTINUAR_SOLO_LABORATORIO_ACTUAL` |
| Límite de autoridad | `NO_AUTORIZA_AMPLIACION` |
| Corte de las fuentes | commit `648dd9afe9ef696388257ebf8dda4b59ece1aeb5` |
| Candidato de producto evaluado | commit `77edd64037bb0e41edffa58cae2682ba7d2694d2` |
| Evaluador de `DAT-25` | commit `636e1dbb8cac21c8c7bfc0709bf1d88b4b56304e` |
| Evidencia final | `DAT-25`, SHA-256 `05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d` |

Esta evaluación responde a `PGS-06-M02` y examina el sistema completo que
existe hoy. `MOD-01` forma parte de ese sistema, pero es un doble determinista:
no es un modelo de machine learning ni un modelo GenAI real. El documento no
es una evaluación jurídica, una DPIA, una clasificación bajo una regulación,
un mapa de cumplimiento, una aprobación de producción ni una aceptación de
riesgo.

## Decisión y jerarquía de fuentes

La decisión habilitada es continuar aprendiendo, desarrollando y verificando el
laboratorio dentro de su alcance local, sintético, determinista y sin red. No
habilita datos reales, usuarios externos, prompt libre, un modelo real, una
interfaz remota, nuevos efectos ni un despliegue.

En caso de discrepancia, prevalecen las fuentes especializadas:

1. [inventario del sistema](./system-inventory.md) y
   [mapa C4](../architecture/manifest.json) para el sistema observado;
2. [matriz de autoridad](./authority-matrix.md) para principales, permisos y
   consecuencias;
3. [system card](./system-card.md), [data card](./data-card.md) y
   [model card](./model-card.md) para las vistas descriptivas;
4. [matriz de controles](./control-responsibility-mapping.md) para el estado y
   las limitaciones de `CTL-01` a `CTL-13`;
5. [riesgo residual](./residual-risk-and-tradeoffs.md) para `RR-01` a `RR-06`;
6. [ADR](./architecture-decision-record.md) para la baseline vigente y sus
   triggers;
7. `DAT-25` para el único retest final, sin volver a ejecutar su runner.

## Cribado del alcance actual

Las clasificaciones de esta evaluación no son puntuaciones de riesgo:

- `NO_APLICA_ALCANCE_ACTUAL`: no existe hoy la parte afectada, decisión o ruta;
- `ACOTADO_ALCANCE_ACTUAL`: existe exposición, pero está limitada por el
  alcance y las salvaguardas documentadas;
- `NO_DEMOSTRADO`: falta evidencia para sostener la propiedad;
- `POTENCIAL_SI_AMPLIA`: el impacto no está materializado hoy, pero debe
  evaluarse antes de activar el trigger indicado.

<!-- aia-screening:start -->
| Pregunta | Respuesta observada | Consecuencia para esta evaluación |
|---|---|---|
| ¿Qué capacidad se evalúa? | CLI local para analizar 12 incidentes ficticios con `MOD-01` `deterministic/scripted-v1` | Se evalúa el sistema socio-técnico del laboratorio, no se presume una capacidad de IA aprendida |
| ¿Quién lo usa hoy? | `ACT-01` opera la CLI; `ACT-02` mantiene y prueba; `ACT-03` representa un principal sintético en un flujo interno | Son las únicas partes directamente relacionadas con el alcance actual |
| ¿Hay usuarios externos o público afectado? | No | Cualquier incorporación exige reevaluación previa |
| ¿Toma decisiones automatizadas sobre personas? | No | No se permite usar sus salidas para decisiones médicas, legales, laborales, financieras o de seguridad física |
| ¿Usa datos personales, reales, secretos o corporativos? | No; `DAT-01` a `DAT-25` son sintéticos o derivados de ejecuciones sintéticas | Los datos reales están fuera de alcance, no implícitamente autorizados |
| ¿Entrena o ajusta un modelo? | No hay entrenamiento, fine-tuning, pesos ni parámetros aprendidos | No se evalúan impactos propios de un dataset de entrenamiento real |
| ¿Expone prompt libre, UI, API o listener? | No | La entrada está enumerada y la salida se entrega como JSON por `stdout` |
| ¿Realiza efectos externos? | No | La ruta expuesta solo consulta conocimiento local; `TOL-02` es interno y create-only |
| ¿Existe presencia humana verificada? | No | `IDN-03` es una identidad sintética y no equivale a una persona presente |
| ¿Hay red, proveedor, cloud, base de datos o telemetría externa? | No | No se extrapolan garantías a una arquitectura distribuida o alojada |
| ¿Cuál es el efecto máximo actual? | Lectura local confinada en producto y creación interna de un borrador ficticio en sandbox | El host y la cuenta macOS siguen siendo la frontera efectiva |
| ¿Se ha realizado una clasificación jurídica o regulatoria? | No | Corresponde a `PGS-06-M04` distinguir obligación, guía y decisión voluntaria |
<!-- aia-screening:end -->

## Partes interesadas y potencialmente afectadas

| Parte | Interés o impacto actual | Límite |
|---|---|---|
| `ACT-01` — operador local | Recibe resultados saneados y puede detener su proceso | No existe interfaz de reclamación ni procedimiento operativo completo |
| `ACT-02` — mantenedor y tester | Controla código, corpus, dependencias, Git y ejecución bajo su cuenta | La concentración de autoridad no constituye una RACI formal |
| `ACT-03` — principal sintético | Demuestra binding y consumo de una aprobación técnica interna | No acredita identidad, comprensión o presencia humana real |
| Titulares de datos reales | Ninguno en el alcance actual | Deben identificarse antes de admitir cualquier dato real |
| Terceros, organizaciones o público | Ninguno recibe decisiones o efectos actuales | Deben identificarse antes de una UI, API, integración o uso de alto impacto |
| Revisor independiente `REV-01` | Papel planificado, no ejercido | No se atribuye revisión independiente a esta evaluación |

## Beneficios previstos y daños plausibles

Beneficios dentro del alcance actual:

- aprender con un ejemplo reproducible y sin enviar datos a terceros;
- separar contenido no confiable, propuesta, autoridad y efecto;
- comparar una baseline histórica con controles y conservar límites negativos;
- producir evidencia versionada que otra persona pueda inspeccionar.

Daños plausibles incluso en el laboratorio:

- falsa confianza si `DAT-25` se presenta como seguridad general o de
  producción;
- modificación o exposición de archivos locales si se evade el confinamiento;
- indisponibilidad o consumo excesivo del proceso y del host;
- fuga si en el futuro se introducen datos reales sin reevaluación;
- dependencia o compromiso de código, corpus, herramientas o paquetes;
- confundir la aprobación sintética con supervisión humana efectiva.

## Registro de impactos

Cada fila identifica la exposición actual, la evidencia disponible y el
trigger que impide extrapolarla. No sustituye el
[registro formal de riesgos](./risk-register.md).

<!-- aia-impact-register:start -->
| ID | Dimensión y partes afectadas | Evidencia y salvaguardas actuales | Impacto o incertidumbre no resueltos | Trigger y tratamiento previo | Clasificación actual |
|---|---|---|---|---|---|
| `AIA-IMP-01` | Autonomía y supervisión humana; `ACT-01`, `ACT-03` | La aplicación conserva la autoridad; el modelo no concede grants ni ejecuta herramientas; `CTL-06` y `CTL-07` | La aprobación sintética no demuestra presencia, comprensión, accesibilidad ni control humano real | Antes de exponer `TOL-02` o añadir autenticador, diseñar confirmación humana, revocación y contestabilidad | `ACOTADO_ALCANCE_ACTUAL` |
| `AIA-IMP-02` | Privacidad y protección de datos; futuros titulares de datos | Corpus `synthetic_internal`, esquemas, hashes, redacción y ausencia de red; `CTL-03`, `CTL-09` y `CTL-11` | No existe política para datos reales ni se ha evaluado reidentificación, retención o derechos | Antes de introducir datos reales o proveedor, definir finalidad, minimización, acceso, ciclo de vida y base aplicable | `ACOTADO_ALCANCE_ACTUAL` |
| `AIA-IMP-03` | Equidad, no discriminación e inclusión; futuras personas afectadas | No hay personas, atributos protegidos ni decisiones reales en el corpus actual | No existe medición de sesgo, representatividad, accesibilidad o diferencias entre grupos | Antes de una decisión sobre personas, identificar grupos, métricas, muestras y vías de reparación | `NO_APLICA_ALCANCE_ACTUAL` |
| `AIA-IMP-04` | Transparencia, explicabilidad y riesgo de representación engañosa; `ACT-01`, lectores del repositorio | Fichas, inventario, ADR, salidas estructuradas y límites públicos; `CTL-02`, `CTL-04` y `CTL-09` | El doble determinista no representa razonamiento ni explicabilidad de un modelo real | Mantener visible la naturaleza del doble y reevaluar antes de cambiar modelo o interfaz | `ACOTADO_ALCANCE_ACTUAL` |
| `AIA-IMP-05` | Ciberseguridad, confidencialidad e integridad; `ACT-01`, `ACT-02`, host local | Validación cerrada, allowlists, mínimo privilegio lógico, salida saneada y 14/14 casos finales; `CTL-04` a `CTL-06`, `CTL-08`, `CTL-09` y `CTL-12` | No hay aislamiento de SO, ataques desconocidos, prompt libre, modelo real o prueba de supply chain | Ante nueva superficie o deriva, contener, ampliar threat model y producir evidencia separada | `ACOTADO_ALCANCE_ACTUAL` |
| `AIA-IMP-06` | Fiabilidad, robustez y calidad; `ACT-01` | `DAT-25` conserva 12/12 casos benignos, 0 falsos rechazos y 84/84 reglas cerradas; `CTL-05`, `CTL-09` y `CTL-12` | No demuestra equivalencia semántica general, otras distribuciones, idiomas ni comportamiento probabilístico | Fijar modelo, corpus, criterios y presupuesto antes de afirmar utilidad o robustez adicional | `ACOTADO_ALCANCE_ACTUAL` |
| `AIA-IMP-07` | Seguridad física y decisiones de alto impacto; futuras personas afectadas | No hay actuador físico ni uso médico, legal, laboral, financiero o de infraestructura crítica | No se han definido severidad, tolerancia, fallback o responsabilidad para esos usos | Un uso de alto impacto exige evaluación nueva y autorización distinta antes de diseñarlo | `NO_APLICA_ALCANCE_ACTUAL` |
| `AIA-IMP-08` | Disponibilidad, recursos e impacto operativo; `ACT-01`, `ACT-02`, host local | Presupuestos cooperativos, preflight, checkpoints y lock advisory; `CTL-10` y `CTL-13` | `RR-01` y `RR-02` conservan DOS/corpus inertes; no hay carga, concurrencia, RSS bajo ataque, energía ni recuperación medida | Solo ejecutar pruebas DOS bajo RoE, topes, parada, recuperación y autorización nuevas | `NO_DEMOSTRADO` |
| `AIA-IMP-09` | Supply chain, propiedad intelectual y terceros; `ACT-02`, mantenedores futuros | Git, `uv.lock`, manifiestos y SHA-256 detectan parte del drift; `CTL-03` y `CTL-11` | `RR-03`: no hay firma, SBOM, CI, release policy, separación de funciones o ataque ejercitado | Inventariar dependencias, procedencia y proceso de release antes de otra distribución o integración | `NO_DEMOSTRADO` |
| `AIA-IMP-10` | Rendición de cuentas, auditabilidad y contestabilidad; `ACT-01`, `ACT-02`, `ACT-03` | `GSL-RACI-001`, `GSL-RISK-REGISTER-001`, evidencia versionada y eventos efímeros; `CTL-01`, `CTL-02`, `CTL-12` y `CTL-13` | La autoridad sigue concentrada; faltan decisiones humanas de riesgo, logs persistentes, revisor asignado y canal de reclamación | Completar M05, M06 y `PGS-07-M04` antes de atribuir gobierno operativo completo | `NO_DEMOSTRADO` |
<!-- aia-impact-register:end -->

## Handoff de riesgo residual

Esta tabla conecta la evaluación con el trabajo posterior sin aceptar,
repriorizar, cerrar o duplicar los riesgos.

<!-- aia-risk-handoff:start -->
| Riesgo | Impacto relacionado | Pregunta que queda para decisión | Target ya previsto | Estado |
|---|---|---|---|---|
| `RR-01` | `AIA-IMP-08` | ¿Qué exposición a agotamiento local y qué prueba limitada se autorizan? | `PGS-06-M07`, `PGS-07-M02` | `PENDIENTE_HUMANA` |
| `RR-02` | `AIA-IMP-02`, `AIA-IMP-08` | ¿Qué corrupción, tamaño y tolerancia de indisponibilidad se evaluarán? | `PGS-06-M08`, `PGS-07-M01`, `PGS-07-M02` | `PENDIENTE_HUMANA` |
| `RR-03` | `AIA-IMP-09`, `AIA-IMP-10` | ¿Qué procedencia, revisión y release se exigirán antes de publicar otro artefacto? | `PGS-06-M08`, `PGS-07-M01`, `PGS-07-M04` | `PENDIENTE_HUMANA` |
| `RR-04` | `AIA-IMP-01`, `AIA-IMP-10` | ¿La aprobación sigue siendo sintética o requiere presencia humana real? | `PGS-07-M04` | `PENDIENTE_HUMANA` |
| `RR-05` | `AIA-IMP-05`, `AIA-IMP-07` | ¿El confinamiento lógico basta para el siguiente efecto autorizado? | `PGS-06-M07`, `PGS-07-M01`, `PGS-07-M02` | `PENDIENTE_HUMANA` |
| `RR-06` | `AIA-IMP-03`, `AIA-IMP-04`, `AIA-IMP-06` | ¿Qué modelo, interfaz, distribución y revisión independiente justifican ampliar las afirmaciones? | `PGS-06-M09`, `PGS-07-M02`, `PGS-07-M04`, `PGS-07-M06` | `PENDIENTE_HUMANA` |
<!-- aia-risk-handoff:end -->

## Evidencia y límites de la evaluación

`DAT-25` registra, para el candidato, corpus y rúbrica fijados:

- 14/14 casos adversarios completados, éxito observado de 1/14 a 0/14,
  operaciones no autorizadas aceptadas o ejecutadas de 1 a 0, un caso mejorado
  y cero regresiones;
- 12/12 casos benignos completados, cero falsos rechazos, 24/24 hallazgos,
  36/36 acciones y 24/24 prohibiciones preservados bajo una rúbrica cerrada;
- cero red o credenciales de proveedor y cuatro fixtures DOS/SC inertes.

La evidencia no demuestra equivalencia semántica general, un juez LLM, ataques
desconocidos, comportamiento de un modelo GenAI real, aislamiento de sistema
operativo, presencia humana, resistencia de supply chain, carga sostenida o
adecuación para producción.

## Triggers de reevaluación

Todo trigger exige revisar esta evaluación antes de materializar el cambio. No
lo autoriza por sí mismo.

<!-- aia-triggers:start -->
| ID | Trigger heredado | Cambio que exige reevaluar | Revisión mínima |
|---|---|---|---|
| `AIA-TRG-01` | `ADR-TRG-01` | Modelo real, prompt libre o medición probabilística | Modelo, parámetros, datos, grupos afectados, utilidad, robustez y presupuesto |
| `AIA-TRG-02` | `ADR-TRG-02` | UI, API, listener, usuario remoto o autenticador | Partes afectadas, identidad, privacidad, accesibilidad, contestabilidad y concurrencia |
| `AIA-TRG-03` | `ADR-TRG-03` | Herramienta, efecto, dato, secreto o scope nuevo | Finalidad, autoridad, consecuencias, minimización, RoE y pruebas |
| `AIA-TRG-04` | `ADR-TRG-04` | Proveedor, red, cloud, contenedor, servicio o identidad de runtime | Transferencias, egress, supply chain, trust boundaries, coste y observabilidad |
| `AIA-TRG-05` | `ADR-TRG-05` | DOS, carga sostenida o requisito de aislamiento | Topes, entorno, parada, recuperación, impacto sobre host y autorización |
| `AIA-TRG-06` | `ADR-TRG-06` | Regresión, bypass, fuga, deriva o pérdida de reproducibilidad | Contención, personas o datos afectados, nueva evidencia y decisión separada |
| `AIA-TRG-07` | `ADR-TRG-07` | Incumplimiento de un umbral aprobado de utilidad u operación | Medición comparable, responsable, impacto de rollback y comunicación |
<!-- aia-triggers:end -->

## Resultado y condiciones de continuidad

La evaluación queda `COMPLETADA_ALCANCE_ACTUAL`. El impacto directo actual es
acotado porque el producto es local, sintético, enumerado, sin red, sin
usuarios externos y sin decisiones de alto impacto. Esto no convierte en
aceptables las incertidumbres: disponibilidad, supply chain, presencia humana,
aislamiento, generalización y gobierno operativo continúan abiertas.

Se permite continuar únicamente con el laboratorio ya descrito. Debe
detenerse una ampliación antes de implementarla si introduce cualquier trigger
`AIA-TRG-*`, datos reales, personas afectadas, un modelo real, una interfaz
remota o un efecto adicional. La continuación requiere entonces una evaluación
nueva o versionada, evidencia proporcional y la autoridad correspondiente.

Siguientes entregas:

- `PGS-06-M04`: mapa de cumplimiento y clasificación de obligaciones;
- `PGS-06-M05` a M07: logs, respuesta, parada y recuperación;
- `PGS-06-M08`: dependencias y supply chain;
- `PGS-06-M09`: política de cambios de modelo y reevaluación.

`PGS-06-M03` ya está completada mediante
[`GSL-RACI-001`](./raci.md) y
[`GSL-RISK-REGISTER-001`](./risk-register.md), sin heredar aceptación ni
atribuir revisión independiente.

## Relación con Tecture

La evaluación describe componentes, datos, límites e interfaces ya presentes
en `architecture/manifest.json`. No añade servicios, almacenes, integraciones,
despliegues, flujos o trust boundaries, por lo que no modifica el mapa.
