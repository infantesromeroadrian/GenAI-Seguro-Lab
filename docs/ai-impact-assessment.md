# Evaluación de impacto de IA — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-AIA-001` |
| Versión | `1.3.0` |
| Fecha | 2026-07-29 |
| Estado de la evaluación | `COMPLETADA_ALCANCE_ACTUAL` |
| Decisión que habilita | `CONTINUAR_SOLO_LABORATORIO_ACTUAL` |
| Límite de autoridad | `NO_AUTORIZA_AMPLIACION` |
| Corte de las fuentes | commit `648dd9afe9ef696388257ebf8dda4b59ece1aeb5` |
| Candidato de producto evaluado | commit `77edd64037bb0e41edffa58cae2682ba7d2694d2` |
| Evaluador de `DAT-25` | commit `636e1dbb8cac21c8c7bfc0709bf1d88b4b56304e` |
| Evidencia final | `DAT-25`, SHA-256 `05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d` |

Esta evaluación responde a `PGS-06-M02` y fue reevaluada para las extensiones
`GSL-WEB-001`, `GSL-OLLAMA-001` y `GSL-PUBLIC-STATIC-001`. `MOD-01`
forma parte de ese sistema, pero es un doble determinista:
no es un modelo de machine learning ni un modelo GenAI real. El documento no
es una evaluación jurídica, una DPIA, una clasificación bajo una regulación,
un mapa de cumplimiento, una aprobación de producción ni una aceptación de
riesgo.

## Decisión y jerarquía de fuentes

La decisión histórica habilitada es continuar con el laboratorio local,
sintético, determinista y sin red externa. `GSL-OLLAMA-001` añade únicamente un
`analyze` alojado explícito con egress sintético; no hereda las conclusiones de
`DAT-25` ni habilita datos reales, usuarios externos, prompt libre, una
interfaz remota, nuevos efectos, evaluaciones cloud o un despliegue.
En particular, la extensión no habilita datos reales.
El perfil público estático solo distribuye proyecciones sintéticas
precomputadas y no expone ese runtime.

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
| ¿Qué capacidad se evalúa? | CLI y frontal de loopback para analizar 12 incidentes ficticios con `MOD-01` `deterministic/scripted-v1`; un `analyze` puede seleccionar `MOD-02` `ollama/gpt-oss:120b` | `MOD-02` es experimental y no hereda la evaluación del candidato determinista |
| ¿Quién lo usa hoy? | `ACT-01` opera la CLI o el navegador local; `ACT-02` mantiene y prueba; `ACT-03` representa un principal sintético en un flujo interno | Son las únicas partes directamente relacionadas con el alcance actual |
| ¿Hay usuarios externos o público afectado? | No | Cualquier incorporación exige reevaluación previa |
| ¿Toma decisiones automatizadas sobre personas? | No | No se permite usar sus salidas para decisiones médicas, legales, laborales, financieras o de seguridad física |
| ¿Usa datos personales, reales, secretos o corporativos? | No; `DAT-01` a `DAT-25` son sintéticos o derivados de ejecuciones sintéticas | Los datos reales están fuera de alcance, no implícitamente autorizados |
| ¿Entrena o ajusta un modelo? | No hay entrenamiento, fine-tuning, pesos ni parámetros aprendidos | No se evalúan impactos propios de un dataset de entrenamiento real |
| ¿Expone prompt libre, UI, API o listener? | Expone `CMP-19`, una UI con listener fijo en `127.0.0.1`; no expone prompt libre, API pública o bind remoto | La entrada está enumerada, validada y limitada a `analyze` o `baseline`; la salida es JSON efímero por `stdout` o HTTP de loopback |
| ¿Realiza efectos externos? | Solo `analyze --provider ollama`: dos POST con datos sintéticos; el modo por defecto y baseline no | La herramienta sigue siendo local; `TOL-02` es interno y create-only |
| ¿Existe presencia humana verificada? | No | `IDN-03` es una identidad sintética y no equivale a una persona presente |
| ¿Hay red, proveedor, cloud, base de datos o telemetría externa? | Ollama Cloud solo por opt-in; no hay base de datos ni telemetría externa | Endpoint/modelo fijos, coste desconocido, un smoke end-to-end acotado y dos fallos cerrados previos; no se extrapolan garantías |
| ¿Cuál es el efecto máximo actual? | Lectura local confinada en producto y creación interna de un borrador ficticio en sandbox | El host y la cuenta macOS siguen siendo la frontera efectiva |
| ¿Se ha realizado una clasificación jurídica o regulatoria? | No | Corresponde a `PGS-06-M04` distinguir obligación, guía y decisión voluntaria |
<!-- aia-screening:end -->

## Reevaluación de la extensión `GSL-WEB-001`

`AIA-TRG-02` se activó al incorporar una UI y un listener. La reevaluación
mantiene `CONTINUAR_SOLO_LABORATORIO_ACTUAL` porque la extensión:

- se fija a `127.0.0.1` y no ofrece bind configurable, CORS o acceso remoto;
- acepta solo un identificador benigno cerrado o un cuerpo vacío de baseline;
- aplica Host, Origin, CSRF, `Content-Type`, 1 KiB, esquema estricto, CSP y
  cabeceras de navegador;
- reutiliza la autoridad, datos, límites y política de salida ya existentes;
- no añade prompt, uploads, rutas, borradores, persistencia, red externa,
  proveedor, modelo o decisiones sobre personas.

El [threat model del frontal](./web-threat-model.md) documenta `TB-07` y los
riesgos residuales específicos. Esta reevaluación no modifica el mapa de
impactos, la clasificación jurídica, las decisiones humanas pendientes ni la
evidencia histórica `DAT-25`.

## Reevaluación de la extensión `GSL-OLLAMA-001`

`AIA-TRG-01` y `AIA-TRG-04` se activaron al incorporar un modelo alojado,
credencial y egress. La extensión queda limitada porque:

- requiere selección explícita, acepta solo un ID benigno y nunca entra en
  baseline, evaluaciones, corpus adversario o `DAT-25`;
- envía únicamente tarea, incidente y conocimiento sintéticos validados al
  endpoint/modelo fijos, con dos llamadas y cero retries;
- conserva grants, scope, allowlist, esquema final, límites y política de
  salida en la aplicación;
- no registra thinking, prompt, cuerpo remoto, respuesta cruda o secreto;
- declara `deterministic=false`, `external_calls=true` y coste desconocido.

La evidencia automatizada usa transporte falso y un smoke instrumentado real
completó el flujo acotado de `INC-BEN-001` tras dos fallos cerrados. No permite
concluir disponibilidad, reproducibilidad, calidad, robustez, privacidad
contractual, residencia, retención, coste o comportamiento general del
proveedor. Cualquier nueva prueba real requiere autoridad raíz, revisión de
egress/términos y evidencia separada.

## Reevaluación de la extensión `GSL-PUBLIC-STATIC-001`

El perfil materializa el trigger de interfaz pública, pero reduce la
consecuencia al servir solo assets y resultados sintéticos precomputados:

- no publica el listener, Python, Functions, API, POST, secretos u Ollama;
- etiqueta la experiencia como demo y los botones como “precomputado”;
- regenera el snapshot desde los 12 análisis y la baseline deterministas;
- no reejecuta ni reinterpreta `DAT-25`.

El despliegue autorizado posterior se verificó en
`https://genai-seguro-lab.vercel.app`: assets y snapshot respondieron `200`,
las rutas API y el POST respondieron `404`, y el flujo completo no produjo
errores de consola. El tratamiento contractual, la residencia, la retención y
los controles internos de Vercel permanecen fuera de esta evaluación.

## Partes interesadas y potencialmente afectadas

| Parte | Interés o impacto actual | Límite |
|---|---|---|
| `ACT-01` — operador local | Recibe resultados saneados y puede detener su proceso | No existe interfaz de reclamación ni procedimiento operativo completo |
| `ACT-02` — mantenedor y tester | Controla código, corpus, dependencias, Git y ejecución bajo su cuenta | La concentración de autoridad no constituye una RACI formal |
| `ACT-03` — principal sintético | Demuestra binding y consumo de una aprobación técnica interna | No acredita identidad, comprensión o presencia humana real |
| Titulares de datos reales | Ninguno en el alcance actual | Deben identificarse antes de admitir cualquier dato real |
| Visitantes del perfil público | Pueden leer una demo sintética precomputada, sin decisión o efecto | Pueden confundirla con ejecución real; la UI debe conservar etiquetas y límites |
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
| `AIA-IMP-02` | Privacidad y protección de datos; futuros titulares de datos | Corpus `synthetic_internal`, esquemas, hashes, redacción y egress Ollama limitado a datos sintéticos; `CTL-03`, `CTL-09` y `CTL-11` | No existe política para datos reales ni se han verificado retención, residencia, reidentificación o derechos del proveedor | Antes de introducir datos reales o ampliar proveedor, definir finalidad, minimización, acceso, ciclo de vida y base aplicable | `ACOTADO_ALCANCE_ACTUAL` |
| `AIA-IMP-03` | Equidad, no discriminación e inclusión; futuras personas afectadas | No hay personas, atributos protegidos ni decisiones reales en el corpus actual | No existe medición de sesgo, representatividad, accesibilidad o diferencias entre grupos | Antes de una decisión sobre personas, identificar grupos, métricas, muestras y vías de reparación | `NO_APLICA_ALCANCE_ACTUAL` |
| `AIA-IMP-04` | Transparencia, explicabilidad y riesgo de representación engañosa; `ACT-01`, lectores del repositorio | Fichas, inventario, status dinámico, salidas estructuradas y límites públicos; `CTL-02`, `CTL-04` y `CTL-09` | El doble no representa razonamiento y el thinking alojado se descarta, no se ofrece como explicación | Mantener visible qué backend opera y reevaluar antes de cambiar modelo o interfaz | `ACOTADO_ALCANCE_ACTUAL` |
| `AIA-IMP-05` | Ciberseguridad, confidencialidad e integridad; `ACT-01`, `ACT-02`, host local | Validación cerrada, allowlists, mínimo privilegio lógico, salida saneada y 14/14 casos finales deterministas; `CTL-04` a `CTL-06`, `CTL-08`, `CTL-09` y `CTL-12` | No hay aislamiento de SO, ataques desconocidos, prompt libre ni evaluación adversaria de `MOD-02` | Ante nueva superficie o deriva, contener, ampliar threat model y producir evidencia separada | `ACOTADO_ALCANCE_ACTUAL` |
| `AIA-IMP-06` | Fiabilidad, robustez y calidad; `ACT-01` | `DAT-25` conserva 12/12 casos benignos, 0 falsos rechazos y 84/84 reglas cerradas para `MOD-01`; `CTL-05`, `CTL-09` y `CTL-12` | No demuestra equivalencia semántica general, otras distribuciones, idiomas ni calidad de `MOD-02` | Producir evidencia nueva del modelo alojado antes de afirmar utilidad o robustez adicional | `ACOTADO_ALCANCE_ACTUAL` |
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
- cero red o credenciales de proveedor en aquel candidato y cuatro fixtures
  DOS/SC inertes.

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

La evaluación queda `COMPLETADA_ALCANCE_ACTUAL`. El impacto directo permanece
acotado por datos sintéticos, entrada enumerada, ausencia de usuarios externos
y ausencia de decisiones de alto impacto. El modo determinista no usa red; el
opt-in Ollama sí realiza egress declarado y conserva incertidumbres de
proveedor, disponibilidad, coste, privacidad, supply chain, generalización y
gobierno operativo.

Se permite continuar únicamente con el laboratorio ya descrito. Debe
detenerse una ampliación antes de implementarla si introduce cualquier trigger
`AIA-TRG-*`, datos reales, personas afectadas, un modelo real, una interfaz
remota o un efecto adicional. La continuación requiere entonces una evaluación
nueva o versionada, evidencia proporcional y la autoridad correspondiente.

Siguientes entregas:

- PGS-06-M04 a M08 están documentadas en sus artefactos enlazados desde el
  índice.
- [`GSL-MODEL-CHANGE-001`](./model-change-reevaluation-policy.md) completa
  PGS-06-M09 y decide qué paquetes repetir ante cada trigger.

`PGS-06-M03` ya está completada mediante
[`GSL-RACI-001`](./raci.md) y
[`GSL-RISK-REGISTER-001`](./risk-register.md), sin heredar aceptación ni
atribuir revisión independiente.

## Relación con Tecture

El mapa `architecture/manifest.json` está sincronizado con
`GSL-OLLAMA-001`: representa `MOD-02`, `CMP-20`, `CMP-21` y el límite de
confianza `TB-08` para el egress fijo hacia Ollama Cloud. Esta sincronización
documenta la arquitectura observada; no invalida el código ni amplía la
autoridad.
