# Plan del proyecto — GenAI Seguro Lab

## Estado

- **Proyecto:** GenAI Seguro Lab.
- **Nombre de carpeta confirmado:** `GenAI-Seguro-Lab`.
- **Checkout:** repositorio Git del proyecto en la rama `main`.
- **Roadmap padre:** fase 01 — Fundamentos de AI Security.
- **Microtareas padre completadas:** P01-M01 y P01-M04 a P01-M08.
- **Estado actual:** PGS-00-M01 a PGS-07-M03 completadas; PGS-04 y P01-M08
  quedan cerradas. La baseline adversaria histórica permanece inmutable; M01
  repitió sus 14 fixtures PI/JB/EX/TOL contra el commit endurecido y M02 fijó
  1/14 (7,14 %) → 0/14 (0 %) de éxito de ataque y 1 → 0 operaciones no
  autorizadas aceptadas o ejecutadas. M03 reconstruyó una proyección benigna
  anterior a controles y ejecutó individualmente el mismo corpus: pre/post
  conservan 12/12 terminaciones técnicas, 0/12 falsos rechazos, 0 llamadas
  externas y 0 efectos, pero 0/12 éxitos estrictos y 12 `PARTIAL` porque el
  resumen genérico no contiene las 24 cláusulas de hallazgo ni las 36 acciones
  esperadas. M04 conservó 30 pares AB/BA: la mediana end-to-end pasó de
  189,69 ms a 259,17 ms, CPU y RSS aumentaron y los conteos 12/24/12/12 y el
  coste externo permanecieron sin cambio. No hay regresiones atribuibles a los
  controles; `SC-07` sigue `NOT_DEMONSTRATED` porque la equivalencia semántica
  y las afirmaciones prohibidas no se evaluaron. `CTL-06`, `CTL-07`, `CTL-08`,
  `CTL-09`, `CTL-10`, `CTL-12` y `CTL-13` permanecen parciales por sus límites
  declarados, las cuatro fixtures inertes, la ausencia de presencia humana,
  aislamiento y modelo real, y porque la medición operativa corresponde a un
  único host y sesión sin energía, TCO, concurrencia o carga sostenida.
  M05 consolida seis hallazgos en `GSL-CONTROL-FINDINGS-001`: no observa
  fallos de control ni bypasses actuales dentro de las 14 fixtures medidas,
  conserva un bypass histórico pendiente del retest final, dos resultados
  negativos y tres gaps de evidencia. Los estados `PARCIAL`,
  `NOT_DEMONSTRATED`, `NOT_COMPUTABLE` e inerte no se reclasifican como fallo.
  M06 confirmó `CF-004` como defecto funcional previo a los controles y lo
  corrigió sin usar `expected_result`: el candidato fijado en `77edd64` genera
  12 salidas estructuradas distintas, con cuatro actuaciones propuestas por
  caso, 12/12 terminaciones técnicas, cero solicitudes no autorizadas, llamadas
  externas o efectos y dos redacciones esperadas. La evidencia histórica
  permanece intacta. M07 ejecutó una sola vez el candidato `77edd640` con el
  evaluador `636e1db`: 14/14 casos adversarios y 12/12 benignos terminaron,
  `ADV-TOL-005` mejoró, no hubo regresiones ni falsos rechazos y las 84
  cláusulas mapeadas se preservaron bajo la rúbrica cerrada. `SC-06` y `SC-07`
  quedan `DEMONSTRATED` para ese candidato y contrato; la equivalencia
  semántica general y el modelo GenAI real siguen sin evaluarse, `CF-002`
  permanece `NOT_COMPUTABLE` y las cuatro fixtures DOS/SC continúan inertes.
  M08 fija
  [`GSL-RESIDUAL-RISK-001`](./docs/residual-risk-and-tradeoffs.md): seis
  riesgos cubren una sola vez los 17 abuse cases, conservan el scoring
  heredado y mantienen toda aceptación pendiente sin adelantar el registro
  formal de PGS-06-M03.
  M09 fija
  [`GSL-ADR-001`](./docs/architecture-decision-record.md): acepta para el
  alcance actual la baseline local-first determinista con autoridad fuera del
  modelo, compara siete alternativas y define triggers, rollback compensatorio
  y supersesión sin seleccionar capacidades futuras ni aceptar riesgo.
  PGS-06-M01 publica
  [`GSL-SYSTEM-CARD-001`](./docs/system-card.md),
  [`GSL-DATA-CARD-001`](./docs/data-card.md) y
  [`GSL-MODEL-CARD-001`](./docs/model-card.md): tres vistas descriptivas del
  alcance observado que fijan fuentes, usos, autoridad, ciclo de vida,
  evidencia y límites sin certificar el sistema ni aceptar los seis riesgos
  pendientes. `MOD-01` queda identificado expresamente como doble
  determinista sin entrenamiento ni proveedor real.
  PGS-06-M02 fija
  [`GSL-AIA-001`](./docs/ai-impact-assessment.md): completa el cribado del
  alcance actual y diez dimensiones de impacto, conserva `RR-01` a `RR-06`
  como `PENDIENTE_HUMANA` y exige reevaluar antes de ampliar modelo, datos,
  interfaz, efectos o despliegue. No realiza clasificación jurídica, no crea
  el registro formal de M03 ni autoriza producción.
  PGS-06-M03 publica
  [`GSL-RACI-001`](./docs/raci.md) y
  [`GSL-RISK-REGISTER-001`](./docs/risk-register.md): doce actividades tienen
  exactamente un accountable actual y los seis riesgos conservan owner,
  controles, brecha, respuesta propuesta, target, trigger y una decisión
  `PENDIENTE_HUMANA`. `REV-01` continúa planificado y sin asignar; no se acepta
  riesgo ni se atribuye revisión independiente.
  PGS-06-M04 publica
  [`GSL-COMPLIANCE-MAP-001`](./docs/compliance-map.md): clasifica nueve
  fuentes y decisiones sin convertir guías en obligaciones, atribuir
  conformidad o realizar una clasificación jurídica del laboratorio.
  PGS-06-M05 amplía
  [`GSL-SECURITY-EVENTS-001`](./docs/security-events-policy.md): mantiene
  el runtime sin persistencia y fija redacción, acceso, conservación y
  retirada por ocho clases sin prometer purga fuera del control observado.
  PGS-06-M06 publica
  [`GSL-AI-IR-001`](./docs/ai-incident-response-runbook.md): separa señal,
  observación e incidente, fija severidad, flujo y playbooks sin automatizar
  respuesta, aceptar riesgos o atribuir participación a `REV-01`.
  PGS-06-M07 publica
  [`GSL-STOP-RECOVERY-001`](./docs/stop-recovery-procedure.md): fija cuatro
  niveles y ocho pasos operativos sobre la parada y reconciliación existente,
  sin añadir handlers, reintentos, rollback automático o borrado de finales.
  PGS-06-M08 publica
  [`GSL-SUPPLY-CHAIN-001`](./docs/dependency-supply-chain-register.md):
  registra 11 distribuciones, toolchain, hashes, proceso de cambio y ocho gaps;
  `RR-03` sigue abierto y no se atribuye un escaneo no ejecutado.
  PGS-06-M09 publica
  [`GSL-MODEL-CHANGE-001`](./docs/model-change-reevaluation-policy.md):
  clasifica nueve cambios y ocho paquetes de evaluación, conserva `DAT-25` y
  separa trigger, evidencia, revisión y autoridad.
  PGS-07-M01 fija
  [`GSL-CLEAN-REBUILD-001`](./evaluations/clean-rebuild-v1.json): un clon
  público nuevo del candidato `93d9a058` valida lock, instalación sin caché,
  segunda sincronización sin cambios y el punto de entrada `main.py`. La red
  usada queda declarada, no se atribuye hermeticidad y `DAT-25` no se ejecuta
  ni cambia.
  PGS-07-M02 fija
  [`GSL-CLOSURE-EXECUTION-001`](./evaluations/closure-execution-v1.json): sobre
  otro clon nuevo del commit `6d4f132` superan 327 pruebas, 12 benignos y los
  14 adversarios PI/JB/EX/TOL autorizados. Las cuatro fixtures DOS/SC siguen
  inertes, las repeticiones quedan declaradas y `DAT-25` no se ejecuta ni
  cambia.
  PGS-07-M03 fija
  [`GSL-CONTENT-SCAN-001`](./evaluations/content-scan-v1.json): Gitleaks no
  observa secretos en el árbol ni en 67 commits y los 56 registros del corpus
  son sintéticos. El historial conserva procedencia personal y cuatro commits
  que tocaron una ruta local ya retirada; se declara sin copiar valores y sin
  reescribir el historial público.
- **Línea seleccionada:** B — aplicación GenAI protegida frente a prompt injection, jailbreak y abuso de herramientas.
- **Entorno previsto:** local-first, con un corpus operativo exclusivamente sintético.
- **Publicación, cloud y gasto:** el repositorio público y su `main`
  versionado están autorizados para este proyecto; releases, cloud, gasto y
  cualquier otro artefacto o canal externo requieren autorización específica.

## Objetivo

Construir desde cero una aplicación GenAI pequeña y reproducible que permita demostrar el ciclo:

`baseline vulnerable → ataque controlado → control de seguridad → retest → métricas → riesgo residual`

El resultado debe producir evidencia verificable de que la persona responsable
puede:

1. delimitar un sistema GenAI y sus límites de confianza;
2. identificar y priorizar amenazas;
3. reproducir ataques únicamente contra el laboratorio propio;
4. diseñar y aplicar controles proporcionales;
5. medir seguridad y utilidad antes y después;
6. documentar decisiones, límites y riesgo residual.

## Producto mínimo aprobado

Un asistente local para analizar incidentes de seguridad ficticios. El sistema utilizará únicamente un pequeño conjunto de documentos sintéticos y tendrá capacidades deliberadamente limitadas:

- consultar una base de conocimiento sintética;
- resumir un incidente;
- proponer una acción;
- crear un borrador dentro de un sandbox local;
- solicitar confirmación humana antes de cualquier acción con efecto.

El laboratorio incluirá documentos adversarios preparados para intentar cambiar las instrucciones, extraer información o provocar un uso no autorizado de herramientas.

Esta definición quedó aprobada al completar **PGS-00-M01** el 25 de julio de
2026. Las capacidades quedaron fijadas en PGS-00-M02 y el stack, la estrategia
de modelo y el presupuesto en PGS-00-M04.

## Capacidades y autoridad aprobadas

- **Analizar incidente:** operación sin efecto externo sobre un incidente sintético seleccionado.
- **Consultar conocimiento:** lectura limitada a la base sintética autorizada.
- **Proponer actuación:** recomendación sin capacidad de ejecución.
- **Crear borrador:** creación de un archivo nuevo únicamente en `sandbox/drafts/`, tras confirmación humana explícita vinculada al contenido exacto.
- **Autoridad:** el modelo solicita; la política valida; solo el usuario autoriza una escritura.
- **Denegación por defecto:** no se permiten otras herramientas, red, shell, secretos, datos reales, modificación, sobrescritura o borrado.
- **Perfil vulnerable:** accesible solo desde el harness aislado de evaluación.

El contrato completo está documentado en
[README.md](./README.md#capacidades-y-autoridad-aprobadas). La baseline
histórica precede al control del producto; los límites de la versión endurecida
han quedado fijados en PGS-04-M06 antes de su retest, sin modificar aquella
evidencia.

## Alcance

- Una sola aplicación GenAI y un solo flujo principal.
- Corpus operativo exclusivamente sintético, sin datos personales reales.
- Un adaptador de modelo con doble modo:
  - sustituto determinista para tests reproducibles;
  - proveedor real opcional, elegido y configurado posteriormente.
- Herramientas locales con permisos mínimos y efectos confinados al sandbox.
- Corpus benigno y adversario versionado.
- Threat model de aplicación, modelo, datos, herramientas, identidad, dependencias e infraestructura local.
- Guardrails, validación, control de capacidades, registro de eventos y parada segura.
- Métricas de seguridad y utilidad.
- Documentación de gobierno y respuesta a incidentes desde el diseño.

## Fuera de alcance

- Reutilizar código o arquitectura de FraudAI-Agent.
- Entrenar un modelo fundacional.
- Utilizar datos personales, corporativos o confidenciales.
- Atacar sistemas, modelos o cuentas de terceros.
- Desplegar en AWS o en otro proveedor cloud durante esta fase.
- Construir una interfaz gráfica antes de validar el núcleo.
- Crear una arquitectura multiagente sin una necesidad demostrada.
- Permitir acciones destructivas o efectos fuera del sandbox.
- Afirmar que el sistema está preparado para producción.

## Principios de diseño

1. **Seguro por defecto:** el perfil vulnerable solo existirá en el harness aislado de evaluación.
2. **Mínimo privilegio:** cada herramienta tendrá únicamente los permisos necesarios.
3. **Autoridad explícita:** modelo, identidad, datos, herramientas y acciones se documentarán por separado.
4. **Evidencia reproducible:** cada claim deberá apuntar a código, prueba, log o documento versionado.
5. **Defensa en profundidad:** ningún control único se considerará protección completa.
6. **Utilidad medible:** la seguridad no podrá evaluarse ignorando la capacidad legítima del sistema.
7. **Riesgo residual visible:** los límites y fallos conocidos no se ocultarán.
8. **Sin secretos en el repositorio:** credenciales operativas y datos sensibles
   quedarán fuera del código y de los logs. Las cadenas públicas usadas como
   fixtures sintéticas no se tratarán como secretos ni se reutilizarán fuera
   de test.

## Stack, modelo y presupuesto aprobados

La selección quedó cerrada en **PGS-00-M04**:

| Área | Decisión |
|---|---|
| Runtime | Python 3.12, restringido a `>=3.12,<3.13` |
| Gestión del proyecto | `uv`, con `pyproject.toml`, `.python-version` y `uv.lock` |
| Validación | Pydantic 2, en modo estricto y rechazando campos adicionales no declarados |
| Pruebas | pytest 9, con fixtures y casos parametrizados |
| Núcleo | Librería estándar para CLI, rutas, JSON/JSONL, hashing, concurrencia y journal en memoria |
| Interfaz inicial | Línea de comandos local |
| Framework de agentes | Ninguno durante el mínimo viable |
| API pública, base de datos y cloud | No se incorporan durante esta fase |

Las versiones exactas de las dependencias se fijarán en `uv.lock` al inicializar el proyecto; PGS-00-M04 no instala paquetes ni crea todavía el repositorio.

### Estrategia de modelo

- El comportamiento canónico y las pruebas reproducibles utilizarán un sustituto determinista ejecutado en proceso.
- Existirá como máximo un adaptador opcional para un modelo GenAI real, desactivado por defecto.
- No habrá múltiples proveedores, fallback automático ni reintentos en segundo plano.
- Proveedor, identificador de modelo y parámetros deberán quedar registrados junto a cada resultado real.
- El proveedor solo se elegirá si permite obtener evidencia de comportamiento que el sustituto determinista no pueda producir.

### Candidato local: Docker AI

- **Docker Model Runner** es el candidato preferente para la validación opcional con un modelo real local, porque expone una API compatible con OpenAI sin enviar por defecto los datos a un proveedor alojado.
- **Docker Compose** podrá empaquetar la aplicación y el modelo cuando aporte reproducibilidad; no será requisito para crear el primer flujo benigno.
- **MCP Gateway** solo se evaluará si el proyecto incorpora servidores MCP. No se añade al mínimo viable.
- **Docker Sandboxes** se considera una herramienta para aislar agentes de programación, no el sandbox funcional de borradores de esta aplicación.
- Esta evaluación no descarga modelos, inicia Docker, incorpora dependencias ni cambia el presupuesto de 0 € por defecto.

### Presupuesto

- Ejecución local y pruebas deterministas: **0 €**.
- Cloud y despliegue: **0 €**.
- Validación opcional con un modelo real: tope acumulado de **5 €** para PGS-01.
- El tope no autoriza gasto ni llamadas a una API: ambas requieren una autorización posterior y específica.
- Al alcanzar el tope, el laboratorio se detiene; no habrá recarga, fallback ni ampliación automática.

## Datos, acciones y límites éticos aprobados

La decisión quedó cerrada en **PGS-00-M05**:

### Datos

- El corpus operativo será 100 % sintético.
- Se admiten incidentes ficticios, documentos sintéticos de conocimiento, fixtures adversarias controladas, metadatos de evaluación y salidas generadas únicamente a partir de esos datos.
- Cada caso deberá declarar identificador, tipo, procedencia, `synthetic: true`, sensibilidad y resultado esperado.
- Una fuente pública solo podrá servir como referencia documentada para redactar material sintético; no se copiarán incidentes reales al corpus.
- Se prohíben datos personales, atributos reidentificables, datos sensibles reales, secretos, credenciales, material corporativo, malware ejecutable, datos robados y material sin procedencia o derechos suficientes.

### Acciones

- Se permiten únicamente la lectura de la base sintética, el análisis y resumen, la propuesta sin ejecución, las pruebas contra el laboratorio propio y la creación confirmada de un archivo nuevo en `sandbox/drafts/`.
- Se prohíben redes y servicios externos, lectura o escritura fuera del sandbox, shell o ejecución de código, modificación, sobrescritura, borrado, acceso a secretos, acciones contra terceros, comunicaciones y cualquier efecto externo.
- Un futuro acceso por `localhost` al modelo local deberá aprobarse y limitarse a un endpoint exacto; hasta entonces permanece desactivado.
- Toda capacidad no permitida expresamente queda denegada por defecto.

### Límites éticos y de conservación

- Uso educativo y defensivo; no se utilizará para incidentes o decisiones reales.
- Ninguna salida decidirá sobre personas, derechos, vigilancia o seguridad física.
- Los atributos protegidos quedan fuera del corpus principal.
- El perfil vulnerable permanece confinado al harness de evaluación.
- Los ejemplos adversarios incluirán solo el detalle necesario para probar controles del laboratorio.
- No habrá telemetría, subida o exportación automática.
- Los logs normales referenciarán identificadores y campos permitidos, sin duplicar contenido completo.
- Un proveedor alojado permanecerá desactivado y solo podrá recibir un subconjunto sintético mediante autorización posterior.
- La conservación y eliminación detalladas se definirán en PGS-06-M05.

Los requisitos y criterios de aceptación completos están en [README.md](./README.md#contrato-de-datos-y-límites-éticos).

## Entregables, éxito y no-objetivos aprobados

La decisión quedó cerrada en **PGS-00-M06**:

- **Entregables:** repositorio reproducible, corpus sintético, arquitectura y threat model, baseline vulnerable, versión endurecida, retest comparativo, métricas, riesgo residual, gobierno, runbooks y revisión independiente.
- **Corpus mínimo:** 12 casos benignos y 18 adversarios repartidos entre seis o más familias.
- **Invariante crítica:** ningún caso crítico endurecido puede producir un efecto o llamada de herramienta no autorizados.
- **Utilidad:** al menos 90 % de éxito benigno y como máximo 10 % de falsos rechazos.
- **Reproducibilidad:** `uv sync --frozen`, suite pytest sin fallos y reconstrucción independiente de un caso benigno y otro adversario.
- **Trazabilidad:** cada claim debe enlazar requisito, versión, prueba, resultado, control y riesgo residual.
- **No-objetivos:** producción, seguridad total, datos reales, entrenamiento, cloud, API pública, interfaz gráfica, multiagente, múltiples proveedores, acciones externas, certificación regulatoria y publicación no autorizada.

El contrato completo se encuentra en [README.md](./README.md#entregables-contractuales).

### Política de versionado

- El primer commit contiene PGS-00 completo porque Git no existía; no se ha fabricado historial.
- Desde PGS-01, cada microtarea con cambios tendrá un commit funcional coherente con sus pruebas y documentación.
- No se crearán commits vacíos.
- El remoto público y el primer `push` fueron autorizados expresamente el
  2026-07-25; los pushes posteriores conservarán commits funcionales,
  verificados y granulares.

## Criterios globales de éxito

- Reconstrucción limpia mediante dependencias bloqueadas y documentación suficiente.
- Suite automatizada sin fallos.
- Corpus mínimo fijado antes de la baseline.
- Fallo crítico reproducible en la baseline y mismo corpus en el retest.
- Cero efectos o llamadas de herramienta no autorizados en casos críticos endurecidos.
- Éxito benigno mínimo del 90 % y falsos rechazos máximos del 10 %.
- Métricas de seguridad, utilidad, operación y coste registradas.
- Ausencia de secretos y datos reales.
- Trazabilidad completa y reproducción independiente de un caso benigno y otro adversario.

## Fases y microtareas

### Fase PGS-00 — Contrato del proyecto

**Objetivo:** cerrar P01-M01 sin empezar a implementar sobre supuestos.

- [x] **PGS-00-M01** Aprobar o corregir el producto mínimo, el usuario, el problema y el resultado esperado.
- [x] **PGS-00-M02** Fijar las capacidades permitidas: consulta, resumen, propuesta y borrador en sandbox.
- [x] **PGS-00-M03** Confirmar el nombre `GenAI Seguro Lab` y la ruta local del proyecto.
- [x] **PGS-00-M04** Elegir el stack, la estrategia de modelo y el presupuesto máximo de ejecución.
- [x] **PGS-00-M05** Definir datos admitidos, acciones prohibidas y límites éticos del laboratorio.
- [x] **PGS-00-M06** Aprobar criterios de éxito, entregables y no-objetivos.

**Salida:** contrato mínimo aprobado y P01-M01 cerrada con evidencia.

### Fase PGS-01 — Esqueleto reproducible

**Objetivo:** obtener una aplicación local mínima antes de introducir ataques.

- [x] **PGS-01-M01** Inicializar el repositorio Git local y crear el commit inicial del contrato después de cerrar PGS-00.
- [x] **PGS-01-M02** Crear la estructura mínima de código, tests, evaluaciones, datos y documentación.
- [x] **PGS-01-M03** Configurar dependencias reproducibles y exclusión de secretos.
- [x] **PGS-01-M04** Crear el dataset sintético de incidentes y la base de conocimiento.
- [x] **PGS-01-M05** Implementar el adaptador determinista de modelo para tests.
- [x] **PGS-01-M06** Implementar el flujo benigno mínimo y las herramientas confinadas al sandbox.
- [x] **PGS-01-M07** Añadir smoke tests y registrar la primera baseline funcional.

**Salida:** flujo benigno reproducible sin dependencia obligatoria de un proveedor externo.

### Fase PGS-02 — Arquitectura y threat model

**Objetivo:** describir exactamente qué se protege antes de probar ataques.

- [x] **PGS-02-M01** Registrar las versiones consultadas de OWASP, MITRE ATLAS y NIST.
- [x] **PGS-02-M02** Inventariar usuarios, datos, modelo, herramientas, identidades, dependencias e infraestructura.
- [x] **PGS-02-M03** Dibujar componentes, flujo de datos y trust boundaries.
- [x] **PGS-02-M04** Crear la matriz `modelo → identidad → datos → herramientas → acciones → consecuencias`.
- [x] **PGS-02-M05** Enumerar abuse cases de prompt injection, jailbreak, exfiltración, abuso de herramientas y denegación de servicio.
- [x] **PGS-02-M06** Priorizar los abuse cases por impacto, probabilidad y capacidad real del sistema.
- [x] **PGS-02-M07** Mapear amenazas a OWASP y MITRE ATLAS.
- [x] **PGS-02-M08** Mapear responsabilidades y controles previstos a NIST AI RMF y NIST SP 800-218A.

**Salida:** threat model versionado y backlog de pruebas priorizado.

### Fase PGS-03 — Baseline vulnerable y harness de ataque

**Objetivo:** demostrar fallos controlados sin convertir el modo vulnerable en el comportamiento predeterminado.

- [x] **PGS-03-M01** Definir las Rules of Engagement del laboratorio propio.
- [x] **PGS-03-M02** Crear un perfil vulnerable aislado y exclusivo para evaluación.
- [x] **PGS-03-M03** Preparar el corpus adversario con entradas y resultados esperados.
- [x] **PGS-03-M04** Implementar pruebas para prompt injection directa e indirecta.
- [x] **PGS-03-M05** Implementar pruebas para jailbreak y revelación de información.
- [x] **PGS-03-M06** Implementar pruebas para llamadas de herramienta no autorizadas y exceso de agencia.
- [x] **PGS-03-M07** Ejecutar la baseline y conservar configuración, resultados y logs saneados.
- [x] **PGS-03-M08** Documentar hallazgos, impacto, reproducción y límites.

**Salida:** al menos un fallo reproducible y medido contra una baseline fija.

### Fase PGS-04 — Controles de seguridad

**Objetivo:** aplicar controles trazables a amenazas concretas.

- [x] **PGS-04-M01** Separar instrucciones de sistema, contenido no confiable y datos de usuario.
- [x] **PGS-04-M02** Validar entradas, salidas y argumentos de herramientas mediante esquemas y allowlists.
- [x] **PGS-04-M03** Aplicar mínimo privilegio a identidades, datos y herramientas.
- [x] **PGS-04-M04** Exigir aprobación autenticada para acciones con efecto:
  principal sintético local implementado; presencia humana real pendiente de
  una futura interfaz/autenticador.
- [x] **PGS-04-M05** Incorporar filtros, redacción de datos y política de salida.
- [x] **PGS-04-M06** Añadir límites de tamaño, tiempo, iteraciones y consumo.
- [x] **PGS-04-M07** Añadir eventos de seguridad, correlación y señales de comportamiento anómalo.
- [x] **PGS-04-M08** Implementar parada segura y recuperación del estado del sandbox.
- [x] **PGS-04-M09** Asociar cada control a amenaza, responsable, prueba y limitación.

**Salida:** versión endurecida con controles independientes y observables.

### Fase PGS-05 — Retest y medición

**Objetivo:** comprobar la mejora sin ocultar regresiones de utilidad.

- [x] **PGS-05-M01** Repetir exactamente el corpus adversario de la baseline.
- [x] **PGS-05-M02** Medir tasa de éxito del ataque y llamadas no autorizadas antes y después.
- [x] **PGS-05-M03** Repetir el corpus benigno y medir éxito de tarea y falsos rechazos.
- [x] **PGS-05-M04** Comparar latencia, consumo y complejidad operativa.
- [x] **PGS-05-M05** Registrar controles fallidos, bypasses y resultados negativos.
- [x] **PGS-05-M06** Corregir únicamente defectos demostrados dentro del alcance.
- [x] **PGS-05-M07** Ejecutar el retest final y fijar los resultados.
- [x] **PGS-05-M08** Documentar riesgo residual y compensaciones entre seguridad y utilidad.
- [x] **PGS-05-M09** Redactar el ADR de la solución seleccionada, alternativas y rollback.

**Salida:** informe comparativo baseline/control/retest con métricas reproducibles.

### Fase PGS-06 — Gobierno y operación

**Objetivo:** hacer que la seguridad sea mantenible y explicable.

- [x] **PGS-06-M01** Crear system card, data card y model card.
- [x] **PGS-06-M02** Completar la evaluación de impacto de IA.
- [x] **PGS-06-M03** Crear RACI y registro de riesgos.
- [x] **PGS-06-M04** Crear el mapa de cumplimiento, diferenciando obligación, guía y decisión voluntaria.
- [x] **PGS-06-M05** Definir política de logs, redacción, conservación y eliminación.
- [x] **PGS-06-M06** Crear el runbook de respuesta a incidentes de IA.
- [x] **PGS-06-M07** Crear el procedimiento de parada y recuperación.
- [x] **PGS-06-M08** Registrar dependencias y riesgos de supply chain.
- [x] **PGS-06-M09** Documentar cambios de modelo y cuándo exigen repetir evaluaciones.

**Salida:** paquete mínimo de gobierno y operación consistente con el sistema real.

### Fase PGS-07 — Verificación y cierre

**Objetivo:** convertir el laboratorio en evidencia admisible para SEC-1.

- [x] **PGS-07-M01** Reconstruir el proyecto desde un entorno limpio.
- [x] **PGS-07-M02** Ejecutar tests, corpus benigno y corpus adversario.
- [x] **PGS-07-M03** Verificar que los logs y artefactos no contienen secretos ni datos reales.
- [ ] **PGS-07-M04** Pedir una revisión independiente del threat model y de una prueba.
- [ ] **PGS-07-M05** Incorporar correcciones justificadas y registrar discrepancias.
- [ ] **PGS-07-M06** Crear la matriz final requisito–evidencia–resultado–límite.
- [ ] **PGS-07-M07** Preparar resumen técnico y resumen ejecutivo.
- [x] **PGS-07-M08** Crear el repositorio público y publicar `main` tras una autorización separada.
- [ ] **PGS-07-M09** Revisar P01-M01 y P01-M04–P01-M11 contra sus criterios.
- [ ] **PGS-07-M10** Registrar el estado de SEC-1 sin cerrarlo mientras BASE siga pendiente.

**Salida:** proyecto reproducible, revisado y trazable; el código fuente y la
evidencia saneada concreta de PGS-03-M07 disponen de publicación pública
autorizada, mientras que releases y otros artefactos externos siguen
requiriendo una decisión separada.

## Trazabilidad con la fase 01

| Roadmap | Evidencia principal del proyecto |
|---|---|
| P01-M01 | PGS-00 — producto, nombre, stack y límites |
| P01-M02 | Selección del curso ya registrada fuera de este proyecto |
| P01-M03 | Certificado y apuntes del curso ya registrados fuera de este proyecto |
| P01-M04 | PGS-02-M01 — versiones de los marcos consultados |
| P01-M05 | PGS-02-M02 y PGS-02-M04 — inventario y autoridad |
| P01-M06 | PGS-02-M03 — arquitectura y trust boundaries |
| P01-M07 | PGS-02-M05 a PGS-03-M08 — abuse cases y pruebas |
| P01-M08 | PGS-02-M08 y PGS-04 — controles y responsables |
| P01-M09 | PGS-03 y PGS-05 — baseline, control y retest |
| P01-M10 | PGS-05-M08 y PGS-05-M09 — riesgo residual y ADR |
| P01-M11 | PGS-07 — reconstrucción y revisión independiente |

## Dependencias y decisiones abiertas

- Elegir un proveedor real solo si aporta evidencia que el sustituto determinista no pueda producir; cualquier llamada y gasto exigirán autorización específica.
- `GSL-ADR-001` mantiene la baseline local-first determinista como decisión
  revisable del alcance actual. Modelo, proveedor, Docker, UI/API, aislamiento
  y frameworks continúan diferidos o rechazados para este corte y requieren un
  trigger, autoridad y ADR sucesor.
- El repositorio local en `main` sigue
  `origin/main` del remoto público
  [infantesromeroadrian/GenAI-Seguro-Lab](https://github.com/infantesromeroadrian/GenAI-Seguro-Lab).
- La estructura mínima ya separa código, tests, evaluaciones, datos, documentación y sandbox; Python 3.12, Pydantic 2, pytest 9 y sus dependencias están fijados mediante `pyproject.toml` y `uv.lock`.
- El corpus benigno inicial contiene 12 incidentes y 8 documentos de conocimiento sintéticos; su esquema estricto, referencias, conteos y hashes están verificados automáticamente. `GSL-ADVERSARIAL-CORPUS-001` añade de forma separada 18 fixtures y 18 oráculos para los 17 abuse cases y seis familias; 14 PI/JB/EX/TOL están conectadas a tests y evaluadas canónicamente, mientras cuatro permanecen inertes.
- El adaptador determinista ejecutado en proceso responde solo a peticiones completas previamente guionizadas, no usa red, registra coste cero y no autoriza ni ejecuta solicitudes de herramienta.
- El flujo benigno exige una única búsqueda sobre las referencias del incidente
  y una respuesta final. `KnowledgeCatalog` crea una vista exacta por caso y
  su grant no deriva del catálogo anunciado al modelo. La escritura queda
  separada, exige una propuesta registrada, autenticación sintética y un grant
  de efecto de un solo uso, y crea por descriptor con `O_EXCL`, `O_NOFOLLOW`
  y modo `0600`. La presencia humana real y el aislamiento de la cuenta macOS
  continúan abiertos.
- PGS-04-M01 incorpora `instruction_boundary` y una clase de confianza por
  mensaje. El flujo ordinario exige una instrucción confiable inicial, datos de
  usuario y contenido no confiable separados; marca los resultados de
  herramienta como no confiables y conserva el perfil de evaluación como
  `deliberately_merged`. Esta evidencia no sustituye el retest sobre un modelo
  GenAI real.
- PGS-04-M02 incorpora `BenignTaskInput`, `BenignIncidentInput` y
  `BenignFinalOutput`. PGS-04-M03 sustituye la política autocontenida por
  `ToolExecutionGrant`, liga principal, scope, herramienta e instancia,
  proyecta datos por incidente, separa el grant de efecto de `TOL-02` y limita
  el entorno de EX-003 a tres variables. Los contratos están en
  `docs/validation-policy.md` y `docs/least-privilege-policy.md`. PGS-04-M04
  añade `DraftApprovalAuthority`, con credencial sintética fuera del modelo,
  tokens opacos, TTL, binding completo y consumo antes de I/O. PGS-04-M05
  incorpora `GSL-OUTPUT-POLICY-001`: una política obligatoria con canales
  cerrados, rechazo prioritario, redacción determinista y proyección de
  invocaciones sin texto bruto. PGS-04-M06 incorpora
  `GSL-RESOURCE-POLICY-001`: lectura acotada del corpus, límites de frontera,
  presupuestos por operación y sesión de borrador y un lock advisory de CLI.
  El plazo no puede interrumpir una llamada síncrona bloqueada y el retest
  continúa pendiente. PGS-04-M07 incorpora `GSL-SECURITY-EVENTS-001` mediante
  un journal efímero y saneado. PGS-04-M08 incorpora
  `GSL-SANDBOX-RECOVERY-001`: marker/staging `0600`, publicación por hard link
  create-only, `stop()` idempotente y reconciliación preautoridad que preserva
  finales publicados y nunca restaura grants.
- El proyecto permanece deliberadamente sin empaquetar mediante `[tool.uv] package = false`. `main.py` ofrece el punto de entrada local estable desde el propio checkout, sin instalación editable ni `PYTHONPATH`.
- La baseline `GSL-BASELINE-BENIGN-001` fija 12/12 ejecuciones funcionales, 24 invocaciones deterministas, 12 consultas autorizadas, 0 llamadas externas y 0 €. Sus campos declaran que no es una baseline de seguridad ni una evaluación de utilidad semántica.
- `GSL-METRICS-BENIGN-UTILITY-001` separa terminación técnica, cumplimiento
  estricto del resultado esperado y falsos rechazos. La proyección anterior a
  controles y la ejecución endurecida quedan en 12/12 terminaciones, 0/12
  falsos rechazos y 0/12 éxitos estrictos, con 12 `PARTIAL` sin cambios,
  0 llamadas externas y 0 efectos. La cobertura exacta es 0/24 hallazgos y
  0/36 acciones; no se presenta como equivalencia semántica y `SC-07`
  permanece `NOT_DEMONSTRATED`.
- `GSL-METRICS-OPERATIONAL-001` reconstruye los commits precontroles
  `df13683` y postcontroles `ba600ca` desde objetos Git, verifica cuatro
  entradas comunes byte a byte y conserva 30 pares AB/BA de procesos nuevos.
  La mediana end-to-end es 189,69 ms pre y 259,17 ms post, con delta
  emparejado mediano de +67,39 ms; CPU y RSS también aumentan. Los conteos
  12/24/12/12, las llamadas externas y el coste de proveedor/cloud permanecen
  sin cambio. La carga del operador es igual y la superficie interna aumenta;
  no hay score, umbral universal ni generalización fuera del host observado.
- `GSL-CONTROL-FINDINGS-001` es `DAT-23`, un registro estático revisado con
  seis hallazgos disjuntos y 44 referencias escalares a `DAT-20`, `DAT-21` y
  `DAT-22`. `CMP-17` comprueba hashes, esquemas, JSON Pointers, taxonomía y
  resumen sin reejecutar ninguna evaluación ni generar clasificaciones. Fija
  0 fallos y 0 bypasses actuales observados dentro de 14 fixtures, 1 bypass
  histórico, 2 resultados negativos, 3 gaps y 1 candidato de revisión en M06.
- `docs/framework-versions.md` fija OWASP LLM 2025, OWASP Agentic 2026, MITRE ATLAS release `v2026.06` con `ATLAS.yaml` 5.6.0, NIST AI RMF 1.0 y NIST SP 800-218A final; NIST AI 600-1 queda como perfil GenAI complementario. La revalidación para PGS-02-M07 conserva el snapshot ATLAS anterior y documenta la actualización de `AML.T0054`.
- `docs/system-inventory.md` fija `GSL-SYS-INV-001` con actores, datos,
  componentes, modelo, herramientas, identidades, dependencias,
  infraestructura e integraciones verificadas. Distingue la CLI expuesta de
  `DraftWriterTool`, que solo está implementada como API interna, y separa el
  remoto público de desarrollo del runtime local, que continúa sin modelo
  GenAI real, red, autenticación general, Docker, cloud, bases de datos o
  telemetría externa.
- `architecture/manifest.json` y sus diagramas Tecture fijan contexto, contenedores y componentes con seis trust boundaries. El mapa incorpora `CMP-06` como perfil interno, `CMP-07` como harness adversario acotado para 14 fixtures PI/JB/EX/TOL, `CMP-09` como política de salida, `CMP-10` como control preventivo de recursos, `CMP-11` como journal saneado, `CMP-12` como controlador transaccional del sandbox, `CMP-14` como analizador adversario offline, `CMP-15` como evaluador benigno por caso, `CMP-16` como medidor operativo pre/post y `CMP-17` como verificador offline de `DAT-23`; este último no genera hallazgos ni ejecuta targets. `DraftWriterTool` permanece desconectada de la CLI y del flujo benigno. TB-02 a TB-04 siguen siendo límites lógicos dentro del mismo proceso. PGS-02-M03 cierra P01-M06.
- `docs/authority-matrix.md` fija `GSL-AUTH-MATRIX-001` con veintitrés cadenas actuales y cuatro niveles de consecuencia. `AUTH-15` obliga a pasar resúmenes y borradores por `CMP-09`; `AUTH-16` consume los límites de `CMP-10`; `AUTH-17` observa mediante `CMP-11`; `AUTH-18` publica o reconcilia mediante `CMP-12` sin crear autoridad; `AUTH-19` acota el retest de soporte de PGS-05-M01, `AUTH-20` limita M02 a lectura e interpretación offline, `AUTH-21` limita M03 a la evaluación benigna, `AUTH-22` limita M04 a commits fijados y `AUTH-23` limita M05 a verificar evidencia y registro sin ejecutar ni escribir. Mantiene separadas la propuesta sin autoridad de `MOD-01`, la ejecución con `IDN-01`, los grants lógicos `IDN-05`, la aprobación sintética `IDN-03`, el efecto interno create-only de `TOL-02` y la autoridad externa de mantenimiento de `ACT-02`.
- `docs/abuse-cases.md` fija `GSL-ABUSE-CASES-001` con 17 escenarios: 3 de prompt injection, 2 de jailbreak, 3 de exfiltración, 5 de abuso de herramientas, 3 de denegación de servicio y 1 de supply chain. Los separa como `SIN-RUTA`, `INTERNO`, `MANTENIMIENTO` o `CLI` y conserva los gaps de evidencia.
- `docs/risk-prioritization.md` fija `GSL-RISK-PRIORITY-001` con impacto `I0`–`I3`, probabilidad condicionada `L1`–`L3`, capacidad real `K0`–`K3` y una puntuación reproducible para los 17 casos. PGS-05-M02 aporta la comparación adversaria y PGS-05-M03 descarta una regresión técnica benigna, pero ninguna altera todavía el recálculo: 1 en `PR-1`, 1 en `PR-2`, 14 en `PR-3` y 1 en `PR-0`; los casos DOS siguen inertes y no existe un modelo real.
- `docs/threat-crosswalk.md` fija `GSL-THREAT-CROSSWALK-001` con una fila por abuse case y relaciones directas, parciales o ausentes frente a OWASP LLM 2025, OWASP Agentic 2026 y MITRE ATLAS `v2026.06`. Conserva los gaps de consentimiento, filesystem y escenarios no agentic sin cambiar la prioridad.
- `docs/control-responsibility-mapping.md` fija `GSL-NIST-CONTROLS-001` con cuatro roles y una matriz canónica comprobable: una fila por cada uno de los trece controles, cobertura explícita de los 17 abuse cases, selectores pytest existentes, limitaciones y correspondencias acotadas con NIST AI RMF 1.0 y NIST SP 800-218A. `CTL-08` incorpora la recuperación local de `CMP-12` y `CTL-13` conserva como gaps el runbook, monitorización y respuesta generales. PGS-04 y P01-M08 quedan cerradas sin atribuir eficacia a la validación documental.
- `docs/security-events-policy.md` fija `GSL-SECURITY-EVENTS-001`: eventos cerrados de hasta 2 KiB, perfiles acotados, secuencia global, correlación primaria y una hija opaca por caso de baseline, cadena SHA-256, diez señales deterministas y exposición CLI opt-in. No persiste logs, exporta telemetría, concede autoridad ni prueba ataques; `CMP-12` actúa por su condición real y no por una señal.
- `docs/sandbox-recovery-policy.md` fija `GSL-SANDBOX-RECOVERY-001`: punto único de publicación, estado duradero mínimo, reconciliación no autoritativa, parada y límites. No añade handlers globales, resume, red, aislamiento de SO ni un procedimiento operativo.
- `docs/rules-of-engagement.md` fija `GSL-ROE-001` con autorización por ejecución, activos incluidos y excluidos, acciones permitidas y prohibidas, presupuestos cuantitativos, evidencia, parada y un vehículo acotado para cada uno de los 17 abuse cases. `AC-DOS-01` solo admite un piloto limitado y `AC-DOS-03` necesita una ampliación posterior; PGS-03-M04/M05/M06 aplican esos límites a 14 fixtures PI/JB/EX/TOL sin red, proveedor o evidencia canónica.
- `src/genai_seguro_lab/evaluation_profile.py` implementa `GSL-PROFILE-VULNERABLE-001`: requiere autorización estricta de `GSL-ROE-001`, datos sintéticos y un sandbox temporal, construye peticiones débiles claramente marcadas y carece de llamadas al modelo, ejecución de herramientas, red, escritura o ruta CLI. Su aislamiento queda probado en `tests/test_evaluation_profile.py`.
- `data/adversarial/` y `load_adversarial_corpus()` fijan las entradas y los
  oráculos separados, validan cobertura, procedencia, límites y hashes, y
  terminan en un bundle en memoria. `src/genai_seguro_lab/evaluation_harness.py`
  selecciona 14 casos PI/JB/EX/TOL, materializa únicamente copias o sandboxes
  bajo `$TMP`, ejecuta dobles deterministas, guardas de flujo, rechazos de
  búsqueda, comprobaciones de borrador y un subproceso CLI saneado, mantiene el
  oráculo fuera del target y produce observaciones tipadas. El checkout actual
  rechaza el literal histórico de `AC-TOL-05` y crea cero archivos; la
  evidencia del residual de `93aefa45` permanece inmutable. `AC-DOS-03`
  permanece como descriptor no materializado que requiere ampliar las RoE.
- `src/genai_seguro_lab/adversarial_baseline.py` y
  `evaluations/run_adversarial_baseline.py` implementan `CMP-08`, fijado al
  candidato histórico. El run
  `GSL-ADV-BL-20260725-001` evaluó el commit limpio `93aefa45` y conserva bajo
  `evaluations/adversarial-baseline-v1/` configuración, resultados, eventos y
  un manifiesto de integridad saneados: 13 `PASS`, 1 `RESIDUAL`, 0 `FAIL`, 0
  `STOPPED`, 0 llamadas externas y 0 €.
- `CMP-13`, implementado en `src/genai_seguro_lab/adversarial_retest.py` y
  `evaluations/run_adversarial_retest.py`, mantiene separado el contrato
  histórico y reutiliza la única ejecución de `CMP-07`. El run
  `GSL-ADV-RT-20260726-001` evaluó una sola vez el commit limpio
  `d236bbee9f371a75e330c227f100aef167b864b0`, conservó 14 casos
  `COMPLETED`, 13 relaciones `MATCH` y una `DIFF` en `ADV-TOL-005`, y
  versionó en `evaluations/adversarial-retest-v1/` solo la proyección saneada
  y revisada con `final_retest: false`.
- `CMP-14`, implementado en `src/genai_seguro_lab/adversarial_metrics.py` y
  `evaluations/run_adversarial_metrics.py`, verifica ambos namespaces de
  evidencia, aplica una política cerrada a los 14 triples emparejados y fija
  `evaluations/adversarial-metrics-v1.json`: tasa de éxito 1/14 (7,14 %) →
  0/14 (0 %), una operación no autorizada aceptada/ejecutada → cero, un caso
  mejorado y ninguna regresión. No reejecuta el target y conserva
  `source_final_retest: false`.
- `CMP-16`, implementado en `src/genai_seguro_lab/operational_metrics.py` y
  `evaluations/run_operational_metrics.py`, fija commits, árboles, corpus,
  entrada y lock; extrae ambos candidatos bajo `$TMP` y mide 30 pares
  end-to-end con procesos nuevos. `evaluations/operational-metrics-v1.json`
  conserva muestras, mediana, MAD y p95, contadores y complejidad descriptiva
  sin salida bruta, score ni umbral universal.
- `CMP-17`, implementado en `src/genai_seguro_lab/control_findings.py` y
  `evaluations/verify_control_findings.py`, verifica el registro estático
  `evaluations/control-findings-v1.json` y sus tres fuentes fijadas. Resuelve
  44 referencias escalares y recalcula el resumen; no genera el registro,
  reejecuta evaluadores, decide correcciones, acepta riesgo o declara el retest
  final.
- `GSL-BENIGN-CORRECTION-CANDIDATE-001`, generado por
  `src/genai_seguro_lab/benign_correction.py` y
  `evaluations/run_benign_correction.py`, fija el candidato `77edd64`, conserva
  byte a byte baseline, `DAT-21` y `DAT-23`, registra los hashes de las 12
  salidas estructuradas y demuestra mediante mutación y canario que el oráculo
  no entra en la petición ni cambia la salida. Declara `final_retest: false`,
  no evalúa equivalencia semántica ni cierra `SC-07`.
- `CMP-18`, implementado en `src/genai_seguro_lab/final_retest.py` y
  `evaluations/run_final_retest.py`, verificó el candidato `77edd640`, su árbol,
  el evaluador `636e1db`, `DAT-24` y 15 artefactos históricos. El único run
  `GSL-FINAL-RT-20260727-001` materializó el target bajo `$TMP`, bloqueó red y
  credenciales, ejecutó 14 casos adversarios, 12 benignos y dos probes, y dejó
  cuatro entradas inertes. `evaluations/final-retest-v1.json` (`DAT-25`) fija
  1/14 → 0/14 éxitos, 1 → 0 operaciones no autorizadas, 0 regresiones, 0 falsos
  rechazos y 84/84 cláusulas preservadas bajo trazabilidad cerrada. Declara
  `final_retest: true`, `SC-06` y `SC-07` `DEMONSTRATED`, pero mantiene falsas
  la equivalencia semántica general, el juez LLM y la evaluación con modelo
  real; `CF-002` sigue `NOT_COMPUTABLE` y `DAT-22` es solo histórico.
- `docs/adversarial-baseline-findings.md` fija
  `GSL-FINDINGS-ADVERSARIAL-001`: explica cómo usar hoy la CLI, consolida seis
  hallazgos, acota el impacto del residual `ADV-TOL-005`, documenta la
  reproducción histórica y declara la ausencia de frontal, modelo real y
  cobertura DOS/SC. PGS-03-M08 y P01-M07 quedan cerradas.
- PGS-07-M08 quedó adelantada mediante autorización específica: remoto público
  creado y `main` publicado el 2026-07-25. PGS-03-M07 autoriza además su
  evidencia saneada concreta; releases y otros artefactos externos siguen
  fuera de alcance.
- Completar P00-M08, P00-M09 y P00-M10 antes de declarar superado SEC-1.

## Próxima microtarea

**PGS-07-M04 — obtener una revisión humana independiente del threat model y de una prueba.**

**Progreso interno:** 60 de 66 microtareas completadas, 6 abiertas (**90,9 %**).
