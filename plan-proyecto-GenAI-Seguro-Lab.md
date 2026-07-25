# Plan del proyecto — GenAI Seguro Lab

## Estado

- **Proyecto:** GenAI Seguro Lab.
- **Nombre de carpeta confirmado:** `GenAI-Seguro-Lab`.
- **Ruta local confirmada:** `/Users/adrianinfantes/Desktop/AIR/Carreer/AI-Security-Architec/Portfolio/GenAI-Seguro-Lab`.
- **Roadmap padre:** fase 01 — Fundamentos de AI Security.
- **Microtareas padre completadas:** P01-M01, P01-M04, P01-M05 y P01-M06.
- **Estado actual:** PGS-00-M01 a PGS-00-M06, PGS-01-M01 a PGS-01-M07, PGS-02-M01 a PGS-02-M08 y PGS-03-M01 completadas; el esqueleto reproducible, la arquitectura, el threat model, los responsables, el mapa de controles NIST y las Rules of Engagement ya están fijados.
- **Línea seleccionada:** B — aplicación GenAI protegida frente a prompt injection, jailbreak y abuso de herramientas.
- **Entorno previsto:** local-first, con un corpus operativo exclusivamente sintético.
- **Publicación, cloud y gasto:** fuera de alcance hasta una autorización específica.

## Objetivo

Construir desde cero una aplicación GenAI pequeña y reproducible que permita demostrar el ciclo:

`baseline vulnerable → ataque controlado → control de seguridad → retest → métricas → riesgo residual`

El resultado debe producir evidencia verificable de que Adrián puede:

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

Esta definición fue aprobada por Adrián al completar **PGS-00-M01** el 25 de julio de 2026. Las capacidades quedaron fijadas en PGS-00-M02 y el stack, la estrategia de modelo y el presupuesto en PGS-00-M04.

## Capacidades y autoridad aprobadas

- **Analizar incidente:** operación sin efecto externo sobre un incidente sintético seleccionado.
- **Consultar conocimiento:** lectura limitada a la base sintética autorizada.
- **Proponer actuación:** recomendación sin capacidad de ejecución.
- **Crear borrador:** creación de un archivo nuevo únicamente en `sandbox/drafts/`, tras confirmación humana explícita vinculada al contenido exacto.
- **Autoridad:** el modelo solicita; la política valida; solo el usuario autoriza una escritura.
- **Denegación por defecto:** no se permiten otras herramientas, red, shell, secretos, datos reales, modificación, sobrescritura o borrado.
- **Perfil vulnerable:** accesible solo desde el harness aislado de evaluación.

El contrato completo está documentado en [README.md](./README.md#capacidades-y-autoridad-aprobadas). Los límites numéricos de recursos se fijarán antes de la baseline en PGS-04-M06.

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
8. **Sin secretos en el repositorio:** credenciales y datos sensibles quedarán fuera del código y de los logs.

## Stack, modelo y presupuesto aprobados

La selección quedó cerrada en **PGS-00-M04**:

| Área | Decisión |
|---|---|
| Runtime | Python 3.12, restringido a `>=3.12,<3.13` |
| Gestión del proyecto | `uv`, con `pyproject.toml`, `.python-version` y `uv.lock` |
| Validación | Pydantic 2, en modo estricto y rechazando campos adicionales no declarados |
| Pruebas | pytest 9, con fixtures y casos parametrizados |
| Núcleo | Librería estándar para CLI, rutas, JSON/JSONL y logging |
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
- No habrá `push` hasta crear un remoto y recibir autorización específica.

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
- [ ] **PGS-03-M02** Crear un perfil vulnerable aislado y exclusivo para evaluación.
- [ ] **PGS-03-M03** Preparar el corpus adversario con entradas y resultados esperados.
- [ ] **PGS-03-M04** Implementar pruebas para prompt injection directa e indirecta.
- [ ] **PGS-03-M05** Implementar pruebas para jailbreak y revelación de información.
- [ ] **PGS-03-M06** Implementar pruebas para llamadas de herramienta no autorizadas y exceso de agencia.
- [ ] **PGS-03-M07** Ejecutar la baseline y conservar configuración, resultados y logs saneados.
- [ ] **PGS-03-M08** Documentar hallazgos, impacto, reproducción y límites.

**Salida:** al menos un fallo reproducible y medido contra una baseline fija.

### Fase PGS-04 — Controles de seguridad

**Objetivo:** aplicar controles trazables a amenazas concretas.

- [ ] **PGS-04-M01** Separar instrucciones de sistema, contenido no confiable y datos de usuario.
- [ ] **PGS-04-M02** Validar entradas, salidas y argumentos de herramientas mediante esquemas y allowlists.
- [ ] **PGS-04-M03** Aplicar mínimo privilegio a identidades, datos y herramientas.
- [ ] **PGS-04-M04** Exigir confirmación humana para acciones con efecto.
- [ ] **PGS-04-M05** Incorporar filtros, redacción de datos y política de salida.
- [ ] **PGS-04-M06** Añadir límites de tamaño, tiempo, iteraciones y consumo.
- [ ] **PGS-04-M07** Añadir eventos de seguridad, correlación y señales de comportamiento anómalo.
- [ ] **PGS-04-M08** Implementar parada segura y recuperación del estado del sandbox.
- [ ] **PGS-04-M09** Asociar cada control a amenaza, responsable, prueba y limitación.

**Salida:** versión endurecida con controles independientes y observables.

### Fase PGS-05 — Retest y medición

**Objetivo:** comprobar la mejora sin ocultar regresiones de utilidad.

- [ ] **PGS-05-M01** Repetir exactamente el corpus adversario de la baseline.
- [ ] **PGS-05-M02** Medir tasa de éxito del ataque y llamadas no autorizadas antes y después.
- [ ] **PGS-05-M03** Repetir el corpus benigno y medir éxito de tarea y falsos rechazos.
- [ ] **PGS-05-M04** Comparar latencia, consumo y complejidad operativa.
- [ ] **PGS-05-M05** Registrar controles fallidos, bypasses y resultados negativos.
- [ ] **PGS-05-M06** Corregir únicamente defectos demostrados dentro del alcance.
- [ ] **PGS-05-M07** Ejecutar el retest final y fijar los resultados.
- [ ] **PGS-05-M08** Documentar riesgo residual y compensaciones entre seguridad y utilidad.
- [ ] **PGS-05-M09** Redactar el ADR de la solución seleccionada, alternativas y rollback.

**Salida:** informe comparativo baseline/control/retest con métricas reproducibles.

### Fase PGS-06 — Gobierno y operación

**Objetivo:** hacer que la seguridad sea mantenible y explicable.

- [ ] **PGS-06-M01** Crear system card, data card y model card.
- [ ] **PGS-06-M02** Completar la evaluación de impacto de IA.
- [ ] **PGS-06-M03** Crear RACI y registro de riesgos.
- [ ] **PGS-06-M04** Crear el mapa de cumplimiento, diferenciando obligación, guía y decisión voluntaria.
- [ ] **PGS-06-M05** Definir política de logs, redacción, conservación y eliminación.
- [ ] **PGS-06-M06** Crear el runbook de respuesta a incidentes de IA.
- [ ] **PGS-06-M07** Crear el procedimiento de parada y recuperación.
- [ ] **PGS-06-M08** Registrar dependencias y riesgos de supply chain.
- [ ] **PGS-06-M09** Documentar cambios de modelo y cuándo exigen repetir evaluaciones.

**Salida:** paquete mínimo de gobierno y operación consistente con el sistema real.

### Fase PGS-07 — Verificación y cierre

**Objetivo:** convertir el laboratorio en evidencia admisible para SEC-1.

- [ ] **PGS-07-M01** Reconstruir el proyecto desde un entorno limpio.
- [ ] **PGS-07-M02** Ejecutar tests, corpus benigno y corpus adversario.
- [ ] **PGS-07-M03** Verificar que los logs y artefactos no contienen secretos ni datos reales.
- [ ] **PGS-07-M04** Pedir una revisión independiente del threat model y de una prueba.
- [ ] **PGS-07-M05** Incorporar correcciones justificadas y registrar discrepancias.
- [ ] **PGS-07-M06** Crear la matriz final requisito–evidencia–resultado–límite.
- [ ] **PGS-07-M07** Preparar resumen técnico y resumen ejecutivo.
- [ ] **PGS-07-M08** Decidir separadamente si se crea o publica el repositorio remoto.
- [ ] **PGS-07-M09** Revisar P01-M01 y P01-M04–P01-M11 contra sus criterios.
- [ ] **PGS-07-M10** Registrar el estado de SEC-1 sin cerrarlo mientras BASE siga pendiente.

**Salida:** proyecto reproducible, revisado y trazable; publicación externa solo si se autoriza.

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
- El repositorio local ya está inicializado sobre `main`; no existe ningún remoto configurado.
- La estructura mínima ya separa código, tests, evaluaciones, datos, documentación y sandbox; Python 3.12, Pydantic 2, pytest 9 y sus dependencias están fijados mediante `pyproject.toml` y `uv.lock`.
- El corpus benigno inicial contiene 12 incidentes y 8 documentos de conocimiento sintéticos; su esquema estricto, referencias, conteos y hashes están verificados automáticamente. Los casos adversarios siguen fuera de alcance hasta PGS-03.
- El adaptador determinista ejecutado en proceso responde solo a peticiones completas previamente guionizadas, no usa red, registra coste cero y no autoriza ni ejecuta solicitudes de herramienta.
- El flujo benigno exige una única búsqueda sobre las referencias del incidente y una respuesta final. La búsqueda solo usa conocimiento sintético cargado en memoria; la escritura de borradores queda separada del modelo, requiere una confirmación declarada por el llamador y ligada a la huella exacta de la propuesta, y aplica creación exclusiva dentro de `sandbox/drafts/`. Esta capa todavía no autentica la identidad humana.
- El proyecto permanece deliberadamente sin empaquetar mediante `[tool.uv] package = false`. `main.py` ofrece el punto de entrada local estable desde el propio checkout, sin instalación editable ni `PYTHONPATH`.
- La baseline `GSL-BASELINE-BENIGN-001` fija 12/12 ejecuciones funcionales, 24 invocaciones deterministas, 12 consultas autorizadas, 0 llamadas externas y 0 €. Sus campos declaran que no es una baseline de seguridad ni una evaluación de utilidad semántica.
- `docs/framework-versions.md` fija OWASP LLM 2025, OWASP Agentic 2026, MITRE ATLAS release `v2026.06` con `ATLAS.yaml` 5.6.0, NIST AI RMF 1.0 y NIST SP 800-218A final; NIST AI 600-1 queda como perfil GenAI complementario. La revalidación para PGS-02-M07 conserva el snapshot ATLAS anterior y documenta la actualización de `AML.T0054`.
- `docs/system-inventory.md` fija `GSL-SYS-INV-001` con actores, datos, componentes, modelo, herramientas, identidades, dependencias, infraestructura e integraciones verificadas. Distingue la CLI expuesta de `DraftWriterTool`, que solo está implementada como API interna, y confirma la ausencia actual de modelo GenAI real, red, autenticación, Docker, cloud, bases de datos, telemetría y remoto Git.
- `architecture/manifest.json` y sus diagramas Tecture fijan contexto, contenedores y componentes con 20 nodos y seis trust boundaries. No inventan integraciones externas; `DraftWriterTool` permanece desconectada en L3 y TB-02 a TB-04 se declaran límites lógicos dentro del mismo proceso. PGS-02-M03 cierra P01-M06.
- `docs/authority-matrix.md` fija `GSL-AUTH-MATRIX-001` con nueve cadenas actuales, cuatro niveles de consecuencia y siete rutas ausentes. Separa la propuesta sin autoridad de `MOD-01`, la ejecución con `IDN-01`, el efecto interno create-only de `TOL-02` y la autoridad externa de mantenimiento de `ACT-02`. PGS-02-M04 completa el inventario de autoridad y cierra P01-M05.
- `docs/abuse-cases.md` fija `GSL-ABUSE-CASES-001` con 17 escenarios: 3 de prompt injection, 2 de jailbreak, 3 de exfiltración, 5 de abuso de herramientas, 3 de denegación de servicio y 1 de supply chain. Los separa como `SIN-RUTA`, `INTERNO`, `MANTENIMIENTO` o `CLI` y conserva los gaps de evidencia.
- `docs/risk-prioritization.md` fija `GSL-RISK-PRIORITY-001` con impacto `I0`–`I3`, probabilidad condicionada `L1`–`L3`, capacidad real `K0`–`K3` y una puntuación reproducible para los 17 casos. Sitúa 2 en `PR-1`, 3 en `PR-2`, 11 en `PR-3` y 1 en `PR-0`; PGS-02-M06 avanza P01-M07, que permanece abierta.
- `docs/threat-crosswalk.md` fija `GSL-THREAT-CROSSWALK-001` con una fila por abuse case y relaciones directas, parciales o ausentes frente a OWASP LLM 2025, OWASP Agentic 2026 y MITRE ATLAS `v2026.06`. Conserva los gaps de consentimiento, filesystem y escenarios no agentic sin cambiar la prioridad; PGS-02-M07 avanza P01-M07, que permanece abierta.
- `docs/control-responsibility-mapping.md` fija `GSL-NIST-CONTROLS-001` con cuatro roles, trece controles en estado presente, parcial o planificado, cobertura de los 17 abuse cases y correspondencias acotadas con NIST AI RMF 1.0 y NIST SP 800-218A. Declara la concentración de responsabilidad en `ACT-02`, la falta de autenticación de `ACT-03`, el futuro `REV-01` sin asignar y los límites de alcance del perfil; PGS-02-M08 avanza P01-M08, que permanece abierta hasta implementar PGS-04.
- `docs/rules-of-engagement.md` fija `GSL-ROE-001` con autorización por ejecución, activos incluidos y excluidos, acciones permitidas y prohibidas, presupuestos cuantitativos, evidencia, parada y un vehículo acotado para cada uno de los 17 abuse cases. `AC-DOS-01` solo admite un piloto limitado y `AC-DOS-03` necesita una ampliación posterior; PGS-03-M01 no ejecutó ataques.
- Decidir GitHub, remoto, visibilidad y primer `push` únicamente en PGS-07-M08 o mediante una autorización específica posterior.
- Completar P00-M08, P00-M09 y P00-M10 antes de declarar superado SEC-1.

## Próxima microtarea

**PGS-03-M02 — crear un perfil vulnerable aislado y exclusivo para evaluación.**

**Progreso interno:** 22 de 66 microtareas completadas, 44 abiertas (**33,3 %**).
