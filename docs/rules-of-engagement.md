# Rules of Engagement del laboratorio

## Ficha de las reglas

| Campo | Valor |
|---|---|
| Identificador | `GSL-ROE-001` |
| Versión | `1.0.0` |
| Fecha de entrada en vigor | 2026-07-25 |
| Baseline técnica de origen | commit `f6469fce93e86a4fef5396065c2970552e2e47a9` |
| Propietario | `ACT-02` — mantenedor y ejecutor de pruebas |
| Operador | `ACT-01` — operador local |
| Catálogo de origen | [`GSL-ABUSE-CASES-001`](./abuse-cases.md) |
| Priorización de origen | [`GSL-RISK-PRIORITY-001`](./risk-prioritization.md) |
| Ámbito | checkout local propio, datos sintéticos y procesos aislados de evaluación |

Estas Rules of Engagement (RoE) delimitan cómo se podrán preparar y ejecutar
las evaluaciones adversarias de GenAI Seguro Lab. No son una autorización
permanente para atacar: cada ejecución debe estar cubierta por una petición
vigente que identifique los casos, el perfil, el candidato y los límites.

PGS-03-M01 autoriza únicamente la creación de estas reglas y las comprobaciones
ordinarias del repositorio. En esta microtarea no se crea el perfil vulnerable,
no se añade corpus adversario y no se ejecuta ningún caso de ataque.

## Objetivo y resultado permitido

El único objetivo autorizado es producir evidencia educativa y defensiva sobre
el comportamiento del laboratorio propio:

```text
candidato identificado
  → caso sintético autorizado
  → ejecución acotada
  → observación saneada
  → parada o resultado
  → evidencia reproducible
```

Un resultado puede demostrar rechazo, aceptación, fallo o riesgo residual. No
se reinterpretará un bloqueo como seguridad total ni un fallo como permiso
para ampliar el alcance.

## Autoridad y responsabilidades

- `ACT-02` define el candidato, selecciona los casos, fija cualquier excepción
  y responde por los cambios, la evidencia y el tratamiento del riesgo.
- `ACT-01` ejecuta solo el plan autorizado, vigila los límites y detiene la
  prueba ante cualquier condición de parada.
- `ACT-03` solo puede confirmar una propuesta exacta de borrador. Esta función
  no autoriza una campaña ni acredita todavía la identidad de una persona.
- `REV-01` permanece planificado para la revisión independiente de PGS-07. Su
  ausencia no se presentará como una revisión independiente ya realizada.
- El modelo y sus salidas nunca autorizan una herramienta, una ampliación del
  alcance, una excepción ni una repetición.

Un `GO` del usuario solo cubre el plan, los targets y las mutaciones que se
hayan expuesto para la microtarea vigente. Un documento anterior, un resultado
del modelo o el estado de una nota no reanudan ni amplían esa autoridad.

## Alcance autorizado

### Activos incluidos

- El repositorio local
  `/Users/adrianinfantes/Desktop/AIR/Carreer/AI-Security-Architec/Portfolio/GenAI-Seguro-Lab`
  para lectura, build, tests y cambios deliberados de desarrollo.
- El código, la CLI, el adaptador determinista, las herramientas internas y el
  futuro perfil vulnerable creado expresamente en PGS-03-M02.
- El corpus benigno actual y el futuro corpus adversario 100 % sintético de
  PGS-03-M03.
- Directorios temporales específicos de la ejecución, creados por pytest o por
  el sistema operativo, para corpus alterados, sandboxes y copias desechables.
- `evaluations/` únicamente para evidencia saneada y revisada antes de
  versionarla.
- Procesos locales hijos iniciados expresamente por el harness dentro de los
  límites de este documento.

### Activos excluidos

- Cualquier cuenta, modelo, API, sitio, repositorio, dispositivo o sistema de
  terceros.
- Otros proyectos de AIR, el vault de Obsidian, iCloud como servicio y
  cualquier ruta personal ajena al repositorio o al directorio temporal
  específico de la ejecución.
- Datos personales, corporativos, confidenciales, credenciales, secretos,
  incidentes reales o material de procedencia no verificada.
- GitHub, remotos Git, CI/CD, cloud, Docker, proveedores GenAI y cualquier
  endpoint de red, incluido `localhost`, hasta una autorización posterior que
  actualice estas reglas.
- El host macOS como objetivo: sus controles, permisos, procesos ajenos,
  persistencia, llavero, configuración y disponibilidad global quedan fuera.

## Acciones permitidas

- Leer, validar y hashear los activos incluidos.
- Ejecutar tests y comandos documentados de la CLI contra datos sintéticos.
- Sustituir respuestas del modelo mediante dobles deterministas dentro del
  proceso de test.
- Preparar entradas adversarias no ejecutables y observar las decisiones,
  errores, llamadas propuestas y efectos confinados.
- Modificar corpus, manifiestos, código o lockfiles únicamente en una copia
  temporal desechable cuando el caso requiera simular corrupción o supply
  chain.
- Crear como máximo los borradores sintéticos permitidos por el presupuesto,
  siempre en un sandbox temporal propio de la ejecución.
- Registrar métricas, hashes, resultados y logs saneados.

## Acciones prohibidas

- Conectar a red, proveedor, servicio externo o endpoint no autorizado.
- Usar datos reales, secretos o malware; ejecutar payloads, shell, código
  generado, persistencia, escalada de privilegios o evasión de controles del
  host.
- Probar contra terceros o usar el laboratorio para phishing, fraude,
  vigilancia, desinformación o decisiones reales.
- Escribir, sobrescribir o borrar fuera del sandbox temporal; modificar de
  forma adversaria el checkout canónico; reescribir historial Git o publicar.
- Seguir enlaces simbólicos fuera del directorio temporal, montar volúmenes o
  conceder permisos adicionales al proceso.
- Ejecutar fuzzing, stress, soak o carga sin un plan y unos límites nuevos
  expresamente autorizados.
- Mantener bucles, reintentos, procesos en segundo plano o continuaciones
  automáticas después de la prueba.
- Ocultar una desviación, editar el oráculo después de conocer el resultado o
  presentar un artefacto temporal como evidencia canónica.

## Precondiciones de cada ejecución

Antes de una ejecución que vaya a producir evidencia, el registro del run debe
contener:

1. identificador único y fecha/hora UTC;
2. petición vigente que cubre los casos seleccionados;
3. commit exacto y estado limpio del candidato canónico;
4. perfil y configuración, con sus hashes;
5. lista de `AC-*`, entradas sintéticas y oráculos previos al resultado;
6. comandos y componentes permitidos;
7. directorio temporal y sandbox exactos;
8. presupuesto aplicable y condiciones de parada;
9. evidencia que se conservará y regla de saneado;
10. procedimiento de limpieza y responsable de comunicar una anomalía.

Una ejecución de desarrollo sobre cambios todavía no confirmados puede servir
para depurar, pero debe fijar el diff observado y no cuenta como baseline
canónica. La baseline de PGS-03-M07 y los retests sí deben utilizar un commit
exacto con el checkout limpio.

PGS-03-M02 y PGS-03-M03 son precondiciones para ejecutar el corpus adversario.
Hasta completarlas, los 17 casos permanecen catalogados y no ejecutables como
campaña.

## Presupuesto operativo de seguridad

Estos topes protegen el host durante la evaluación; no son objetivos de
rendimiento ni controles del producto.

| Recurso | Límite por defecto |
|---|---:|
| Procesos objetivo simultáneos | 1 |
| Ejecuciones por caso | 1 |
| Casos por run | 36 |
| Tiempo por caso | 15 segundos |
| Tiempo total por run | 10 minutos |
| Turnos de modelo por caso | 4 |
| Solicitudes de herramienta por caso | 2 |
| Tamaño de una entrada adversaria | 64 KiB |
| Datos de entrada acumulados por run | 10 MiB |
| Archivos creados por caso | 1 |
| Archivos creados por run | 36 |
| Escritura temporal y evidencia bruta acumuladas | 25 MiB |
| RSS agregado de los procesos objetivo | 512 MiB |

El presupuesto especial de `AC-DOS-01` sustituye solo los límites de procesos,
invocaciones y tiempo:

- máximo 2 procesos simultáneos;
- máximo 20 invocaciones totales;
- máximo 60 segundos de ejecución;
- RSS agregado máximo de 512 MiB;
- sin afirmar resistencia a carga: el objetivo es observar si dos procesos
  ordinarios carecen de coordinación o cuota, no degradar el Mac.

`AC-DOS-03` queda fuera del presupuesto base porque exige un corpus
deliberadamente grande. Necesita una ampliación específica de estas RoE después
de que PGS-04-M06 implemente límites de recursos. Ninguna otra prueba puede
elevar estos topes por analogía.

## Condiciones de parada

`ACT-01` debe detener inmediatamente los procesos objetivo si ocurre cualquiera
de estas condiciones:

- aparece tráfico de red o un intento de resolver o conectar a un endpoint;
- se detectan datos no sintéticos, secretos o una ruta fuera de alcance;
- existe una escritura fuera del sandbox temporal o cambia el checkout
  canónico de forma inesperada;
- se propone o ejecuta una herramienta, payload o privilegio no previsto;
- se alcanza cualquier límite de tiempo, concurrencia, memoria, tamaño o
  número de archivos;
- el host muestra inestabilidad, presión de memoria no normal o interfiere con
  procesos ajenos;
- el resultado ya no puede asociarse al candidato, caso u oráculo fijados;
- el usuario interrumpe o retira la autorización.

La parada se limita a los PID hijos conocidos: primero terminación ordenada y,
solo si no responden, finalización forzada de esos PID concretos. No se usan
patrones amplios de procesos. Después se registra `STOPPED`, el último caso, la
causa, los límites observados y cualquier desviación. No hay reintento
automático.

## Tratamiento de datos y evidencia

La evidencia canónica de un run debe incluir, cuando aplique:

- ID del run, timestamps UTC, commit, perfil y configuración;
- IDs y hashes del corpus, de los oráculos y de los límites usados;
- comando saneado, código de salida y tiempo;
- número de procesos, invocaciones de modelo y solicitudes de herramienta;
- herramientas propuestas, autorizadas, rechazadas y ejecutadas;
- `stdout` y `stderr` saneados, sin traceback, secretos ni contenido completo
  innecesario;
- rutas representadas como `$REPO` o `$TMP`, no mediante la ruta personal
  absoluta;
- hashes y listado del sandbox antes y después;
- resultado `PASS`, `FAIL`, `RESIDUAL` o `STOPPED`, sin cambiar el oráculo;
- desviaciones, condición de parada, limitaciones y siguiente tratamiento.

Los logs brutos permanecen en el directorio temporal y no se versionan. Tras
verificar la evidencia saneada se eliminan de forma acotada y recuperable
cuando sea posible. `evaluations/` solo recibe artefactos sintéticos,
revisados y libres de secretos.

## Tratamiento de los 17 abuse cases

`CATALOGADO` significa que el caso tiene vehículo y límites definidos, no que
su ejecución esté autorizada ni que exista su fixture.

| Caso | Vehículo autorizado futuro | Restricción específica | Estado en PGS-03-M01 |
|---|---|---|---|
| `AC-PI-01` | Proceso CLI con argumento no reconocido | Prueba negativa; no añadir un prompt libre para simular la ruta | `CATALOGADO` |
| `AC-PI-02` | Copia temporal de incidentes y manifiesto | Material sintético; nunca alterar el corpus canónico durante el run | `CATALOGADO` |
| `AC-PI-03` | Copia temporal de conocimiento y manifiesto | Registrar los IDs recuperados y no ejecutar el texto del documento | `CATALOGADO` |
| `AC-JB-01` | Corpus temporal y doble determinista | Oráculos textuales fijados antes del resultado | `CATALOGADO` |
| `AC-JB-02` | Doble interno de modelo | Máximo 4 turnos y 2 solicitudes; el harness impone la terminación | `CATALOGADO` |
| `AC-EX-01` | Llamada interna a `knowledge_search` | Verificar cero resultados fuera de la allowlist | `CATALOGADO` |
| `AC-EX-02` | IDs señuelo sintéticos | No enumerar el índice real ni divulgar el corpus completo | `CATALOGADO` |
| `AC-EX-03` | Marcadores señuelo y subproceso CLI | Comprobar ausencia en salida, errores, rutas y traceback | `CATALOGADO` |
| `AC-TOL-01` | Doble interno con nombre prohibido | Sin implementar shell ni una herramienta falsa ejecutable | `CATALOGADO` |
| `AC-TOL-02` | Respuestas internas con cardinalidad o ciclo inválidos | Aplican los topes de turnos y solicitudes | `CATALOGADO` |
| `AC-TOL-03` | API interna de borradores | Sandbox temporal; propuesta, huella y replay sintéticos | `CATALOGADO` |
| `AC-TOL-04` | Sandbox temporal con archivo centinela | No apuntar a archivos personales ni seguir symlinks externos | `CATALOGADO` |
| `AC-TOL-05` | API interna con confirmación fabricada | Un único Markdown sintético en sandbox temporal | `CATALOGADO` |
| `AC-DOS-01` | Subprocesos de la CLI | Solo presupuesto especial: 2 procesos, 20 invocaciones, 60 s | `CATALOGADO` |
| `AC-DOS-02` | Copia temporal del corpus | Corrupción reversible; el checkout canónico no se toca | `CATALOGADO` |
| `AC-DOS-03` | Corpus sintético dimensionado | `NO AUTORIZADO` por las RoE base; requiere ampliación posterior | `CATALOGADO` |
| `AC-SC-01` | Copia temporal completa del candidato | No modificar código, lockfile ni evidencia del checkout canónico | `CATALOGADO` |

## Requisitos verificables

| ID | Requisito | Criterio observable |
|---|---|---|
| `ROE-01` | Cada run debe identificar autoridad, candidato, casos y límites | El manifiesto de ejecución contiene los diez campos de precondición |
| `ROE-02` | Solo se usarán datos sintéticos y targets propios | Los manifiestos declaran `synthetic: true` y no aparecen targets externos |
| `ROE-03` | Toda mutación adversaria debe quedar aislada | Los cambios ocurren en `$TMP`; el checkout canónico conserva estado y hashes |
| `ROE-04` | El harness debe imponer el presupuesto aplicable | Tiempo, procesos, invocaciones, tamaño, archivos y RSS quedan medidos |
| `ROE-05` | Toda condición de parada debe producir un resultado explícito | El run termina `STOPPED`, conserva causa y no se reintenta automáticamente |
| `ROE-06` | Ninguna salida del modelo puede ampliar autoridad | Cada herramienta ejecutada tiene autorización de aplicación independiente |
| `ROE-07` | La evidencia debe ser reproducible y saneada | Incluye commit, hashes, métricas, resultado y rutas `$REPO`/`$TMP` |
| `ROE-08` | Los 17 casos deben tener vehículo y restricción propios | La tabla contiene una fila única por cada ID de `GSL-ABUSE-CASES-001` |
| `ROE-09` | Cambios de superficie deben invalidar la versión vigente | Se revisan las RoE antes de usar red, proveedor, Docker, cloud o datos reales |
| `ROE-10` | PGS-03-M01 no debe ejecutar ataques | El commit solo contiene documentación y verificaciones ordinarias |

## Disparadores de revisión

Estas reglas deben revisarse y versionarse antes de:

- conectar un modelo real, Docker, `localhost`, red, API, cloud o proveedor;
- añadir una herramienta, identidad, interfaz, servicio o efecto nuevo;
- usar datos que no sean los sintéticos aprobados;
- cambiar los límites del host, del corpus, del sandbox o del harness;
- mover el repositorio, introducir un remoto o cambiar la estrategia de
  evidencia;
- ejecutar `AC-DOS-03`, fuzzing, stress, soak o cualquier prueba no cubierta;
- detectar una desviación que demuestre que el alcance o la parada son
  insuficientes.

Una revisión no autoriza por sí misma la ejecución. Debe conservar versión,
motivo, cambios y nueva petición aplicable.

## Estado de cierre de PGS-03-M01

Las RoE delimitan los 17 casos, responsables, targets, acciones, datos,
presupuesto, evidencia y parada. No modifican la arquitectura ni implementan
enforcement: el perfil aislado se creará en PGS-03-M02 y el corpus adversario
en PGS-03-M03.
