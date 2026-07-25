# Matriz de autoridad y consecuencias

## Ficha de la matriz

| Campo | Valor |
|---|---|
| Identificador | `GSL-AUTH-MATRIX-001` |
| Versión | `1.2.0` |
| Fecha de corte | 2026-07-25 |
| Baseline de código | commit `3c4657efbc7dc92b232b83f3185d27968c2ba78b` + candidato PGS-03-M03 |
| Inventario de origen | [`GSL-SYS-INV-001`](./system-inventory.md) |
| Arquitectura de origen | [`architecture/manifest.json`](../architecture/manifest.json) |
| Alcance | autoridad implementada en el checkout local actual |

Esta matriz describe quién puede provocar cada acción, qué identidad la
ejecuta, qué datos alcanza, qué herramienta interviene y cuál es su
consecuencia máxima dentro del sistema implementado. No concede permisos,
no representa componentes futuros y no prioriza riesgos; esa priorización
corresponde a PGS-02-M06.

## Cómo interpretar la autoridad

La cadena relevante no es «el modelo pidió una acción, por tanto la hizo».
En el sistema actual:

1. `MOD-01` solo devuelve datos validados por esquema.
2. `CMP-03` interpreta esos datos y decide si existe una ruta permitida.
3. `IDN-01`, la cuenta de macOS que ejecuta el proceso Python, aporta la
   autoridad efectiva de runtime.
4. La herramienta vuelve a validar sus argumentos y aplica su propio límite.
5. El efecto máximo depende de la herramienta alcanzable, no de la intención
   expresada por el modelo.

`IDN-04` es, por tanto, una ausencia deliberada de autoridad: el modelo no
posee una identidad de aplicación, credenciales, permisos de filesystem ni
capacidad para ejecutar herramientas por sí mismo.

## Escala de consecuencias

La escala clasifica efectos observables actuales, no gravedad ni riesgo
residual.

| Nivel | Consecuencia máxima implementada |
|---|---|
| `C0` | Datos tipados en memoria; no existe efecto externo o persistente directo |
| `C1` | Lectura de datos sintéticos versionados y emisión efímera por `stdout` o `stderr` |
| `C2` | Creación exclusiva de un Markdown sintético dentro de `sandbox/drafts/` |
| `C3` | Mutación del código, corpus, dependencias o evidencia versionada por el mantenedor, fuera de los controles de runtime |

## Matriz `modelo → identidad → datos → herramientas → acciones → consecuencias`

| ID | Actor, entrada y alcance | Modelo | Identidad efectiva | Datos alcanzados | Herramienta o capacidad | Acción autorizada y controles | Acciones explícitamente no autorizadas | Consecuencia máxima actual |
|---|---|---|---|---|---|---|---|---|
| `AUTH-01` | `ACT-01` ejecuta `main.py analyze --incident <ID>`; ruta expuesta por CLI | `MOD-01`, dos respuestas deterministas guionizadas | `IDN-01`; no hay login ni rol interno | Lee `DAT-01`, `DAT-02` y `DAT-03`; emite `DAT-05` | `CMP-01` a `CMP-04` y `TOL-01` | Validar el corpus, seleccionar un ID exacto, ejecutar una búsqueda limitada a las referencias del incidente y emitir JSON | Escribir archivos, consultar red, usar otra herramienta, buscar IDs fuera del incidente o ejecutar una acción recomendada | `C1`: lectura sintética y resultado efímero de un caso |
| `AUTH-02` | `ACT-01` ejecuta `main.py baseline`; ruta expuesta por CLI | `MOD-01`, 24 respuestas deterministas guionizadas para 12 casos | `IDN-01`; no hay identidad de servicio separada | Lee `DAT-01`, `DAT-02` y `DAT-03`; emite `DAT-05` | `CMP-01` a `CMP-05` y `TOL-01` | Repetir el flujo acotado para los 12 incidentes y serializar una baseline funcional canónica | Escribir o reemplazar `DAT-04`, ampliar el corpus, iniciar reintentos abiertos o hacer llamadas externas | `C1`: lectura completa del corpus benigno y JSON efímero; carga acotada a 12 casos |
| `AUTH-03` | `CMP-03` solicita la primera respuesta y recibe una propuesta de herramienta | `MOD-01` origina un único `ModelToolRequest` guionizado | Ninguna identidad de ejecución; aplica `IDN-04` | Lee una representación de `DAT-01`; produce nombre y argumentos tipados en memoria | Ninguna herramienta se ejecuta en este paso | Proponer exactamente una solicitud `knowledge_search` como datos | Autorizarla, ejecutarla, acceder por sí mismo a `DAT-02`, usar filesystem, shell, red o credenciales | `C0`: una propuesta en memoria sin efecto directo |
| `AUTH-04` | `CMP-03` evalúa la propuesta de `AUTH-03`; ruta interna del flujo expuesto | La salida de `MOD-01` se trata como entrada no confiable | `IDN-01` ejecuta la llamada una vez autorizada por la aplicación | Consulta en memoria el subconjunto permitido de `DAT-02` | `TOL-01` | Exigir el nombre exacto, validar JSON estricto, limitar 1–8 IDs declarados, comprobar el subconjunto del incidente, rechazar IDs desconocidos y devolver como máximo 5 resultados | Consultar documentos no autorizados, leer el filesystem durante la búsqueda, usar red o encadenar otra herramienta | `C1`: divulgación al mismo proceso de conocimiento sintético autorizado |
| `AUTH-05` | `CMP-03` entrega el resultado de `TOL-01` al modelo y exige la respuesta final | `MOD-01` produce texto final guionizado | Ninguna identidad de ejecución; aplica `IDN-04` | Lee contexto de `DAT-01` y resultados autorizados de `DAT-02`; produce texto en memoria | Ninguna | Emitir una respuesta final tipada con `finish_reason=stop` | Solicitar otra herramienta, ejecutar recomendaciones o persistir la respuesta | `C0` dentro de la frontera del modelo; `AUTH-01` o `AUTH-02` eleva su salida a `C1` al imprimirla |
| `AUTH-06` | `ACT-03` o cualquier llamador Python local invoca `TOL-02.prepare`; API interna, no CLI | Ninguno conectado; acepta estructuralmente un `ModelToolRequest`, pero `MOD-01` no tiene ruta hasta aquí | `IDN-01`; no se autentica al llamador | Recibe contenido de propuesta y devuelve una huella SHA-256 en memoria | `TOL-02.prepare` | Aceptar solo `draft_create`, validar nombre, título, cuerpo y referencias, y preparar la propuesta exacta | Crear el archivo, interpretar la propuesta como confirmación o alcanzar una ruta fuera del sandbox | `C0`: propuesta verificable en memoria |
| `AUTH-07` | `ACT-03` aporta por API interna una propuesta y una confirmación separadas | Ninguno participa en la autorización | `IDN-01` ejecuta; `IDN-03` declara consentimiento pero no acredita identidad humana | Crea `DAT-06` con nombre de hasta 64 caracteres, título de 120 y cuerpo de 10 000 | `TOL-02.create` | Comprobar la huella exacta, consumirla una sola vez por instancia, revalidar el directorio y crear con modo exclusivo | Sobrescribir, borrar, usar subrutas, seguir symlinks de directorio, escribir fuera de `sandbox/drafts/`, usar shell o red | `C2`: un Markdown sintético nuevo y confinado; la CLI actual no puede provocarlo |
| `AUTH-08` | `ACT-02` regenera y versiona manualmente la baseline; operación de soporte | `MOD-01` genera material de origen, pero no autoriza la versión | Cuenta macOS y autoridad Git de `ACT-02`, fuera de la aplicación | Transforma `DAT-05` en `DAT-04` | CLI, redirección/editor y Git; no son herramientas del producto | Revisar, guardar y versionar la evidencia funcional | Atribuir a la aplicación una escritura automática o considerar el snapshot una evaluación de seguridad | `C3`: modificar la evidencia versionada y su interpretación |
| `AUTH-09` | `ACT-02` mantiene el checkout local; operación de desarrollo y soporte | Ninguno limita esta autoridad | Cuenta macOS y autoridad Git de `ACT-02`, fuera de la aplicación | Puede modificar código, `DAT-01` a `DAT-04`, `DAT-06` a `DAT-09`, configuración y resolución de dependencias | Editor, Git, `uv` y herramientas de desarrollo | Cambiar y versionar el laboratorio de forma deliberada | Ningún control de runtime restringe esta cuenta; su uso queda sujeto al sistema operativo, revisión y disciplina de repositorio | `C3`: mayor autoridad actual; puede alterar controles, comportamiento, datos y evidencia |
| `AUTH-10` | `ACT-02` llama a la factory de `CMP-06`; API Python interna, no CLI | Ninguno se ejecuta; solo se construye una `ModelRequest` deliberadamente débil | `IDN-01`; declaración exacta de `GSL-ROE-001`, sin identidad de servicio | Lee en memoria un incidente de `DAT-01` y metadatos de `DAT-03`; omite el oráculo y liga un `$TMP/sandbox/drafts` | `CMP-06`; valida autorización, datos sintéticos y aislamiento temporal | Preparar una petición marcada que anuncia `TOL-01` y `TOL-02` para un futuro harness | Usar el sandbox canónico, elegir el perfil desde CLI, llamar a `MOD-01`, ejecutar herramientas, crear archivos, usar red o iniciar un ataque | `C0`: petición tipada en memoria, sin efecto o ejecución |
| `AUTH-11` | `ACT-02` o pytest llama a `load_adversarial_corpus()`; API Python interna, no CLI | Ninguno participa | `IDN-01`; no existe una identidad de evaluación separada | Lee `DAT-07`, `DAT-08` y `DAT-09` y devuelve fixtures y oráculos tipados en memoria | `CMP-02`; valida esquema, cobertura, límites, relación uno a uno, conteos y SHA-256 | Cargar el corpus inerte y comprobar su contrato sin interpretarlo | Entregar una entrada a `CMP-06` o `MOD-01`, ejecutar un caso, iniciar procesos, invocar herramientas, escribir, usar red o tratar el oráculo como autorización | `C1`: lectura de datos sintéticos versionados; cero conexiones y cero ejecuciones |

## Cadenas de autoridad resumidas

```text
ACT-01
  → IDN-01
  → CMP-01/CMP-02/CMP-04/CMP-03
  → MOD-01 propone datos
  → CMP-03 autoriza
  → TOL-01 lee DAT-02
  → DAT-05 por stdout
```

```text
ACT-03 (API interna)
  → IDN-01
  → TOL-02.prepare
  → IDN-03 confirma la propuesta exacta, sin autenticarse
  → TOL-02.create
  → DAT-06 create-only
```

```text
ACT-02
  → cuenta macOS/Git
  → editor, uv y Git fuera del runtime
  → código, corpus, dependencias y evidencia versionada
```

```text
ACT-02 (API Python interna)
  → declaración exacta de GSL-ROE-001
  → CMP-06 valida dataset y $TMP/sandbox/drafts
  → ModelRequest vulnerable marcada
  → fin sin llamar modelo o herramientas
```

```text
ACT-02 o pytest (API Python interna)
  → CMP-02 valida DAT-07/DAT-08/DAT-09
  → AdversarialCorpusBundle en memoria
  → fin sin entregar entradas al perfil, modelo o herramientas
```

La primera cadena es la única alcanzable mediante `main.py`. La segunda existe
como capacidad interna probada, pero no está conectada a la CLI ni al flujo
benigno. La tercera es una autoridad de mantenimiento externa a los controles
de la aplicación. La cuarta prepara una entrada de evaluación `C0`; todavía no
es un harness ni una ejecución adversaria. La quinta solo valida el corpus
inerte y termina antes de cualquier target.

## Rutas de autoridad que no existen

| Origen | Destino pretendido | Estado actual |
|---|---|---|
| `MOD-01` | Ejecutar directamente `TOL-01` | Sin ruta: el modelo solo devuelve una solicitud tipada a `CMP-03` |
| `MOD-01` | Preparar o crear mediante `TOL-02` | Sin ruta: no hay arista de ejecución desde el modelo o el flujo benigno |
| `CMP-06` | Invocar `MOD-01`, `TOL-01` o `TOL-02` | Sin ruta: el perfil solo construye una `ModelRequest`; no contiene adaptador ni dispatcher |
| `DAT-07`/`DAT-08` | Entrar en `CMP-06`, `MOD-01` o una herramienta | Sin ruta: `load_adversarial_corpus()` devuelve un bundle a su llamador y no existe harness o dispatcher |
| `CMP-01` | Invocar `TOL-02` | Sin ruta: la CLI solo expone `analyze` y `baseline` |
| Runtime de aplicación | Escribir `DAT-04` | Sin ruta directa: la baseline solo se emite por `stdout` y el mantenedor la versiona |
| Runtime de aplicación | Shell, red, proveedor, cloud, base de datos o secretos | Sin capacidad implementada ni credenciales |
| Usuario remoto | Entrar en el sistema | Sin interfaz: no hay API, UI remota, cuenta de aplicación o listener |
| `IDN-03` | Demostrar quién confirmó | Sin mecanismo: la confirmación demuestra coincidencia de contenido, no identidad |

«Sin ruta» significa que el comportamiento no está implementado en la
aplicación actual. No es una garantía frente a la modificación del código o a
una ejecución arbitraria bajo la cuenta de macOS: esos escenarios heredarían
la autoridad de `ACT-02` o `IDN-01` y deben tratarse como abuso del host o de la
supply chain.

## Invariantes que deben conservar las siguientes fases

- El modelo propone; la aplicación autoriza; la identidad del proceso ejecuta.
- Una solicitud de herramienta no equivale a consentimiento ni a ejecución.
- La allowlist pertenece al incidente validado, no a los argumentos del modelo.
- Los oráculos `DAT-08` permanecen separados de las entradas `DAT-07` y nunca
  se convierten en instrucciones o autoridad para el sistema evaluado.
- La confirmación de un borrador queda ligada al contenido exacto, pero sigue
  necesitando una identidad humana real si la capacidad se expone.
- Los efectos persistentes de producto no pueden superar `C2` sin revisar esta
  matriz, el inventario y los trust boundaries.
- La autoridad `C3` del mantenedor debe permanecer distinguida del
  comportamiento que se atribuye al producto.

## Límites y disparadores de revisión

Esta matriz no demuestra que el sistema sea seguro y no incluye todavía abuse
cases, probabilidad, impacto ni riesgo residual. Debe revisarse antes de
incorporar cualquiera de estos cambios:

- un modelo o proveedor real;
- red, API, interfaz remota o ejecución desatendida;
- autenticación, roles, service accounts o secretos;
- nuevas herramientas o conexión de `TOL-02` a la CLI;
- escritura sobre datos o evidencia versionada;
- Docker, cloud, almacenamiento externo, telemetría o sistema multiagente.

PGS-02-M05 materializa estas cadenas y rutas ausentes en el
[catálogo `GSL-ABUSE-CASES-001`](./abuse-cases.md), sin atribuir al modelo
capacidades que hoy no posee.
