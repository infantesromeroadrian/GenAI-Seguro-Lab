# Evaluaciones

Este directorio conserva resultados reproducibles del laboratorio sobre el
corpus sintético versionado.

## Baseline funcional benigna v1

`benign-baseline-v1.json` es la instantánea canónica de
`GSL-BASELINE-BENIGN-001`. Se regenera por `stdout` con:

```bash
uv run --frozen python main.py baseline
```

Resultado fijado:

- 12 casos benignos completados;
- 24 invocaciones del adaptador determinista;
- 12 consultas de conocimiento autorizadas;
- 0 llamadas externas;
- 0 € de coste.

El snapshot es evidencia de reproducibilidad y funcionamiento del flujo, no
una medición de resistencia a ataques ni de utilidad semántica.

PGS-04-M01 renovó únicamente sus 24 huellas de petición para incorporar las
clases de confianza y la frontera de instrucciones al contrato serializado. Los
12 resultados funcionales y el resumen permanecieron sin cambios; el historial
Git conserva la instantánea anterior.

## Baseline adversaria canónica v1

`adversarial-baseline-v1/` conserva la proyección saneada y revisada de
`GSL-BASELINE-ADVERSARIAL-001`, ejecutada contra el commit exacto
`93aefa45eac687d219bfed32f03be4e60e4a13ed`.

Resultado fijado:

- 14 fixtures PI/JB/EX/TOL evaluadas;
- 13 `PASS`, 1 `RESIDUAL`, 0 `FAIL` y 0 `STOPPED`;
- residual crítico reproducido en `ADV-TOL-005`;
- 14 invocaciones de modelo, 22 solicitudes de herramienta y 23 operaciones
  sobre fronteras de herramienta;
- 2 subprocesos, 1 archivo de efecto temporal, 0 llamadas externas y 0 €.

La configuración, resultados, eventos y manifiesto de integridad están
documentados dentro del propio directorio. Los logs brutos y el sandbox
temporal no se versionan.

## Retest adversario v1

`adversarial-retest-v1/` conserva la proyección saneada y revisada de
`GSL-RETEST-ADVERSARIAL-001`. `run_adversarial_retest.py` la ejecutó una sola
vez como `GSL-ADV-RT-20260726-001`, sin modificar ni reinterpretar la baseline
histórica, contra el commit endurecido
`d236bbee9f371a75e330c227f100aef167b864b0`, tree
`b54b260245ba4e8426fbba86c2c22b0608960315` y rama `main` limpios.

El runner verifica el manifiesto y los hashes de
`adversarial-baseline-v1/`, la identidad byte a byte de cinco archivos de
contenido y la deriva de metadatos del manifiesto adversario `1.3.0` →
`1.4.0`. Los mismos 14 casos se ejecutaron en el mismo orden y completaron:
13 relaciones fueron `MATCH` y `ADV-TOL-005` registró `DIFF`; las cuatro
fixtures DOS/SC permanecieron inertes. La evidencia usa estados de ejecución y
relaciones con el oráculo, sin valoración de eficacia ni cuentas históricas
presentadas como medición actual.

La salida inicial se escribió create-only bajo
`$TMP/adversarial-retest-v1/reviewed`. Tras verificar saneado, tamaños, hashes,
orden y configuración, solo la proyección cerrada se versionó en
`adversarial-retest-v1/`, con `reviewed_for_versioning: true` y
`final_retest: false`. PGS-05-M02 interpreta después esta evidencia sin
modificarla ni reejecutar el target.

## Perfil vulnerable de evaluación

`GSL-PROFILE-VULNERABLE-001` ya existe como configuración aislada, no
predeterminada y sin capacidad de ejecución. Construye peticiones claramente
marcadas, pero no llama al modelo, no ejecuta herramientas y no genera aquí
ningún resultado.

El corpus adversario está fijado fuera de este directorio, con entradas y
oráculos separados. `CMP-07` implementa las pruebas de desarrollo y los
runners separados de baseline y retest las orquestan para producir primero
evidencia bajo `$TMP` y después una proyección saneada y revisada. La
    aplicación ordinaria no escribe estos resultados.

## Métricas adversarias comparativas v1

`adversarial-metrics-v1.json` es la proyección canónica de
`GSL-METRICS-ADVERSARIAL-001`. Se deriva offline con:

```bash
uv run --frozen python evaluations/run_adversarial_metrics.py
```

`CMP-14` verifica primero los SHA-256 de los dos manifiestos y de todos sus
ficheros declarados. Después empareja los 14 IDs evaluables y aplica una
clasificación cerrada por caso y triple observado. La salida fija:

- éxito de ataque: 1/14 (7,14 %) en baseline y 0/14 (0 %) en retest;
- operaciones no autorizadas aceptadas o ejecutadas: 1 y 0;
- `ADV-TOL-005` como único caso mejorado, sin regresiones;
- cobertura 14/18 y cuatro fixtures DOS/SC fuera del denominador;
- `source_final_retest: false`.

No se ejecuta ningún target ni herramienta. Las solicitudes intentadas o
rechazadas no son comparables porque M01 no conservó esa cuenta post; el
snapshot lo declara como `NOT_COMPUTABLE_FROM_M01`.

## Utilidad benigna comparativa v1

`benign-pre-controls-functional-v1.json` es una proyección saneada del
snapshot original del commit `df13683`. Conserva únicamente identidad,
categoría, estado y conteos por caso; el evaluador verifica además el objeto
Git y el SHA-256 del artefacto original.

`benign-utility-v1.json` es la salida canónica de
`GSL-METRICS-BENIGN-UTILITY-001`:

```bash
uv run --frozen python evaluations/run_benign_utility.py
```

`CMP-15` verifica las fuentes fijadas, el corpus y ocho archivos del producto.
Después ejecuta los 12 incidentes uno a uno con el control de recursos
`analyze`, de modo que un rechazo o error no oculte los demás casos. La salida
fija:

- 12/12 terminaciones técnicas antes y después;
- 0/12 falsos rechazos y 0 errores;
- 0/12 éxitos estrictos y 12 `PARTIAL`;
- cobertura textual exacta de 0/24 hallazgos y 0/36 acciones;
- 12 casos sin cambio, 0 regresiones, 0 llamadas externas y 0 efectos.

La coincidencia exacta usa NFKC, `casefold` y espacios normalizados. No
interpreta paráfrasis ni equivalencia semántica y tampoco evalúa
semánticamente las afirmaciones prohibidas. Por ello los diagnósticos de
umbral se publican, pero `SC-07` permanece `NOT_DEMONSTRATED`.

## Métricas operativas comparativas v1

`operational-metrics-v1.json` es la evidencia canónica de
`GSL-METRICS-OPERATIONAL-001`:

```bash
uv run --frozen python evaluations/run_operational_metrics.py
```

`CMP-16` verifica los commits y árboles `df13683` y `ba600ca`, además de los
SHA-256 byte a byte idénticos de `data/manifest.json`, `main.py`,
`pyproject.toml` y `uv.lock`. Los materializa con `git archive` bajo un
directorio temporal y ejecuta el mismo baseline con el mismo intérprete, sin
instalar dependencias ni cambiar el checkout.

El protocolo descarta tres pares de calentamiento y conserva 30 pares
medidos, 15 en cada orden AB/BA, con un proceso nuevo por muestra y sin
reintentos ni eliminación de outliers. La evidencia fija:

- latencia mediana pre/post de 189.693.584 ns y 259.169.250 ns; delta
  emparejado mediano de +67.387.688 ns;
- CPU mediana de 167.383.000 ns y 223.382.500 ns; delta emparejado mediano de
  +60.542.500 ns;
- RSS mediana de 36.315.136 B y 41.172.992 B; delta emparejado mediano de
  +4.907.008 B;
- 12 casos, 24 invocaciones, 12 solicitudes y 12 ejecuciones derivadas por
  candidato, con 0 llamadas externas y 0 céntimos de proveedor/cloud;
- carga del operador `UNCHANGED`, superficie interna `INCREASED` y ningún
  score compuesto.

Cada muestra conserva tiempos, CPU, RSS, código de salida, tamaño y SHA-256
de `stdout`, `stderr` vacío e identidades parseadas; no conserva la salida
bruta. No hay umbral universal ni afirmación de significación. Energía,
amortización y trabajo humano quedan sin medir; el resultado corresponde a
un único host y sesión con un modelo determinista sin aislamiento de red a
nivel kernel.

## Registro canónico de hallazgos M05

`control-findings-v1.json` es el registro estático y revisado
`GSL-CONTROL-FINDINGS-001` (`DAT-23`). No es la salida de otro evaluador:
clasifica con juicio explícito la evidencia ya fijada en `DAT-20`, `DAT-21` y
`DAT-22`.

```bash
uv run --frozen python evaluations/verify_control_findings.py
```

`CMP-17` verifica los tres hashes, sus esquemas cerrados, 44 JSON Pointers
escalares, los seis IDs y el resumen derivado. La salida solo confirma la
validación; no escribe ni regenera `DAT-23`, ejecuta targets o benchmarks,
acepta riesgo, selecciona reparaciones o declara el retest final.

El registro separa:

- `CF-001`: bypass histórico mitigado en el retest inicial, pendiente de M07;
- `CF-002`, `CF-003` y `CF-005`: dato no computable, cobertura 14/18 y
  aseguramiento semántico no evaluado;
- `CF-004`: brecha funcional textual preexistente, único candidato de revisión
  en M06;
- `CF-006`: sobrecoste local observado sin umbral de aceptación.

La cuenta de cero fallos y cero bypasses actuales está limitada a las 14
fixtures medidas. Un control `PARCIAL`, un caso inerte, `NOT_DEMONSTRATED` o
`NOT_COMPUTABLE` no se presenta como fallo.

## Retest final M07

`final-retest-rubric-v1.json` es `DAT-24`, el contrato cerrado fijado antes de
la ejecución. Contiene 24 hallazgos, 36 acciones y 24 prohibiciones enlazados
por hash a fuentes o invariantes autorizados. No se entrega al target, no usa
un juez LLM y declara falsa la equivalencia semántica general.

`final-retest-v1.json` es `DAT-25`, la salida revisada del único run canónico:

```bash
uv run --frozen python evaluations/run_final_retest.py
```

La ejecución real no debe repetirse para regenerar el archivo: el comando
anterior documenta su punto de entrada. `DAT-25` fija el run
`GSL-FINAL-RT-20260727-001`, candidato `77edd640`/`bc09b78f` y evaluador
`636e1db`/`8ccd162e`. Su SHA-256 es
`05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d`.

La evidencia conserva:

- 14/14 casos adversarios completos, 1/14 → 0/14 éxitos, 1 → 0 operaciones no
  autorizadas, un caso mejorado y cero regresiones;
- 12/12 benignos completos, cero falsos rechazos, 12 hashes congelados y
  24/24 + 36/36 + 24/24 cláusulas preservadas por reglas cerradas;
- dos probes de frontera sin fuga de `expected_result`, cuatro entradas
  inertes sin ejecutar y 15 artefactos M01–M06 byte a byte;
- `SC-06` y `SC-07` `DEMONSTRATED` solo para el candidato, corpus y rúbrica
  fijados;
- `CF-002` `NOT_COMPUTABLE`, `DAT-22` histórico y ninguna evaluación semántica
  general, con modelo GenAI real o juez LLM.

## Reconstrucción limpia de cierre v1

[`clean-rebuild-v1.json`](./clean-rebuild-v1.json) es la evidencia saneada de
`GSL-CLEAN-REBUILD-001`. Se obtuvo desde un clon nuevo del repositorio público,
con el candidato `93d9a058` y el árbol `af535623`, sin reutilizar el checkout
local ni la caché de paquetes.

La ejecución validó el lock, instaló las diez distribuciones aplicables en
Darwin arm64, confirmó que una segunda sincronización no requería cambios y
ejecutó el punto de entrada soportado `main.py --help`. El checkout empezó y
terminó limpio, `.venv` permaneció ignorado y el directorio temporal se movió
a la Papelera.

La descarga del repositorio y de los paquetes usó red, por lo que no se
presenta como build offline o hermética. Tampoco acredita tests del producto,
corpus, ausencia de secretos, vulnerabilidades, licencias, procedencia, firmas
o revisión independiente. `DAT-25` no se ejecutó ni cambió.
