Agrupa la lógica que conserva el control de ejecución frente a datos y salidas
del modelo.

## Trust boundary

- ID: `TB-02`.
- Incluye CLI, contrato de datos, flujo benigno, motor de baseline, política
  de salida, control de recursos, journal de seguridad, perfil vulnerable,
  harness adversario, runner histórico, runner neutral de retest y analizador
  offline de métricas, evaluador de utilidad y evaluador operativo.
- Decide qué datos se cargan, qué herramienta se autoriza y cuándo termina el
  flujo.
- Emite un principal y scope lógicos por operación y no deriva la autoridad
  ejecutable del catálogo anunciado al modelo.
- Proyecta para `TOL-01` únicamente las referencias del incidente validado.
- Exige `CMP-09` antes de devolver un resumen o ligar un borrador a una
  aprobación.
- Exige `CMP-10` antes de leer el corpus, cruzar fronteras acotadas o crear un
  efecto y mantiene un lock no bloqueante durante cada operación de CLI.
- Usa `CMP-11` para observar decisiones mediante metadatos cerrados; el
  journal no concede autoridad ni persiste o exporta automáticamente.
- Usa `CMP-12` para publicar y reconciliar únicamente el efecto de borrador ya
  autorizado, sin convertir markers o señales en autoridad.
- El harness selecciona solo 14 fixtures PI/JB/EX/TOL y nunca entrega el
  oráculo al target.
- `CMP-08` exige exclusivamente el commit histórico limpio, aplica los
  presupuestos y escribe evidencia bruta únicamente bajo `$TMP`; no forma
  parte de la CLI de producto ni evalúa el checkout endurecido.
- `CMP-13` exige un candidato endurecido exacto y limpio, verifica la evidencia
  histórica y la comparabilidad del corpus y proyecta observaciones neutrales
  bajo `$TMP`; no forma parte de la CLI.
- `CMP-14` verifica los dos namespaces versionados y deriva métricas cerradas
  por `stdout`; no ejecuta el target, runners, harness o herramientas.
- `CMP-15` repite el corpus benigno por caso y compara los oráculos después de
  cada salida; no los entrega al target ni afirma equivalencia semántica.
- `CMP-16` materializa dos commits fijados bajo `$TMP` y mide sus baselines en
  procesos nuevos; no cambia el checkout, instala dependencias o fija un
  umbral universal.
- Los casos indirectos conectan una copia temporal al perfil, al doble
  determinista y a una búsqueda autorizada; los JB/EX añaden guardas,
  rechazos de búsqueda y una comprobación CLI saneada. TOL añade llamadas
  internas confinadas a las fronteras existentes. El checkout actual rechaza
  el literal TOL-005; el efecto residual pertenece al candidato histórico.
  Ninguno forma parte del flujo ordinario ni habilita una ruta adversaria en
  la CLI.

## Límite

Es una separación lógica dentro del mismo proceso Python. No constituye una
cuenta, sandbox o proceso aislado. Los grants no reducen los permisos de
`IDN-01` ni protegen frente a ejecución arbitraria de Python. El plazo y el
lock de `CMP-10` son cooperativos.
La cadena SHA-256 de `CMP-11` no está firmada o anclada fuera del proceso.
El lock y las validaciones de `CMP-12` tampoco aíslan código hostil bajo
`IDN-01`.
