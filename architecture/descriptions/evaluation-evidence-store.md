Conserva snapshots revisados que permiten comparar ejecuciones funcionales y
adversarias de forma reproducible.

## Contenido

- `DAT-04`: `GSL-BASELINE-BENIGN-001`.
- 12/12 casos, 24 invocaciones deterministas y 12 consultas autorizadas.
- `DAT-10`: configuración saneada de `GSL-BASELINE-ADVERSARIAL-001`.
- `DAT-11`: resultados de 14 casos: 13 `PASS`, 1 `RESIDUAL`, 0 `FAIL` y 0
  `STOPPED`.
- `DAT-12`: 16 eventos allowlisted.
- `DAT-13`: manifiesto revisado con tamaños y SHA-256.
- `DAT-16`: configuración saneada de `GSL-RETEST-ADVERSARIAL-001`.
- `DAT-17`: resultados neutrales de 14 casos: 14 `COMPLETED`, 13 `MATCH` y
  1 `DIFF`, sin interpretación de eficacia.
- `DAT-18`: 16 eventos de inicio, observación y cierre.
- `DAT-19`: manifiesto revisado con tamaños, SHA-256 y
  `final_retest: false`.
- `DAT-20`: snapshot comparativo de 14 pares con reglas cerradas, tasas,
  operaciones aceptadas/ejecutadas, cobertura y límites.
- `DAT-21`: proyección precontroles y snapshot comparativo de 12 casos
  benignos; conserva terminación, invariantes, falsos rechazos, cobertura
  textual exacta, hashes y límites sin salida bruta.
- `DAT-22`: 30 pares pre/post de tiempo de pared, CPU y RSS, contadores,
  costes externos y complejidad descriptiva; conserva hash y tamaño de salida,
  no su contenido.
- `DAT-23`: registro estático y revisado de seis hallazgos con 44 referencias
  escalares a `DAT-20/21/22`, taxonomía cerrada, tratamiento y resumen
  derivable.
- `DAT-24`: rúbrica cerrada y fijada antes del retest final; enlaza por hash 84
  cláusulas con fuentes o invariantes autorizados y no contiene la salida del
  target.
- `DAT-25`: proyección saneada del único retest final, con provenance de
  candidato/evaluador, 14 casos adversarios, 12 benignos, dos probes, métricas
  derivadas y límites explícitos.

## Flujo de escritura

La CLI ordinaria emite el resultado benigno por `stdout`. `CMP-08` y `CMP-13`
escriben primero la evidencia adversaria bajo `$TMP`; el mantenedor incorpora
la proyección saneada al repositorio después de revisarla. `CMP-14` lee ambos
namespaces, emite `DAT-20` por `stdout` y tampoco escribe directamente. No existe una
escritura directa desde la CLI de producto hacia `evaluations/`. `CMP-15`
verifica su fuente histórica, ejecuta los 12 casos benignos y emite `DAT-21`
por `stdout`; el versionado sigue siendo una acción manual del mantenedor.
`CMP-16` materializa los candidatos fijados bajo `$TMP`, ejecuta sus baselines
y emite `DAT-22` por `stdout` con la misma separación de escritura. El
mantenedor redacta y versiona `DAT-23`; `CMP-17` solo lo verifica junto con
sus fuentes y emite un informe efímero por `stdout`. El mantenedor versiona
`DAT-24` antes del run; `CMP-18` la verifica, la mantiene fuera del target y no
persiste por sí mismo el resultado final.

## Límite

La evidencia adversaria solo demuestra las observaciones y métricas de las
variantes y los commits fijados. No acredita seguridad general, resistencia a
ataques desconocidos ni utilidad semántica. `DAT-21` acredita 12/12
terminaciones y 0 falsos rechazos en ambos candidatos, pero su cobertura
textual exacta no equivale a una evaluación semántica.
`DAT-22` representa una sesión y un host; no constituye un SLO, benchmark
universal ni medición de energía o coste total.
`DAT-23` no convierte controles parciales, casos inertes, datos no computables,
criterios no demostrados u overhead sin umbral en fallos; tampoco sustituye el
retest final ni la aceptación de riesgo. `DAT-24` fija una evaluación cerrada
de trazabilidad y no equivale a evaluación semántica general. `DAT-25`
demuestra `SC-06` y `SC-07` solo para el candidato, corpus y rúbrica fijados;
no evalúa ataques desconocidos o un modelo real.
