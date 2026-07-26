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

## Flujo de escritura

La CLI ordinaria emite el resultado benigno por `stdout`. `CMP-08` y `CMP-13`
escriben primero la evidencia adversaria bajo `$TMP`; el mantenedor incorpora
la proyección saneada al repositorio después de revisarla. No existe una
escritura directa desde la CLI de producto hacia `evaluations/`.

## Límite

La evidencia adversaria solo demuestra las observaciones de las variantes y
los commits fijados. Las relaciones del retest inicial no son todavía tasas de
eficacia. No acredita seguridad general, resistencia a ataques desconocidos ni
utilidad semántica.
