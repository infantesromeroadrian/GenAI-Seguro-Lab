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

## Flujo de escritura

La CLI ordinaria emite el resultado benigno por `stdout`. `CMP-08` escribe la
evidencia adversaria bruta solo bajo `$TMP`; el mantenedor incorpora la
proyección saneada al repositorio después de revisarla. No existe una escritura
directa desde la CLI de producto hacia `evaluations/`.

## Límite

La evidencia adversaria solo demuestra las observaciones de las variantes y
el commit fijados. No acredita seguridad general, resistencia a ataques
desconocidos ni utilidad semántica.
