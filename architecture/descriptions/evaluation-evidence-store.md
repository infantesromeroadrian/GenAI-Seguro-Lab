Conserva snapshots revisados que permiten comparar ejecuciones funcionales de
forma reproducible.

## Contenido

- `DAT-04`: `GSL-BASELINE-BENIGN-001`.
- 12/12 casos, 24 invocaciones deterministas y 12 consultas autorizadas.

## Flujo de escritura

La aplicación emite el resultado por `stdout`; el snapshot se incorpora al
repositorio mediante una acción manual del mantenedor. No existe una escritura
directa desde la CLI hacia `evaluations/`.

## Límite

La evidencia es funcional. No demuestra resistencia a ataques ni utilidad
semántica.
