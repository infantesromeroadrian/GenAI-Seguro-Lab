Convierte los ficheros benignos en el bundle usado por la aplicación y permite
validar por separado el corpus adversario inerte mediante una API interna.

## Responsabilidades

- Validar registros Pydantic sin campos adicionales.
- Exigir IDs únicos y referencias existentes.
- Comprobar tipos, conteos y hashes del manifiesto.
- Rechazar datos no sintéticos o registros adversarios dentro del bundle
  benigno.
- Unir cada entrada adversaria con un único oráculo sin mezclar ambos archivos.
- Exigir 18 fixtures, los 17 abuse cases, seis familias y los límites de las
  RoE.
- Devolver el bundle adversario en memoria sin interpretarlo, conectarlo o
  ejecutarlo.

## Tecnología

- Python 3.12.
- Pydantic 2.

## Inventario

- `CMP-02`
- `DAT-01`, `DAT-02`, `DAT-03`, `DAT-07`, `DAT-08` y `DAT-09`
