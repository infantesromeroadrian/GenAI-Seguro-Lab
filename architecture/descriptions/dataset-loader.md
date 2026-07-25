Convierte los ficheros benignos en el bundle usado por la aplicación y valida
por separado el corpus adversario mediante una API interna.

## Responsabilidades

- Validar registros Pydantic sin campos adicionales.
- Exigir IDs únicos y referencias existentes.
- Comprobar tipos, conteos y hashes del manifiesto.
- Rechazar datos no sintéticos o registros adversarios dentro del bundle
  benigno.
- Unir cada entrada adversaria con un único oráculo sin mezclar ambos archivos.
- Exigir 18 fixtures, los 17 abuse cases, seis familias y los límites de las
  RoE.
- Verificar que tres fixtures PI están conectadas al harness de test y que las
  otras quince permanecen inertes.
- Devolver el bundle en memoria sin interpretar payloads ni entregar oráculos
  al target.

## Tecnología

- Python 3.12.
- Pydantic 2.

## Inventario

- `CMP-02`
- `DAT-01`, `DAT-02`, `DAT-03`, `DAT-07`, `DAT-08` y `DAT-09`
