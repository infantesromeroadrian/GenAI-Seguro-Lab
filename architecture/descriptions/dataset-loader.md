Convierte los ficheros del corpus en un bundle estricto antes de entregarlo al
resto de la aplicación.

## Responsabilidades

- Validar registros Pydantic sin campos adicionales.
- Exigir IDs únicos y referencias existentes.
- Comprobar tipos, conteos y hashes del manifiesto.
- Rechazar datos no sintéticos o registros adversarios en esta versión.

## Tecnología

- Python 3.12.
- Pydantic 2.

## Inventario

- `CMP-02`
- `DAT-01`, `DAT-02` y `DAT-03`
