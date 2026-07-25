Busca coincidencias únicamente dentro de documentos sintéticos ya validados y
cargados en memoria.

## Responsabilidades

- Aceptar solo `knowledge_search`.
- Validar consulta, IDs y límite mediante Pydantic.
- Exigir que los IDs solicitados estén en la allowlist del incidente y en el
  índice conocido.
- Ordenar coincidencias de forma determinista.

## Restricciones

- Sin filesystem.
- Sin red.
- Sin escritura.

## Evidencia

- `src/genai_seguro_lab/local_tools.py`
- Inventario `TOL-01`
