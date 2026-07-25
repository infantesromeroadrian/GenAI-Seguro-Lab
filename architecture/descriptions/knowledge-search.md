Busca coincidencias únicamente dentro de documentos sintéticos ya validados y
cargados en memoria.

## Responsabilidades

- Aceptar solo `knowledge_search`.
- Validar consulta, IDs y límite mediante Pydantic.
- Exigir una `ToolExecutionPolicy` aportada por la aplicación.
- Comprobar que la herramienta está permitida, que la allowlist solo contiene
  IDs conocidos y que los IDs solicitados son un subconjunto autorizado.
- Ordenar coincidencias de forma determinista.

## Restricciones

- Sin filesystem.
- Sin red.
- Sin escritura.
- Sin política explícita no existe invocación válida.

## Evidencia

- `src/genai_seguro_lab/local_tools.py`
- Inventario `TOL-01`
