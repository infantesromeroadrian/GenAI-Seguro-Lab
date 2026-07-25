Busca coincidencias únicamente dentro de documentos sintéticos ya validados y
cargados en memoria.

## Responsabilidades

- Aceptar solo `knowledge_search`.
- Validar consulta, IDs y límite mediante Pydantic.
- Ser creada únicamente por `KnowledgeCatalog` con los documentos exactos del
  incidente validado.
- Exigir el `ToolExecutionGrant` emitido para su principal, scope e instancia.
- Comprobar que los IDs solicitados existen en la vista físicamente retenida.
- Ordenar coincidencias de forma determinista.

## Restricciones

- Sin filesystem.
- Sin red.
- Sin escritura.
- Sin el grant exacto de la instancia no existe invocación válida.

## Evidencia

- `src/genai_seguro_lab/local_tools.py`
- Inventario `TOL-01`
