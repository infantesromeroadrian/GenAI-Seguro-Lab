Orquesta un ciclo fijo de modelo, búsqueda autorizada y respuesta final.

## Responsabilidades

- Construir una petición inicial que trata el incidente como dato no confiable.
- Exigir exactamente una solicitud `knowledge_search`.
- Solicitar al catálogo una vista con las referencias exactas del incidente y
  usar su grant `benign-flow` ligado a ese scope.
- Incorporar el resultado tipado y exigir una respuesta final en la segunda
  invocación.
- Validar que la salida final pertenece al incidente y solo cita los
  documentos realmente devueltos por la búsqueda.

## Restricciones

- Exactamente dos invocaciones de modelo.
- Una única herramienta por incidente.
- El catálogo anunciado al modelo no concede ni amplía el grant.
- Sin bucles abiertos o reintentos.
- Sin ruta hacia `DraftWriterTool`.
- Cualquier salida libre, campo adicional, afirmación de efecto o referencia
  fuera de alcance falla cerrada.

## Inventario

- `CMP-03`
