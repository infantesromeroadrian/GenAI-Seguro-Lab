Orquesta un ciclo fijo de modelo, búsqueda autorizada y respuesta final.

## Responsabilidades

- Construir una petición inicial que trata el incidente como dato no confiable.
- Exigir exactamente una solicitud `knowledge_search`.
- Autorizar la consulta mediante las referencias del incidente.
- Incorporar el resultado tipado y exigir una respuesta final en la segunda
  invocación.

## Restricciones

- Exactamente dos invocaciones de modelo.
- Una única herramienta por incidente.
- Sin bucles abiertos o reintentos.
- Sin ruta hacia `DraftWriterTool`.

## Inventario

- `CMP-03`
