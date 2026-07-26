Orquesta un ciclo fijo de modelo, búsqueda autorizada y respuesta final.

## Responsabilidades

- Construir una petición inicial que trata el incidente como dato no confiable.
- Consumir en `CMP-10` caso, dos invocaciones, una solicitud y una ejecución,
  verificando además tamaños y plazo antes y después de cada frontera.
- Exigir exactamente una solicitud `knowledge_search`.
- Solicitar al catálogo una vista con las referencias exactas del incidente y
  usar su grant `benign-flow` ligado a ese scope.
- Incorporar el resultado tipado y exigir una respuesta final en la segunda
  invocación.
- Validar que la salida final pertenece al incidente y solo cita los
  documentos realmente devueltos por la búsqueda.
- Aplicar `CMP-09` al resumen y sustituir las invocaciones brutas por una
  proyección de métricas antes de devolver el resultado.

## Restricciones

- Exactamente dos invocaciones de modelo.
- Una única herramienta por incidente.
- El catálogo anunciado al modelo no concede ni amplía el grant.
- Sin bucles abiertos o reintentos.
- Sin ruta hacia `DraftWriterTool`.
- La política de salida es obligatoria y no puede configurarla el modelo.
- Cualquier salida libre, campo adicional, afirmación de efecto o referencia
  fuera de alcance falla cerrada.
- Un exceso de recursos descarta el resultado y no produce una salida parcial.

## Inventario

- `CMP-03`
- `CMP-10`
