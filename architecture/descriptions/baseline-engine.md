Construye los intercambios deterministas y agrega la evidencia funcional de uno
o doce incidentes.

## Responsabilidades

- Guionizar las dos respuestas esperadas para cada incidente.
- Instanciar el modelo determinista, el catálogo y una vista/grant de
  conocimiento independiente por incidente.
- Ejecutar `run_incident()` o `run_functional_baseline()`.
- Compartir un único perfil `baseline` de `CMP-10`: 12 casos, 24 invocaciones,
  12 solicitudes y ejecuciones dentro de cinco segundos cooperativos.
- Compartir un único `CMP-11`: correlación primaria para inicio/cierre y una
  correlación hija opaca distinta por caso, con secuencia global.
- Contar invocaciones, tool requests, coste y llamadas externas.

## Persistencia

Devuelve modelos Pydantic que la CLI serializa. No escribe directamente
`evaluations/benign-baseline-v1.json`.

## Inventario

- `CMP-04`
- `CMP-05`
- `CMP-10`
- `CMP-11`
