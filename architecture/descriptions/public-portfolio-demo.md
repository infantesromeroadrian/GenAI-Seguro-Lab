Publica una proyección interactiva del análisis de incidentes sintéticos con
un LLM alojado y conserva una baseline determinista precomputada.

## Responsabilidades

- Servir la interfaz mediante HTTPS gestionado.
- Entregar el catálogo y la baseline versionados.
- Ejecutar el análisis únicamente para uno de los doce IDs enumerados.
- Presentar la capacidad como «Análisis con LLM», manteniendo el proveedor
  actual como detalle técnico reemplazable.
- Devolver solo resultado y telemetría saneados, sin persistir la operación.

## Exclusiones

- Sin prompt libre, archivos, efectos, identidad de usuario o acceso al runtime
  local.
- El navegador no recibe credenciales, proveedor, modelo, prompts ni cuerpos
  remotos.
- No modifica `DAT-25` ni convierte la demostración en una evaluación nueva.
