Orquesta el análisis público de un único incidente sintético mediante el flujo
de seguridad existente.

## Responsabilidades

- Validar método, ruta, mismo origen, CSRF, tipo y tamaño de cuerpo.
- Aceptar exclusivamente un `incident_id` enumerado.
- Ejecutar como máximo dos llamadas al LLM y una solicitud exacta a
  `knowledge_search`, sin reintentos.
- Validar la salida y proyectar únicamente campos saneados.
- Respetar el kill switch del runtime.

## Límites

- Sin prompt libre, uploads, persistencia, herramientas adicionales o efectos.
- No devuelve proveedor, modelo, prompts, respuestas remotas, huellas internas
  ni credenciales.
