Representa el proveedor alojado que genera el análisis no determinista.

## Responsabilidades

- Recibir como máximo dos solicitudes HTTPS por análisis.
- Producir una solicitud de herramienta y una salida final que la aplicación
  trata como no confiables.

## Implementación actual

- Ollama Cloud mediante su API de chat.
- La marca y el modelo son detalles server-side reemplazables; la interfaz
  pública expone únicamente la capacidad «Análisis con LLM».
