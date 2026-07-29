Traduce el contrato local de modelo a la API de chat alojada de Ollama.

## Responsabilidades

- Enviar `POST https://ollama.com/api/chat` con `gpt-oss:120b`.
- Leer `OLLAMA_API_KEY` únicamente en tiempo de ejecución.
- Anunciar solo `knowledge_search` en la primera llamada y ninguna herramienta
  en la segunda.
- Rechazar redirects, respuestas sobredimensionadas, secuencias inválidas y
  errores de proveedor con mensajes saneados.
- Descartar thinking y metadatos remotos antes de devolver una respuesta
  tipada.

## Límites

- Dos llamadas como máximo, 60 segundos por llamada y cero reintentos.
- Coste desconocido y comportamiento probabilístico.
- El transporte falso verifica el contrato; el servicio real se comprueba
  aparte.

## Inventario

- `CMP-20`
- `MOD-02`
- `TB-08`
