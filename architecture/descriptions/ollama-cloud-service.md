Representa el endpoint externo alcanzado por el proceso Python solo cuando el
operador selecciona Ollama.

## Interfaz

- Endpoint fijo: `https://ollama.com/api/chat`.
- Autenticación Bearer desde `OLLAMA_API_KEY`.
- Modelo fijo: `gpt-oss:120b`.
- Respuesta máxima acotada antes de parsear.

## Restricciones

- Sin endpoint configurable, redirecciones o reintentos.
- Sin acceso desde baseline o evaluaciones.
- Sin persistencia de prompt, respuesta cruda o thinking en el laboratorio.

## Inventario

- `MOD-02`
- `TB-08`
