Servicio externo opcional que ejecuta el modelo `gpt-oss:120b`.

## Datos intercambiados

- Recibe únicamente la tarea, el incidente y el conocimiento sintéticos
  necesarios para una operación `analyze`.
- Devuelve una solicitud de herramienta y una respuesta final no confiables.
- No recibe oráculos, rúbricas, evidencias históricas, rutas locales o datos
  reales.

## Límite de confianza

- Está fuera del host local y cruza `TB-08` mediante HTTPS.
- Su disponibilidad, cuota, coste y comportamiento no forman parte de
  `DAT-25`.

## Inventario

- `MOD-02`
- `TB-08`
