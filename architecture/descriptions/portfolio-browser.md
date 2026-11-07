Renderiza la demostración pública en el dispositivo del visitante.

## Responsabilidades

- Cargar únicamente assets y JSON del mismo origen.
- Construir el DOM mediante APIs de texto, sin interpretar contenido como
  HTML.
- Seleccionar localmente el resultado precomputado solicitado.

## Límite

El navegador no dispone de credenciales ni de una ruta hacia el proceso Python
local.
