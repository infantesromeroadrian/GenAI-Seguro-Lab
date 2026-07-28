Inicia las operaciones expuestas del laboratorio desde una terminal o un
navegador local y consume el resultado JSON saneado.

## Responsabilidades

- Elegir `analyze` o `baseline` desde CLI o desde el frontal de loopback.
- Proporcionar un identificador de incidente cuando usa `analyze`.
- Interpretar la salida sin asumir que constituye una evaluación de seguridad.

## Autoridad

- No inicia sesión en la aplicación.
- El proceso utiliza los permisos de su cuenta local de macOS.
- No puede alcanzar `DraftWriterTool` mediante las rutas expuestas.

## Inventario

- `ACT-01`
