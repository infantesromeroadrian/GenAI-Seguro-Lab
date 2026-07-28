Expone las dos operaciones históricas y el arranque del frontal local.

## Responsabilidades

- Parsear `analyze --incident <ID>`, `baseline` y `web --port <PUERTO>`.
- Resolver `data/` desde el checkout.
- Adquirir sin espera el lock advisory de `CMP-10` sobre
  `data/manifest.json` durante toda la operación.
- Convertir fallos esperados en errores saneados.
- Serializar el resultado canónico por `stdout`.
- Abrir y cerrar `CMP-11`; conservar la salida predeterminada y envolverla
  junto al snapshot saneado solo con `--security-report`.

## Restricciones

- Las operaciones históricas no usan red; `web` solo abre HTTP en
  `127.0.0.1`.
- No escribe snapshots o borradores.
- No expone `DraftWriterTool`.
- No permite configurar el bind, CORS o una interfaz remota.
- No espera, reintenta ni crea un lockfile si otra CLI cooperante está activa.
- No escribe o exporta el journal ni lo mezcla con `stderr`.

## Evidencia

- `main.py`
- `src/genai_seguro_lab/cli.py`
- Inventario `CMP-01`
- Control `CMP-10`
- Control `CMP-11`
- Componente `CMP-19`
