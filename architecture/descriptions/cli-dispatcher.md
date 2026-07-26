Expone las únicas dos operaciones alcanzables por el operador local.

## Responsabilidades

- Parsear `analyze --incident <ID>` y `baseline`.
- Resolver `data/` desde el checkout.
- Adquirir sin espera el lock advisory de `CMP-10` sobre
  `data/manifest.json` durante toda la operación.
- Convertir fallos esperados en errores saneados.
- Serializar el resultado canónico por `stdout`.

## Restricciones

- No usa red.
- No escribe snapshots o borradores.
- No expone `DraftWriterTool`.
- No espera, reintenta ni crea un lockfile si otra CLI cooperante está activa.

## Evidencia

- `main.py`
- `src/genai_seguro_lab/cli.py`
- Inventario `CMP-01`
- Control `CMP-10`
