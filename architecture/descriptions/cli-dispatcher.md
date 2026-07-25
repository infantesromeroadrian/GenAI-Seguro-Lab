Expone las únicas dos operaciones alcanzables por el operador local.

## Responsabilidades

- Parsear `analyze --incident <ID>` y `baseline`.
- Resolver `data/` desde el checkout.
- Convertir fallos esperados en errores saneados.
- Serializar el resultado canónico por `stdout`.

## Restricciones

- No usa red.
- No escribe snapshots o borradores.
- No expone `DraftWriterTool`.

## Evidencia

- `main.py`
- `src/genai_seguro_lab/cli.py`
- Inventario `CMP-01`
