Conserva las entradas sintéticas que el proceso carga antes de ejecutar un
incidente.

## Contenido

- `DAT-01`: 12 incidentes benignos.
- `DAT-02`: 8 documentos de conocimiento.
- `DAT-03`: manifiesto con procedencia, conteos y SHA-256.

## Trust boundary

- ID: `TB-06`.
- El contenido de incidentes se trata como dato no confiable.
- Pydantic rechaza campos adicionales y el loader comprueba referencias,
  conteos y hashes.
- `expected_result` no se entrega al modelo.

## Persistencia

- JSON y JSONL versionados bajo `data/`.
