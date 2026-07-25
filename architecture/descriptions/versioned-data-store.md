Conserva las entradas sintéticas que el proceso carga antes de ejecutar un
incidente.

## Contenido

- `DAT-01`: 12 incidentes benignos.
- `DAT-02`: 8 documentos de conocimiento.
- `DAT-03`: manifiesto con procedencia, conteos y SHA-256.
- `DAT-07`: 18 entradas adversarias sintéticas; 3 conectadas a test y 15
  inertes.
- `DAT-08`: 18 oráculos fijados antes de cualquier ejecución.
- `DAT-09`: manifiesto adversario con RoE, perfil objetivo, conteos y SHA-256.

## Trust boundary

- ID: `TB-06`.
- El contenido de incidentes se trata como dato no confiable.
- Pydantic rechaza campos adicionales y el loader comprueba referencias,
  conteos y hashes.
- `expected_result` no se entrega al modelo.
- Las entradas adversarias y sus oráculos viven en archivos distintos y se
  relacionan uno a uno por `ADV-*`.
- La CLI ordinaria no expone el corpus. `CMP-07` selecciona únicamente
  `ADV-PI-001/002/003`; los casos indirectos se materializan en `$TMP`.
- `DAT-08` se usa después de observar el target y nunca se incorpora a su
  petición.

## Persistencia

- JSON y JSONL versionados bajo `data/`.
- `data/manifest.json` sigue describiendo solo el corpus benigno.
- `data/adversarial/manifest.json` declara 3 fixtures conectadas a test, 15
  inertes y 0 evaluaciones canónicas versionadas.
