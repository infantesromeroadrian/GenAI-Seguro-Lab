Conserva las entradas sintéticas que el proceso carga antes de ejecutar un
incidente.

## Contenido

- `DAT-01`: 12 incidentes benignos.
- `DAT-02`: 8 documentos de conocimiento.
- `DAT-03`: manifiesto con procedencia, conteos y SHA-256.
- `DAT-07`: 18 entradas adversarias sintéticas e inertes.
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
- El bundle adversario no está conectado a la CLI, al perfil, al modelo ni a
  las herramientas.

## Persistencia

- JSON y JSONL versionados bajo `data/`.
- `data/manifest.json` sigue describiendo solo el corpus benigno;
  `data/adversarial/manifest.json` declara cero conexiones y cero ejecuciones.
