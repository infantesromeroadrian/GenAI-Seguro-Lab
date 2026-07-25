# Corpus sintético

Este directorio contiene el corpus benigno inicial de GenAI Seguro Lab. Todos
los registros son ficticios, se han redactado expresamente para el laboratorio
y no describen personas, organizaciones, credenciales o incidentes reales.

## Inventario

| Archivo | Contenido | Registros |
|---|---|---:|
| `incidents.jsonl` | Incidentes benignos sintéticos | 12 |
| `knowledge.jsonl` | Procedimientos de conocimiento sintético | 8 |
| `manifest.json` | Versión, conteos, procedencia y hashes SHA-256 | 1 |

Los ocho temas cubiertos son `phishing`, `identity`, `endpoint`,
`data_protection`, `availability`, `cloud_configuration`, `supply_chain` y
`physical_device`.

## Contrato

El esquema ejecutable está en
`src/genai_seguro_lab/data_contract.py`. Pydantic valida los registros en modo
estricto, rechaza campos adicionales y exige:

- identificador y tipo compatibles con el archivo;
- procedencia `authored_for_lab`;
- autor `GenAI Seguro Lab`;
- `synthetic: true`;
- sensibilidad `synthetic_internal`;
- resultado esperado y herramientas permitidas;
- referencias a documentos de conocimiento existentes;
- identificadores únicos, conteos y hashes coincidentes con el manifiesto.

El manifiesto declara cero registros adversarios. Las fixtures adversarias
controladas pertenecen a PGS-03 y no forman parte de este corpus.

## Verificación

Desde la raíz del repositorio:

```bash
uv run --frozen pytest tests/test_data_contract.py
```

La verificación detecta cambios no reflejados en los hashes, referencias
inválidas, datos no sintéticos y desviaciones del esquema. Si se modifica
deliberadamente un archivo JSONL, hay que revisar el cambio y actualizar su
hash en `manifest.json` dentro de la misma unidad funcional.
