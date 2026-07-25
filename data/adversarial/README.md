# Corpus adversario sintético

Este directorio prepara `GSL-ADVERSARIAL-CORPUS-001` como material inerte para
las futuras pruebas de PGS-03. No está conectado a la CLI, al perfil
vulnerable, al modelo ni a las herramientas, y su creación no ha ejecutado
ningún ataque.

## Inventario

| Archivo | Contenido | Registros |
|---|---|---:|
| `inputs.jsonl` | Entradas o descriptores adversarios sintéticos | 18 |
| `oracles.jsonl` | Resultados esperados fijados antes de ejecutar | 18 |
| `manifest.json` | Versión, RoE, perfil objetivo, conteos y SHA-256 | 1 |

Las 18 fixtures cubren exactamente los 17 abuse cases de
`GSL-ABUSE-CASES-001` y las seis familias aprobadas. `AC-JB-01` tiene dos
variantes para separar una afirmación falsa de compromiso de una afirmación
falsa de acciones ejecutadas.

## Separación entre entrada y oráculo

Cada `ADV-*` tiene exactamente una entrada y un oráculo unidos por `case_id`.
Los oráculos están en un archivo distinto para que un futuro harness pueda
entregar solo la entrada al sistema evaluado. El loader comprueba:

- esquema estricto y ausencia de campos adicionales;
- procedencia `authored_for_lab`, `synthetic: true` y
  `synthetic_internal`;
- IDs únicos y correspondencia uno a uno entre entrada y oráculo;
- cobertura de 17 abuse cases y seis familias;
- límite de 64 KiB por entrada y 10 MiB acumulados;
- hashes y conteos del manifiesto;
- estado `requires_extension` exclusivamente para `AC-DOS-03`.

`AC-DOS-03` es solo un descriptor no materializado. No crea un dataset grande
y no puede ejecutarse bajo las RoE actuales.

## Verificación

Desde la raíz:

```bash
uv run --frozen pytest tests/test_adversarial_corpus.py
```

Esta comprobación solo carga y valida archivos. No construye el perfil
vulnerable, no llama al modelo, no ejecuta herramientas, no inicia procesos y
no escribe en el sandbox.
