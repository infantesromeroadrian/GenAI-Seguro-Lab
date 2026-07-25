# Corpus adversario sintético

Este directorio conserva `GSL-ADVERSARIAL-CORPUS-001` v1.2.0. Las tres
fixtures de prompt injection y las seis de jailbreak y revelación están
conectadas al harness interno por PGS-03-M04/M05; las otras nueve permanecen
inertes. La CLI ordinaria no expone el corpus y todavía no existe una
evaluación adversaria canónica versionada.

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
Los oráculos están en un archivo distinto para que `CMP-07` entregue solo la
entrada al sistema evaluado. Pytest compara el oráculo después. El loader
comprueba:

- esquema estricto y ausencia de campos adicionales;
- procedencia `authored_for_lab`, `synthetic: true` y
  `synthetic_internal`;
- IDs únicos y correspondencia uno a uno entre entrada y oráculo;
- cobertura de 17 abuse cases y seis familias;
- límite de 64 KiB por entrada y 10 MiB acumulados;
- hashes y conteos del manifiesto;
- exactamente 9 registros `test_wired` y 9 `inert_not_wired`;
- cero evaluaciones canónicas versionadas;
- estado `requires_extension` exclusivamente para `AC-DOS-03`.

`AC-DOS-03` es solo un descriptor no materializado. No crea un dataset grande
y no puede ejecutarse bajo las RoE actuales.

## Verificación

Desde la raíz:

```bash
uv run --frozen pytest tests/test_adversarial_corpus.py
uv run --frozen pytest tests/test_prompt_injection_evaluation.py
uv run --frozen pytest tests/test_jailbreak_disclosure_evaluation.py
```

La primera comprobación solo carga y valida archivos. La segunda ejecuta
únicamente `ADV-PI-001/002/003`. La tercera cubre `ADV-JB-001/002/003` y
`ADV-EX-001/002/003`: dos inyecciones de contenido en `$TMP`, dos guardas del
ciclo del modelo, dos rechazos de conocimiento y un error de CLI con marcador
señuelo. Ninguna usa red, proveedor, datos reales, borradores o escritura en el
checkout.
