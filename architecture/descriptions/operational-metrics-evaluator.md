# CMP-16 · Evaluador de métricas operativas

Componente de soporte offline que compara el mismo baseline benigno entre dos
candidatos Git fijados sin cambiar el checkout.

## Responsabilidades

- Verificar commits, árboles y los SHA-256 comunes de corpus, `main.py`,
  `pyproject.toml` y `uv.lock`.
- Materializar ambos candidatos mediante `git archive` bajo `$TMP`.
- Ejecutar tres pares de calentamiento y 30 pares medidos, alternando AB/BA,
  con un proceso nuevo por muestra y el mismo intérprete.
- Medir tiempo de pared, CPU y RSS, validar cada salida y conservar solo su
  tamaño, hash e identidades cerradas.
- Derivar mediana, MAD y p95, contadores deterministas, coste externo y un
  vector descriptivo de complejidad.
- Emitir `DAT-22` por `stdout` para su revisión y versionado manual.

## Límites

- No está conectado a `CMP-01` ni añade una ruta de producto.
- No instala dependencias, cambia el checkout, usa un worktree, elimina
  outliers, reintenta o escribe directamente en `evaluations/`.
- Las 12 ejecuciones de herramienta precontroles son una derivación de una
  búsqueda satisfactoria por caso, no un contador histórico directo.
- La medición representa un host y una sesión; incluye arranque de proceso y
  no mide energía, amortización, trabajo humano, concurrencia o carga
  sostenida.
- El proceso hijo recibe un entorno allowlisted, pero no existe aislamiento de
  red a nivel kernel.

## Evidencia

- `src/genai_seguro_lab/operational_metrics.py`
- `evaluations/run_operational_metrics.py`
- `evaluations/operational-metrics-v1.json`
- `tests/test_operational_metrics.py`
