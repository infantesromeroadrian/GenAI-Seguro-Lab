Ejecuta el contrato cerrado de PGS-05-M07 sobre un único candidato final
fijado, sin añadir una ruta de producto.

## Responsabilidades

- Verificar el commit `77edd64037bb0e41edffa58cae2682ba7d2694d2`, su
  árbol `bc09b78f7f3d85f94241f9955e79abb264bd89de`, las fuentes del
  evaluador y 15 artefactos históricos M01–M06.
- Validar `DAT-24`, con 24 hallazgos, 36 acciones y 24 prohibiciones ligados
  por hash a fuentes o invariantes autorizados.
- Materializar el target mediante `git archive` bajo `$TMP`, bloquear red y
  credenciales y mantener la rúbrica, los oráculos y `expected_result` fuera
  de sus peticiones.
- Ejecutar 14 fixtures adversarias, 12 casos benignos y dos probes de frontera;
  las cuatro entradas DOS/SC siguen inertes.
- Evaluar las observaciones después de congelar la salida y emitir una
  proyección saneada por `stdout`.

El run canónico `GSL-FINAL-RT-20260727-001` se ejecutó una sola vez desde el
evaluador `636e1db` y produjo `DAT-25`: 14/14 casos adversarios y 12/12 benignos
completos, cero regresiones y falsos rechazos, y `SC-06`/`SC-07` demostrados
dentro de la rúbrica cerrada.

## Límites

- No forma parte de `main.py`, no acepta argumentos y no escribe evidencia.
- El run canónico requiere que el evaluador y `DAT-24` estén comprometidos y
  separados del árbol candidato.
- `final_retest` identifica provenance del run; no demuestra seguridad
  general, robustez ante ataques desconocidos o utilidad con un modelo real.
- La rúbrica es una comprobación cerrada de trazabilidad. Mantiene
  `general_semantic_equivalence_evaluated: false`, no usa juez LLM y no
  reinterpreta `CF-002` o `DAT-22`.

## Evidencia

- `src/genai_seguro_lab/final_retest.py`
- `evaluations/run_final_retest.py`
- `evaluations/final-retest-rubric-v1.json`
- `evaluations/final-retest-v1.json`
- `tests/test_final_retest.py`
