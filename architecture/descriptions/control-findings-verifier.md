Verifica offline el registro canónico y revisado de hallazgos de
PGS-05-M05.

## Responsabilidades

- Cargar `DAT-23` con un esquema estricto e inmutable.
- Verificar los SHA-256 y contratos cerrados de `DAT-20`, `DAT-21` y
  `DAT-22`.
- Resolver 44 referencias escalares fijadas por JSON Pointer y comprobar sus
  valores esperados.
- Recalcular el resumen de seis hallazgos y emitir un informe efímero y
  saneado por `stdout`.

## Límites

- No genera, clasifica, modifica o versiona hallazgos.
- No ejecuta targets, evaluadores, runners, harness, modelos o herramientas.
- No usa red ni escribe evidencia.
- No decide qué corregir en M06, acepta riesgo residual o cambia el estado del
  retest final.
- La ausencia de fallos o bypasses actuales se limita a las 14 fixtures
  medidas por las fuentes fijadas.

## Evidencia

- `src/genai_seguro_lab/control_findings.py`
- `evaluations/control-findings-v1.json`
- `evaluations/verify_control_findings.py`
- `tests/test_control_findings.py`
