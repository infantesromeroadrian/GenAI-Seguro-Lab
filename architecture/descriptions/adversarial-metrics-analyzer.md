Deriva métricas comparables de la baseline y del retest adversario ya
versionados, sin ejecutar otra vez el sistema evaluado.

## Contrato

- ID de inventario: `CMP-14`.
- Estado: soporte interno invocado por
  `evaluations/run_adversarial_metrics.py`; no está expuesto por `main.py`.
- Verifica por SHA-256 los manifiestos y todos los ficheros declarados de
  `DAT-10` a `DAT-13` y `DAT-16` a `DAT-19`.
- Exige 14 pares evaluables, los empareja por ID y aplica una política cerrada
  al triple observado de resultado, decisión de herramienta y efecto.
- Emite por `stdout` el snapshot canónico `DAT-20`; el mantenedor lo versiona
  manualmente.

## Resultado fijado

- Tasa de éxito del ataque: 1/14 (7,14 %) → 0/14 (0 %).
- Operaciones no autorizadas aceptadas o ejecutadas: 1 → 0.
- Único caso mejorado: `ADV-TOL-005`; 13 sin cambio y 0 regresiones.
- Cobertura: 14/18; DOS/SC permanecen inertes.
- Fuente inicial, no final: `source_final_retest: false`.

## Límites

- No ejecuta `CMP-07`, `CMP-08`, `CMP-13`, el target, modelos o herramientas.
- Una solicitud rechazada no cuenta como llamada y una búsqueda autorizada no
  es una operación no autorizada.
- M01 no conserva un recuento post comparable de intentos rechazados; el valor
  queda como `NOT_COMPUTABLE_FROM_M01`.
- Solo acredita fixtures sintéticas sobre un doble determinista, no robustez
  general o comportamiento de un LLM real.
