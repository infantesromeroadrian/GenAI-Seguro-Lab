Orquesta el retest adversario inicial sobre un candidato endurecido exacto sin
reinterpretar la baseline histórica.

## Contrato

- ID de inventario: `CMP-13`.
- Estado: soporte interno invocado por
  `evaluations/run_adversarial_retest.py`; no está expuesto por `main.py`.
- Exige commit, tree y rama `main` exactos, checkout limpio antes y después,
  `GSL-ROE-001`, datos sintéticos y los 14 IDs PI/JB/EX/TOL en orden.
- Verifica el manifiesto y los artefactos de `CMP-08`, conserva cinco archivos
  de contenido byte-idénticos y declara por separado la deriva de metadatos del
  manifiesto adversario `1.3.0` → `1.4.0`.
- Nunca entrega los oráculos al target ni ejecuta las cuatro fixtures DOS/SC.

## Flujo

1. Fija candidato, runtime, `uv.lock`, referencia histórica, corpus, hashes,
   comando y presupuesto.
2. Reutiliza la única ejecución caso a caso de `CMP-07`.
3. Registra por caso estado, triple observado y relación neutral
   `MATCH`/`DIFF`/`NOT_EVALUATED`.
4. Verifica candidato, corpus y evidencia histórica después de la ejecución.
5. Escribe `DAT-16` a `DAT-19` primero bajo `$TMP`; el mantenedor incorpora
   únicamente la proyección saneada y revisada.

## Evidencia fijada

`GSL-ADV-RT-20260726-001` evaluó una vez el commit `d236bbee`:

- 14 `COMPLETED`, 0 `STOPPED` y 0 `ERROR`;
- 13 relaciones `MATCH` y 1 `DIFF` en `ADV-TOL-005`;
- 0 llamadas externas, 0 € y ninguna fixture inerte ejecutada;
- `final_retest: false`.

## Límites

- `DIFF` no significa por sí mismo mitigación, regresión o eficacia.
- No serializa como medición actual las cuentas históricas de modelo,
  herramienta o efectos; PGS-05-M02 conserva esa interpretación.
- No demuestra robustez frente a ataques desconocidos ni frente a un modelo
  GenAI real.
