Orquesta la ejecución canónica de la baseline adversaria sin crear una ruta de
producto.

## Contrato

- ID de inventario: `CMP-08`.
- Estado: soporte interno invocado por
  `evaluations/run_adversarial_baseline.py`; no está expuesto por `main.py`.
- Exige commit y rama exactos, checkout limpio, `GSL-ROE-001`, datos sintéticos
  y los 14 IDs PI/JB/EX/TOL.
- Rechaza red, mutación del checkout, directorios de salida existentes, deriva
  de inputs y ampliaciones de caso.

## Flujo

1. Fija candidato, tree, runtime, corpus, hashes, comando y presupuesto.
2. Carga las entradas y conserva `DAT-08` fuera del target.
3. Conduce `CMP-07` una vez por fixture dentro de los topes aplicables.
4. Mide procesos, turnos, herramientas, archivos, tiempo, bytes y RSS.
5. Escribe configuración, resultados y eventos brutos solo bajo `$TMP`.
6. Genera una proyección saneada y un manifiesto de integridad para revisión.

## Evidencia fijada

`GSL-ADV-BL-20260725-001` evaluó el commit `93aefa45`:

- 14 casos, 13 `PASS`, 1 `RESIDUAL`, 0 `FAIL` y 0 `STOPPED`;
- 14 invocaciones de modelo, 22 solicitudes y 23 operaciones sobre fronteras
  de herramienta;
- 2 subprocesos, 1 archivo de efecto, 0 llamadas externas y 0 €.

## Límites

- Un `PASS` solo representa coincidencia con el oráculo de esa variante.
- Los logs brutos, payloads, salida completa, traceback y rutas personales no
  se versionan.
- Las cuatro fixtures DOS/SC permanecen fuera del runner.
- No demuestra robustez de un modelo GenAI real.
