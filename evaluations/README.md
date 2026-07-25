# Evaluaciones

Este directorio conserva resultados reproducibles del laboratorio sobre el
corpus sintético versionado.

## Baseline funcional benigna v1

`benign-baseline-v1.json` es la instantánea canónica de
`GSL-BASELINE-BENIGN-001`. Se regenera por `stdout` con:

```bash
uv run --frozen python main.py baseline
```

Resultado fijado:

- 12 casos benignos completados;
- 24 invocaciones del adaptador determinista;
- 12 consultas de conocimiento autorizadas;
- 0 llamadas externas;
- 0 € de coste.

El snapshot es evidencia de reproducibilidad y funcionamiento del flujo, no
una medición de resistencia a ataques ni de utilidad semántica.

## Baseline adversaria canónica v1

`adversarial-baseline-v1/` conserva la proyección saneada y revisada de
`GSL-BASELINE-ADVERSARIAL-001`, ejecutada contra el commit exacto
`93aefa45eac687d219bfed32f03be4e60e4a13ed`.

Resultado fijado:

- 14 fixtures PI/JB/EX/TOL evaluadas;
- 13 `PASS`, 1 `RESIDUAL`, 0 `FAIL` y 0 `STOPPED`;
- residual crítico reproducido en `ADV-TOL-005`;
- 14 invocaciones de modelo, 22 solicitudes de herramienta y 23 operaciones
  sobre fronteras de herramienta;
- 2 subprocesos, 1 archivo de efecto temporal, 0 llamadas externas y 0 €.

La configuración, resultados, eventos y manifiesto de integridad están
documentados dentro del propio directorio. Los logs brutos y el sandbox
temporal no se versionan.

## Perfil vulnerable de evaluación

`GSL-PROFILE-VULNERABLE-001` ya existe como configuración aislada, no
predeterminada y sin capacidad de ejecución. Construye peticiones claramente
marcadas, pero no llama al modelo, no ejecuta herramientas y no genera aquí
ningún resultado.

El corpus adversario está fijado fuera de este directorio, con entradas y
oráculos separados. `CMP-07` implementa las pruebas de desarrollo y `CMP-08`
las orquesta para producir primero evidencia bruta bajo `$TMP` y después una
proyección saneada. La aplicación ordinaria no escribe estos resultados.
