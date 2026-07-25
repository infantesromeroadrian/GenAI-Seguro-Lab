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
una medición de resistencia a ataques ni de utilidad semántica. El perfil
vulnerable, el corpus adversario y la baseline de seguridad pertenecen a
PGS-03.
