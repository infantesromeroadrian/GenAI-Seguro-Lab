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

## Perfil vulnerable de evaluación

`GSL-PROFILE-VULNERABLE-001` ya existe como configuración aislada, no
predeterminada y sin capacidad de ejecución. Construye peticiones claramente
marcadas, pero no llama al modelo, no ejecuta herramientas y no genera aquí
ningún resultado.

El corpus adversario ya está fijado fuera de este directorio, con entradas y
oráculos separados, pero el harness, los runs y la baseline de seguridad siguen
pendientes de PGS-03-M04 a PGS-03-M07. Este directorio no debe recibir una
evidencia de ataque antes de implementar el harness y fijar el candidato exacto
de cada ejecución.
