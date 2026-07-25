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
oráculos separados. `CMP-07` implementa como pruebas de desarrollo los tres
casos PI, los seis casos de jailbreak y revelación y los cinco casos de abuso de
herramientas, pero no escribe resultados aquí. La baseline adversaria canónica
pertenece a PGS-03-M07. Este directorio no debe recibirla hasta fijar un commit
limpio, configuración, límites, resultados y logs saneados.
