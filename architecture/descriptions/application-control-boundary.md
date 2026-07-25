Agrupa la lógica que conserva el control de ejecución frente a datos y salidas
del modelo.

## Trust boundary

- ID: `TB-02`.
- Incluye CLI, contrato de datos, flujo benigno, motor de baseline, perfil
  vulnerable de evaluación y harness interno de prompt injection.
- Decide qué datos se cargan, qué herramienta se autoriza y cuándo termina el
  flujo.
- El harness selecciona solo las tres fixtures PI y nunca entrega el oráculo
  al target.
- Los casos indirectos conectan una copia temporal al perfil, al doble
  determinista y a una única búsqueda autorizada; no forman parte del flujo
  ordinario ni de la CLI.

## Límite

Es una separación lógica dentro del mismo proceso Python. No constituye una
cuenta, sandbox o proceso aislado.
