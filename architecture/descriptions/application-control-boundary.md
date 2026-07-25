Agrupa la lógica que conserva el control de ejecución frente a datos y salidas
del modelo.

## Trust boundary

- ID: `TB-02`.
- Incluye CLI, contrato de datos, flujo benigno, motor de baseline, perfil
  vulnerable de evaluación y harness adversario interno.
- Decide qué datos se cargan, qué herramienta se autoriza y cuándo termina el
  flujo.
- El harness selecciona solo nueve fixtures PI/JB/EX y nunca entrega el
  oráculo al target.
- Los casos indirectos conectan una copia temporal al perfil, al doble
  determinista y a una búsqueda autorizada; los JB/EX añaden guardas,
  rechazos de búsqueda y una comprobación CLI saneada. Ninguno forma parte del
  flujo ordinario ni habilita una ruta adversaria en la CLI.

## Límite

Es una separación lógica dentro del mismo proceso Python. No constituye una
cuenta, sandbox o proceso aislado.
