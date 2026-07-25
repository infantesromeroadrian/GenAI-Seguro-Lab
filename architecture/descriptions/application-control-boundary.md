Agrupa la lógica que conserva el control de ejecución frente a datos y salidas
del modelo.

## Trust boundary

- ID: `TB-02`.
- Incluye CLI, contrato de datos, flujo benigno, motor de baseline, perfil
  vulnerable de evaluación, harness adversario interno y runner canónico.
- Decide qué datos se cargan, qué herramienta se autoriza y cuándo termina el
  flujo.
- Emite un principal y scope lógicos por operación y no deriva la autoridad
  ejecutable del catálogo anunciado al modelo.
- Proyecta para `TOL-01` únicamente las referencias del incidente validado.
- El harness selecciona solo 14 fixtures PI/JB/EX/TOL y nunca entrega el
  oráculo al target.
- `CMP-08` exige un commit limpio exacto, aplica los presupuestos y escribe
  evidencia bruta únicamente bajo `$TMP`; no forma parte de la CLI de producto.
- Los casos indirectos conectan una copia temporal al perfil, al doble
  determinista y a una búsqueda autorizada; los JB/EX añaden guardas,
  rechazos de búsqueda y una comprobación CLI saneada. TOL añade llamadas
  internas confinadas a las fronteras existentes y un único efecto temporal
  conocido. Ninguno forma parte del flujo ordinario ni habilita una ruta
  adversaria en la CLI.

## Límite

Es una separación lógica dentro del mismo proceso Python. No constituye una
cuenta, sandbox o proceso aislado. Los grants no reducen los permisos de
`IDN-01` ni protegen frente a ejecución arbitraria de Python.
