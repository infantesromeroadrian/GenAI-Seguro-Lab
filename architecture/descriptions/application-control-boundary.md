Agrupa la lógica que conserva el control de ejecución frente a datos y salidas
del modelo.

## Trust boundary

- ID: `TB-02`.
- Incluye CLI, contrato de datos, flujo benigno, motor de baseline y perfil
  vulnerable de evaluación.
- Decide qué datos se cargan, qué herramienta se autoriza y cuándo termina el
  flujo.
- El perfil de evaluación solo construye una petición y no participa en el
  flujo ordinario.

## Límite

Es una separación lógica dentro del mismo proceso Python. No constituye una
cuenta, sandbox o proceso aislado.
