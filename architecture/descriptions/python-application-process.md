Contiene toda la lógica ejecutable del producto en un único proceso Python
local.

## Responsabilidades

- Resolver la CLI desde el checkout.
- Validar el dataset benigno antes de utilizarlo.
- Validar por API interna las entradas y oráculos adversarios.
- Ejecutar el flujo benigno acotado y el adaptador determinista.
- Autorizar la búsqueda de conocimiento fuera del modelo.
- Exponer internamente la herramienta de borradores sin conectarla a la CLI.
- Construir, solo por factory interna, una petición vulnerable de evaluación
  ligada a datos sintéticos y un sandbox temporal.
- Ejecutar por API interna nueve fixtures PI/JB/EX mediante copias temporales,
  dobles deterministas, guardas del flujo, rechazos de búsqueda y un
  subproceso CLI saneado, siempre sin red ni borradores.

## Trust boundary

- ID: `TB-02`.
- Aislamiento real: memoria del proceso.
- Límite: salvo el subproceso acotado de `ADV-EX-003`, no existe aislamiento
  interno por proceso, contenedor o identidad.

## Tecnología

- Python 3.12.8.
- Pydantic 2.13.4.
- Sin framework de agentes o SDK de proveedor.
