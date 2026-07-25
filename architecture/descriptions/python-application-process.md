Contiene toda la lógica ejecutable del producto en un único proceso Python
local.

## Responsabilidades

- Resolver la CLI desde el checkout.
- Validar el dataset antes de utilizarlo.
- Ejecutar el flujo benigno acotado y el adaptador determinista.
- Autorizar la búsqueda de conocimiento fuera del modelo.
- Exponer internamente la herramienta de borradores sin conectarla a la CLI.
- Construir, solo por factory interna, una petición vulnerable de evaluación
  ligada a datos sintéticos y un sandbox temporal.

## Trust boundary

- ID: `TB-02`.
- Aislamiento real: memoria del proceso.
- Límite: no existe aislamiento interno por subprocess, contenedor o identidad.

## Tecnología

- Python 3.12.8.
- Pydantic 2.13.4.
- Sin framework de agentes o SDK de proveedor.
