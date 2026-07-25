Agrupa todos los procesos y ficheros del laboratorio observados en el mismo Mac
local.

## Trust boundary

- ID: `TB-01`.
- Identidad efectiva: cuenta local de macOS que lanza Python.
- Aislamiento: permisos ordinarios del host; no hay contenedor o usuario de
  servicio dedicado.

## Consecuencia

Los controles internos reducen la autoridad de las herramientas, pero no
reducen los permisos generales del proceso a nivel de sistema operativo.

## Evidencia

- Checkout físico local.
- `.venv/` local.
- Ausencia de Docker, IaC y configuración cloud.
