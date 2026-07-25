Representa al código llamador que puede utilizar directamente la API Python de
borradores, fuera de las operaciones expuestas por la CLI.

## Responsabilidades

- Entregar una petición `draft_create` válida.
- Revisar la propuesta resultante.
- Aportar después una confirmación ligada a la huella exacta.

## Límite

`confirmed_by_user: true` expresa consentimiento declarado, pero no autentica
la identidad humana. No existe una ruta desde `main.py` hasta esta capacidad.

## Inventario

- `ACT-03`
- `IDN-03`
