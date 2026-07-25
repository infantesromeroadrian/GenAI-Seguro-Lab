Representa al código llamador que puede utilizar directamente la API Python de
borradores, fuera de las operaciones expuestas por la CLI.

## Responsabilidades

- Entregar una petición `draft_create` válida.
- Revisar la propuesta resultante.
- Solicitar después un challenge ligado al contexto exacto.
- Presentar a la autoridad la identidad y credencial sintéticas configuradas.
- Recibir una aprobación opaca y un grant de efecto efímero.

## Límite

La autoridad autentica el principal sintético configurado, pero no comprueba
que una persona real haya visto o aprobado el contenido. No existe una ruta
desde `main.py` hasta esta capacidad.

## Inventario

- `ACT-03`
- `IDN-03`
