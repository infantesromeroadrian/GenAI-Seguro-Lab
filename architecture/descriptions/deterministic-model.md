Simula la frontera de un modelo mediante respuestas exactas preparadas en
memoria.

## Responsabilidades

- Calcular una huella SHA-256 de la petición completa.
- Devolver únicamente la respuesta guionizada para esa huella.
- Rechazar peticiones desconocidas sin repetir su contenido en el error.
- Transportar tool requests tipadas sin ejecutarlas.

## Descriptor

- Provider: `deterministic`.
- Model: `scripted-v1`.
- Llamadas externas: `false`.
- Coste: 0 €.

## Inventario

- `MOD-01`
