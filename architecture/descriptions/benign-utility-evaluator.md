Compara la utilidad funcional de los 12 casos benignos antes y después de los
controles sin ampliar la superficie del producto.

## Responsabilidades

- Verificar el commit y el árbol de la proyección precontroles.
- Verificar el dataset, la baseline funcional vigente y ocho fuentes de
  producto antes de ejecutar.
- Repetir cada incidente por separado mediante `CMP-03`, `MOD-01`, `TOL-01`,
  `CMP-09`, `CMP-10` y `CMP-11`.
- Comparar los oráculos únicamente después de observar la salida.
- Separar terminación técnica, rechazo de control y error de runtime.
- Medir cobertura textual exacta con normalización NFKC, `casefold` y espacios,
  sin presentarla como equivalencia semántica.
- Emitir `DAT-21` saneado por `stdout` para su versionado deliberado.

## Límites

- No está conectado a la CLI de producto.
- No entrega oráculos al modelo, la herramienta o la política.
- No escribe evidencia ni modifica código, corpus o sandbox.
- No usa red, proveedor, `TOL-02` o efectos externos.
- Depende del objeto Git histórico fijado y falla cerrado si no está
  disponible.
- No evalúa equivalencia semántica ni afirmaciones prohibidas; por eso
  `SC-07` permanece `NOT_DEMONSTRATED`.

## Inventario

- `CMP-15`
- `DAT-21`
- `AUTH-21`
- `ROE-24`
