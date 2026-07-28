Transporta los argumentos de entrada y las salidas del proceso sin ofrecer una
interfaz remota.

## Interfaz

- Entrada: `argv` para `analyze`, `baseline` o `web`.
- Salida correcta: JSON canónico por `stdout`.
- Error: mensaje saneado por `stderr` y código de salida distinto de cero.

## Tecnología

- Shell local; `web` inicia el listener fijo en `127.0.0.1`.
- `main.py` como punto de entrada.

No persiste logs ni resultados por sí misma.
