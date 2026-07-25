Transporta los argumentos de entrada y las salidas del proceso sin ofrecer una
interfaz remota.

## Interfaz

- Entrada: `argv` para `analyze` o `baseline`.
- Salida correcta: JSON canónico por `stdout`.
- Error: mensaje saneado por `stderr` y código de salida distinto de cero.

## Tecnología

- Shell local.
- `main.py` como punto de entrada.

No persiste logs ni resultados por sí misma.
