# Tests

Este directorio contiene las pruebas automatizadas del contrato de datos, el
adaptador determinista, las herramientas locales, el flujo benigno y la
interfaz de proceso completo.

Ejecución completa:

```bash
uv run --frozen pytest
```

`test_cli_smoke.py` comprueba el punto de entrada desde fuera del repositorio,
la reproducción exacta de la baseline versionada, el resultado byte a byte de
un caso repetido, el error saneado ante un identificador desconocido y que la
ejecución no cree borradores.
