Construye el análisis alojado opt-in sin alterar la baseline determinista.

## Responsabilidades

- Aceptar un único identificador de incidente sintético validado.
- Crear el perfil `cloud_analyze` con dos invocaciones y una herramienta.
- Reutilizar `CMP-03`, `TOL-01`, los grants locales, `CMP-09`, `CMP-10` y
  `CMP-11`.
- Devolver solo `CloudAnalysisResult`, sin prompt, respuesta cruda o thinking.

## Restricciones

- Solo se activa mediante `--provider ollama`.
- No entra en baseline, evaluaciones, corpus adversario o `DAT-25`.
- No concede herramientas ni interpreta el resultado como evidencia canónica.

## Inventario

- `CMP-21`
- `MOD-02`
