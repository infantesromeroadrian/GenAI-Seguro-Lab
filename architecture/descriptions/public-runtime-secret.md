Mantiene la credencial del proveedor LLM fuera del repositorio y del navegador.

## Responsabilidades

- Estar disponible únicamente para la Function en el entorno autorizado.
- Tratarse como variable sensible del runtime.

## Límites

- No aparece en HTML, JavaScript, respuestas, errores, snapshots ni `DAT-25`.
- Su presencia no habilita por sí sola el análisis; también debe estar activo
  el kill switch explícito.
