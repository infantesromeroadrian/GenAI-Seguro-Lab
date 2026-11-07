Sirve la interfaz pública del laboratorio y presenta la capacidad de forma
neutral como «Análisis con LLM».

## Responsabilidades

- Entregar HTML, CSS, JavaScript y favicon con cabeceras de seguridad.
- Permitir que el navegador cargue el catálogo y la baseline determinista.
- Enviar únicamente un ID de incidente enumerado a la Function del mismo
  origen.
- Mantener fuera de la proyección pública el proveedor, el modelo, los prompts,
  la credencial y las respuestas remotas sin validar.

## Tecnología

- HTML, CSS y JavaScript sin framework.
- Vercel Static Delivery y rutas del mismo origen configuradas mediante
  `vercel.json`.
