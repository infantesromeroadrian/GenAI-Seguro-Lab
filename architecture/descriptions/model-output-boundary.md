Separa las respuestas producidas por el adaptador de las decisiones de control
de la aplicación.

## Trust boundary

- ID: `TB-03`.
- Las peticiones, respuestas y tool requests usan esquemas estrictos e
  inmutables.
- El flujo ordinario serializa entradas de tarea e incidente mediante sobres
  cerrados y valida la respuesta final como `BenignFinalOutput`.
- La respuesta final debe pertenecer al incidente en curso, citar exactamente
  el conocimiento devuelto por la herramienta autorizada y declarar que no
  ejecutó acciones ni confirmó un compromiso.
- El adaptador solo responde a huellas exactas guionizadas y falla cerrado ante
  una petición desconocida.
- Una solicitud de herramienta conserva su nombre como dato bruto para poder
  observar y rechazar nombres desconocidos; no concede autoridad de ejecución.
- La respuesta final continúa siendo transporte bruto hasta que `CMP-03`
  valida su consistencia y `CMP-09` permite o redacta el resumen.

## Límite

El adaptador actual es determinista y está en el mismo proceso. La frontera es
lógica y deberá revisarse y probarse de nuevo si se incorpora un proveedor
real. `CMP-09` añade reglas léxicas explícitas, pero no sustituye moderación
contextual, retest ni evaluación con un modelo real.
