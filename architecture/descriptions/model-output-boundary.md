Separa las respuestas producidas por el adaptador de las decisiones de control
de la aplicación.

## Trust boundary

- ID: `TB-03`.
- Las peticiones, respuestas y tool requests usan esquemas estrictos e
  inmutables.
- El adaptador solo responde a huellas exactas guionizadas y falla cerrado ante
  una petición desconocida.
- Una solicitud de herramienta es dato; no concede autoridad de ejecución.

## Límite

El adaptador actual es determinista y está en el mismo proceso. La frontera es
lógica y deberá revisarse si se incorpora un proveedor real.
