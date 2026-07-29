Agrupa la entrega estática y la Function Python publicadas mediante la
infraestructura gestionada de Vercel.

## Trust boundary

- ID: `TB-09`.
- Transporte observado: HTTPS público.
- Estado de aplicación: código inmutable por despliegue y ejecución efímera.

## Límites

- La credencial del proveedor solo existe como variable sensible del runtime y
  no se entrega al navegador ni se versiona.
- La Function acepta únicamente un ID de incidente enumerado, no prompts,
  archivos ni datos aportados libremente.
- La protección por origen y los controles edge reducen abuso, pero no
  constituyen por sí solos una cuota global de proveedor.
- Los logs y controles propios de la plataforma no sustituyen la evidencia del
  laboratorio ni forman parte de `DAT-25`.
