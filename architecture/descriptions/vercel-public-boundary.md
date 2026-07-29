Agrupa los artefactos estáticos publicados mediante la infraestructura
gestionada de Vercel.

## Trust boundary

- ID: `TB-09`.
- Transporte observado: HTTPS público.
- Estado de aplicación: inmutable por despliegue.

## Límites

- No aloja funciones, runtime Python, variables de aplicación o secretos.
- Los logs y controles propios de la plataforma no sustituyen la evidencia del
  laboratorio ni forman parte de `DAT-25`.
