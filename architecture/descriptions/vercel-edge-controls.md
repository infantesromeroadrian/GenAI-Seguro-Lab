Encamina la interfaz y las dos rutas API del mismo origen dentro del
despliegue gestionado.

## Responsabilidades

- Servir únicamente mediante HTTPS.
- Aplicar las cabeceras de seguridad declaradas en `vercel.json`.
- Encauzar `GET /api/status` y `POST /api/analyze` hacia la Function.
- Mantener CORS deshabilitado; la Function valida Host, Origin, Fetch Metadata
  y el token CSRF antes de invocar el proveedor.

## Límites

- Los límites por IP son controles de abuso regionales y no equivalen a un
  techo global de gasto.
