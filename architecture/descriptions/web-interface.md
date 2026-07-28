Sirve el frontal local y proyecta exclusivamente las operaciones benignas ya
existentes.

## Responsabilidades

- Escuchar únicamente en `127.0.0.1`.
- Servir cuatro assets exactos y `GET /api/status`.
- Aceptar `POST /api/analyze` y `POST /api/baseline` con cuerpos JSON cerrados.
- Validar Host, Origin, token CSRF, `Content-Type`, tamaño máximo de 1 KiB y
  esquema antes de entrar en el flujo benigno.
- Reutilizar el lock, los límites, la política de salida y el journal del
  producto.
- Emitir errores saneados sin conservar cuerpos, rutas o cabeceras.

## Autoridad

- No autentica a una persona ni crea identidad de aplicación.
- El token CSRF protege el canal; no es un grant ni una credencial de usuario.
- No concede herramientas, amplía vistas o cambia la consecuencia máxima C1.

## Exclusiones

- Sin bind externo, TLS, CORS, cookies, sesiones persistentes o logging raw.
- Sin prompt, upload, filesystem, `TOL-02`, harnesses, red externa o proveedor.

## Inventario

- `CMP-19`
- `TB-07`
- `AUTH-25`
