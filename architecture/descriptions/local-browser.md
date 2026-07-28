Representa el navegador del operador en el mismo host que el laboratorio.

## Responsabilidades

- Cargar los cuatro assets estáticos allowlisted.
- Consultar el estado y los 12 identificadores benignos.
- Enviar únicamente una selección `INC-BEN-NNN` o una baseline sin argumentos.
- Renderizar resultados y eventos mediante APIs seguras del DOM.

## Trust boundary

- ID: `TB-07`.
- Transporte: HTTP en `127.0.0.1`.
- Controles: Host, Origin, CSRF efímero, CSP, cabeceras cerradas y ausencia de
  CORS.
- Límite: comparte host, cuenta y autoridad efectiva con el proceso Python; no
  constituye autenticación o aislamiento frente a código local hostil.

## Exclusiones

- No hay prompt libre, uploads, rutas, navegación externa o persistencia.
- No expone borradores, harnesses adversarios ni evaluadores internos.
