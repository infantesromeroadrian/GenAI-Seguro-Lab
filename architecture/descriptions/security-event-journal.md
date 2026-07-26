Conserva durante una operación eventos de seguridad cerrados, correlacionados
y acotados sin retener el contenido observado.

## Responsabilidades

- Implementar `GSL-SECURITY-EVENTS-001` versión `1.0.0`.
- Crear una correlación primaria opaca por operación.
- Asignar a los 12 casos de `baseline` correlaciones hijas opacas distintas,
  sin incluir el ID del incidente.
- Mantener una secuencia global contigua, tiempo monotónico acotado y una
  cadena SHA-256 canónica.
- Limitar cada evento a 2 KiB y el journal a 32 eventos/32 KiB para `analyze`
  y `draft`, o 256 eventos/256 KiB para `baseline`.
- Reservar el terminal antes de cada append y, para borradores, el intento y
  resultado antes de consumir autoridad o iniciar I/O.
- Derivar diez señales allowlisted a partir de decisiones de la aplicación.
- Entregar un snapshot inmutable solo cuando la CLI recibe
  `--security-report`.

## Datos excluidos

No admite texto libre, prompt, respuesta, argumento, conocimiento, resumen,
título, cuerpo, ruta, entorno, credencial, identidad presentada, token,
excepción o traceback.

## Límites

- Vive en memoria y no crea log, retención, telemetría, alerta o SIEM.
- La cadena no está firmada ni anclada fuera del proceso.
- Una señal no confirma un ataque, compromiso o identidad.
- Observar una decisión no crea, valida, prolonga o sustituye un grant.
- No implementa respuesta, retry, rollback o recuperación.
- `CMP-12` resuelve por separado la transacción del sandbox a partir de su
  estado real; nunca usa el journal como autoridad o estado duradero.

## Referencias

- Inventario `CMP-11`
- Política `GSL-SECURITY-EVENTS-001`
- Código `src/genai_seguro_lab/security_events.py`
- Pruebas `tests/test_security_events.py`
