Aplica la política semántica de salida propiedad de la aplicación.

## Responsabilidades

- Exigir uno de tres canales cerrados: resumen, título o cuerpo de borrador.
- Evaluar rechazo antes de cualquier redacción.
- Redactar correo y rutas locales mediante marcadores fijos.
- Emitir un sello opaco ligado a la instancia y al canal.
- Conservar solo categoría y conteo de redacciones, nunca los valores.
- Fallar cerrado sin reflejar el contenido rechazado.

## Inserción

- `CMP-03` la invoca después de validar la respuesta final y antes de devolver
  `BenignAnalysisResult`.
- `TOL-02` la invoca antes de crear la propuesta, calcular su huella o
  solicitar aprobación.
- No existe una ruta alternativa o configuración aportada por `MOD-01`.

## Límite

Es un control léxico y determinista dentro del mismo proceso. No usa modelo,
red, filesystem, entorno, secretos o autoridad de herramienta. No garantiza
detectar todos los secretos, PII, paráfrasis, homoglifos, ofuscación o
contenido activo.

## Inventario

- `CMP-09`
