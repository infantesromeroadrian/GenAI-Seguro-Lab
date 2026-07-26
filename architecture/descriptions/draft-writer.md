Prepara y materializa borradores ficticios bajo una política de efecto local
muy restringida.

## Responsabilidades

- Validar `draft_create` mediante un esquema cerrado.
- Exigir un grant de preparación ligado a principal, scope e instancia.
- Aplicar `CMP-09` a título y cuerpo antes de construir la propuesta.
- Consumir en `CMP-10` una propuesta y limitar el Markdown UTF-8 a 16 KiB.
- Calcular una huella SHA-256 del contenido ya permitido o redactado.
- Registrar la identidad de la propuesta en la instancia.
- Solicitar a `DraftApprovalAuthority` challenge, aprobación y grant de efecto
  ligados al contexto exacto.
- Consumir el grant antes de I/O; un fallo posterior exige otra aprobación.
- Reservar en `CMP-11` intento y resultado antes de consumir el grant o
  iniciar I/O.
- Delegar en `CMP-12` la publicación atómica y la reconciliación del único
  Markdown nuevo.
- Detener la sesión de forma idempotente, revocar toda autoridad efímera y
  cerrar el descriptor.

## Restricciones

- No admite rutas, symlinks de directorio, sobrescritura o borrado.
- No accede a red, shell o filesystem general.
- Sin el grant de preparación exacto no prepara una propuesta.
- Una propuesta directa o de otra instancia/raíz falla antes de I/O.
- No está conectado a la CLI ni al flujo benigno.
- Solo acepta aprobaciones opacas de la autoridad configurada; no admite una
  confirmación literal o serializable.
- La escritura no transforma el contenido después de su huella y aprobación.
- Acredita un principal sintético, no presencia o identidad humana real.
- Cada sesión admite una propuesta, un challenge, tres autenticaciones, un
  grant y un archivo; los intentos fallidos también consumen presupuesto.
- Antes de publicar no existe efecto final; después de publicar, el final se
  conserva aunque la limpieza interna quede pendiente.
- Una recuperación no restaura grants o cuotas y no publica staging.
- `CMP-07` lo invoca solo desde pytest, bajo `$TMP`, para las fixtures
  `ADV-TOL-003/004/005`; no crea una ruta de producto.

## Evidencia

- `src/genai_seguro_lab/local_tools.py`
- `tests/test_local_tools.py`
- `tests/test_tool_abuse_evaluation.py`
- `tests/test_resource_control.py`
- `tests/test_security_events.py`
- `tests/test_sandbox_recovery.py`
- Inventario `TOL-02`
