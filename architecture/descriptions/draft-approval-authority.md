Autentica un principal sintético local antes de permitir un efecto de
`TOL-02`.

## Responsabilidades

- Verificar la identidad configurada y una credencial local mediante
  PBKDF2-HMAC-SHA256.
- Emitir challenge, aprobación y grant como objetos opacos no serializables.
- Ligar cada token a identidad, propuesta, principal, scope, herramienta,
  efecto, writer, sesión y raíz.
- Aplicar TTL y consumo único de forma sincronizada antes de I/O.
- Consumir en `CMP-10` un challenge, hasta tres intentos de autenticación y un
  grant; los intentos fallidos cuentan.
- Invalidar el estado pendiente al cerrar la autoridad o el writer.

## Restricciones

- La credencial no entra en `ModelRequest`, `ModelToolRequest`, logs o
  evidencia.
- No existe UI, autenticador del sistema operativo ni prueba de presencia
  humana.
- La separación es lógica dentro del mismo proceso Python y no limita la
  autoridad efectiva de `IDN-01`.
- El perfil vulnerable crea y cierra una instancia inerte para validar su
  sandbox, sin emitir challenge, aprobación o efecto.

## Evidencia

- `src/genai_seguro_lab/local_tools.py`
- `tests/test_local_tools.py`
- `tests/test_tool_abuse_evaluation.py`
- `tests/test_resource_control.py`
