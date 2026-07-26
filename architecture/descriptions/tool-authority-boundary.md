Agrupa las capacidades que pueden consultar conocimiento o producir un efecto
local.

## Trust boundary

- ID: `TB-04`.
- Toda solicitud hacia `TOL-01` o la preparación en `TOL-02` exige un
  `ToolExecutionGrant` inmutable ligado a principal, scope, una herramienta e
  instancia.
- `TOL-01` recibe una vista física exacta del incidente; un grant de otro caso
  o un ID no retenido falla cerrado.
- `TOL-02` registra la propuesta en su instancia y exige otro grant de efecto,
  ligado a propuesta y raíz, antes de crear.
- Antes del registro y la huella, `TOL-02` exige que `CMP-09` controle título y
  cuerpo; la aprobación liga únicamente ese contenido saneado.
- `DraftApprovalAuthority` autentica una identidad sintética, emite tokens
  opacos con TTL y liga identidad, propuesta, principal, scope, herramienta,
  efecto, writer, sesión y raíz.
- La creación delega en `CMP-12`: marker/staging `0600`, descriptor anclado y
  hard link create-only; la recuperación nunca restaura autoridad.
- `MOD-01` no contiene código de autorización o ejecución.
- `CMP-06` solo llama al constructor de `TOL-02` para validar un sandbox
  temporal; no prepara ni crea borradores.

## Límite

La búsqueda está conectada al flujo benigno. El borrador permanece como API
interna desconectada de la CLI. Su autoridad acredita un principal sintético,
no presencia humana real. La validación del sandbox del perfil no emite
challenge ni concede autoridad para usar la herramienta. `CMP-07` la invoca
únicamente con autorización TOL exacta y un sandbox efímero bajo `$TMP`. Todo
el límite sigue dentro de `IDN-01`.
