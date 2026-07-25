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
- La creación se ancla a un descriptor de `sandbox/drafts/` con `O_EXCL`,
  `O_NOFOLLOW` y modo `0600`.
- `MOD-01` no contiene código de autorización o ejecución.
- `CMP-06` solo llama al constructor de `TOL-02` para validar un sandbox
  temporal; no prepara ni crea borradores.

## Límite

La búsqueda está conectada al flujo benigno. El borrador permanece como API
interna desconectada de la CLI y su confirmación no autentica al humano. La
validación del sandbox del perfil no concede autoridad para usar la
herramienta. `CMP-07` la invoca únicamente con autorización TOL exacta y un
sandbox efímero bajo `$TMP`. Todo el límite sigue dentro de `IDN-01`.
