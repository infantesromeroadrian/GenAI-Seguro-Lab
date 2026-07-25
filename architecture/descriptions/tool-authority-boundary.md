Agrupa las capacidades que pueden consultar conocimiento o producir un efecto
local.

## Trust boundary

- ID: `TB-04`.
- `TOL-01` aplica esquema, allowlist del incidente e IDs conocidos.
- `TOL-02` separa propuesta, confirmación y creación exclusiva.
- `MOD-01` no contiene código de autorización o ejecución.
- `CMP-06` solo llama al constructor de `TOL-02` para validar un sandbox
  temporal; no prepara ni crea borradores.

## Límite

La búsqueda está conectada al flujo benigno. El borrador permanece como API
interna desconectada de la CLI y su confirmación no autentica al humano. La
validación del sandbox del perfil no concede autoridad para usar la herramienta.
