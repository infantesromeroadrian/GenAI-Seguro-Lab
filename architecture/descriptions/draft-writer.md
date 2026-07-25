Prepara y materializa borradores ficticios bajo una política de efecto local
muy restringida.

## Responsabilidades

- Validar `draft_create` mediante un esquema cerrado.
- Exigir un grant de preparación ligado a principal, scope e instancia.
- Calcular una huella SHA-256 de la propuesta exacta.
- Registrar la identidad de la propuesta en la instancia.
- Tras la confirmación separada, emitir y consumir un grant de efecto ligado a
  propuesta, instancia y raíz.
- Crear un único Markdown nuevo respecto al descriptor de
  `sandbox/drafts/`, con `O_EXCL`, `O_NOFOLLOW` y modo `0600`.

## Restricciones

- No admite rutas, symlinks de directorio, sobrescritura o borrado.
- No accede a red, shell o filesystem general.
- Sin el grant de preparación exacto no prepara una propuesta.
- Una propuesta directa o de otra instancia/raíz falla antes de I/O.
- No está conectado a la CLI ni al flujo benigno.
- No autentica la identidad humana que el llamador declara.
- `CMP-07` lo invoca solo desde pytest, bajo `$TMP`, para las fixtures
  `ADV-TOL-003/004/005`; no crea una ruta de producto.

## Evidencia

- `src/genai_seguro_lab/local_tools.py`
- `tests/test_local_tools.py`
- `tests/test_tool_abuse_evaluation.py`
- Inventario `TOL-02`
