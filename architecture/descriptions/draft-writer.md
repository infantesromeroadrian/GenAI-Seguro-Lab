Prepara y materializa borradores ficticios bajo una política de efecto local
muy restringida.

## Responsabilidades

- Validar `draft_create` mediante un esquema cerrado.
- Exigir una `ToolExecutionPolicy` que permita la herramienta y todas las
  referencias incluidas en la propuesta.
- Calcular una huella SHA-256 de la propuesta exacta.
- Exigir una confirmación separada y consumirla una sola vez en proceso.
- Crear un único Markdown nuevo dentro de `sandbox/drafts/`.

## Restricciones

- No admite rutas, symlinks de directorio, sobrescritura o borrado.
- No accede a red, shell o filesystem general.
- Sin política explícita no prepara una propuesta.
- No está conectado a la CLI ni al flujo benigno.
- No autentica la identidad humana que el llamador declara.
- `CMP-07` lo invoca solo desde pytest, bajo `$TMP`, para las fixtures
  `ADV-TOL-003/004/005`; no crea una ruta de producto.

## Evidencia

- `src/genai_seguro_lab/local_tools.py`
- `tests/test_local_tools.py`
- `tests/test_tool_abuse_evaluation.py`
- Inventario `TOL-02`
