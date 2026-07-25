Prepara y materializa borradores ficticios bajo una política de efecto local
muy restringida.

## Responsabilidades

- Validar `draft_create`.
- Calcular una huella SHA-256 de la propuesta exacta.
- Exigir una confirmación separada y consumirla una sola vez en proceso.
- Crear un único Markdown nuevo dentro de `sandbox/drafts/`.

## Restricciones

- No admite rutas, symlinks de directorio, sobrescritura o borrado.
- No accede a red, shell o filesystem general.
- No está conectado a la CLI ni al flujo benigno.
- No autentica la identidad humana que el llamador declara.

## Evidencia

- `src/genai_seguro_lab/local_tools.py`
- `tests/test_local_tools.py`
- Inventario `TOL-02`
