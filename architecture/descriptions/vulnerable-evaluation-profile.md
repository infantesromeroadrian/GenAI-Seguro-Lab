Construye una `ModelRequest` deliberadamente débil y claramente marcada para
el futuro harness adversario.

## Contrato

- ID de inventario: `CMP-06`.
- Perfil: `GSL-PROFILE-VULNERABLE-001` v1.0.0.
- Estado: API Python interna, no predeterminada y no alcanzable desde CLI.
- Entrada: declaración exacta de `GSL-ROE-001`, `DatasetBundle` sintético e
  instancia existente de `$TMP/sandbox/drafts`.
- Salida: `ModelRequest` en memoria que mezcla deliberadamente contenido no
  confiable y anuncia `knowledge_search` y `draft_create`.

## Aislamiento

- Rechaza el sandbox del checkout canónico.
- No llama a `MOD-01`.
- No prepara ni ejecuta `TOL-01` o `TOL-02`.
- No consume `DAT-07` ni `DAT-08`; todavía no existe dispatcher entre el
  corpus adversario y el perfil.
- No escribe archivos, abre red, inicia procesos o crea evidencia.
- Omite el oráculo `expected_result` de la petición.

## Consecuencia

Su techo actual es `C0`. El perfil materializa una configuración vulnerable,
pero no constituye todavía un harness ni demuestra un ataque.
