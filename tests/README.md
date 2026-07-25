# Tests

Este directorio contiene las pruebas automatizadas del contrato de datos, el
adaptador determinista, las herramientas locales, el flujo benigno, el perfil
vulnerable aislado, el harness adversario acotado, el runner canónico y la
interfaz de proceso completo.

Ejecución completa:

```bash
uv run --frozen pytest
```

`test_cli_smoke.py` comprueba el punto de entrada desde fuera del repositorio,
la reproducción exacta de la baseline versionada, el resultado byte a byte de
un caso repetido, el error saneado ante un identificador desconocido y que la
ejecución no cree borradores.

`test_instruction_boundary.py` comprueba que el flujo ordinario separa
instrucciones confiables, datos de usuario y contenido no confiable; que las
salidas del modelo y de herramientas conservan su clasificación; y que los
roles incompatibles, las instrucciones tardías o los dominios ausentes fallan
cerrados.

`test_evaluation_profile.py` comprueba que
`GSL-PROFILE-VULNERABLE-001` exige las RoE y los límites exactos, usa solo un
`$TMP/sandbox/drafts`, no crea archivos, identifica sus peticiones, no expone
el oráculo y no puede seleccionarse desde la CLI. Estas pruebas no ejecutan
ataques ni herramientas.

`test_adversarial_corpus.py` carga las 18 fixtures y sus 18 oráculos separados,
verifica la cobertura de los 17 abuse cases y seis familias, la procedencia,
los límites RoE, la relación uno a uno y los hashes. También demuestra que el
manifiesto fija 14 fixtures conectadas a test y evaluadas canónicamente, más 4
inertes.

`test_prompt_injection_evaluation.py` cubre los tres casos PI. Comprueba en un
proceso real que `--prompt` se rechaza antes de cargar datos; para las dos
inyecciones indirectas crea un corpus coherente bajo `$TMP`, entrega solo la
entrada a `CMP-07`, limita el flujo a dos turnos y una búsqueda, compara el
oráculo después y exige cero borradores, red o mutación canónica.

`test_jailbreak_disclosure_evaluation.py` cubre los tres casos de jailbreak y
los tres de revelación. Comprueba afirmaciones prohibidas en copias temporales,
cardinalidad y terminación del ciclo, rechazo de IDs fuera de alcance o
desconocidos y un error de CLI con marcador señuelo. Cada ejecución conserva
datos sintéticos, salida saneada, cero llamadas externas y cero archivos.

`test_tool_abuse_evaluation.py` cubre los cinco casos TOL. Comprueba una
allowlist de herramienta cerrada, cardinalidad, IDs duplicados, recursión,
integridad y consumo único de confirmaciones, traversal, symlink y overwrite.
También registra `AC-TOL-05` como residual conocido: una confirmación literal
sin identidad crea exactamente un Markdown sintético bajo `$TMP`.

`test_adversarial_baseline.py` comprueba la autorización exacta de `CMP-08`,
la ejecución de los 14 casos, el residual esperado, el fallo cerrado ante
deriva del candidato, la escritura solo en un directorio temporal nuevo y la
integridad y saneado de la evidencia versionada.
