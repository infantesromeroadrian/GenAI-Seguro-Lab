# Tests

Este directorio contiene las pruebas automatizadas del contrato de datos, el
adaptador determinista, las herramientas locales, el flujo benigno, el perfil
vulnerable aislado, el harness PI y la interfaz de proceso completo.

Ejecución completa:

```bash
uv run --frozen pytest
```

`test_cli_smoke.py` comprueba el punto de entrada desde fuera del repositorio,
la reproducción exacta de la baseline versionada, el resultado byte a byte de
un caso repetido, el error saneado ante un identificador desconocido y que la
ejecución no cree borradores.

`test_evaluation_profile.py` comprueba que
`GSL-PROFILE-VULNERABLE-001` exige las RoE y los límites exactos, usa solo un
`$TMP/sandbox/drafts`, no crea archivos, identifica sus peticiones, no expone
el oráculo y no puede seleccionarse desde la CLI. Estas pruebas no ejecutan
ataques ni herramientas.

`test_adversarial_corpus.py` carga las 18 fixtures y sus 18 oráculos separados,
verifica la cobertura de los 17 abuse cases y seis familias, la procedencia,
los límites RoE, la relación uno a uno y los hashes. También demuestra que el
manifiesto fija 3 fixtures conectadas a test, 15 inertes y 0 evaluaciones
canónicas.

`test_prompt_injection_evaluation.py` cubre los tres casos PI. Comprueba en un
proceso real que `--prompt` se rechaza antes de cargar datos; para las dos
inyecciones indirectas crea un corpus coherente bajo `$TMP`, entrega solo la
entrada a `CMP-07`, limita el flujo a dos turnos y una búsqueda, compara el
oráculo después y exige cero borradores, red o mutación canónica.
