# Data card — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-DATA-CARD-001` |
| Versión | `1.0.0` |
| Fecha de corte | 2026-07-28 |
| Estado | `DESCRIPTIVA_ALCANCE_ACTUAL` |
| Corte de las fuentes del repositorio | commit `52e039f0c72f96671170e977a761691aa81c525e` |
| Candidato de producto evaluado | commit `77edd64037bb0e41edffa58cae2682ba7d2694d2` |
| Evidencia final | `DAT-25`, SHA-256 `05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d` |
| Sensibilidad declarada | `synthetic_internal` |

Esta ficha resume los activos del
[inventario del sistema](./system-inventory.md). Los manifiestos versionados,
los esquemas y cada artefacto de evidencia siguen siendo las fuentes
canónicas. La ficha no autoriza datos reales, no fija por sí sola una política
de conservación y no convierte evidencia histórica en un resultado actual.
Esta ficha no constituye una certificación, una declaración de conformidad o
una aceptación de riesgo.

## Finalidad y composición

Los datos existen para ejecutar un laboratorio reproducible de análisis de
incidentes ficticios, evaluar controles sobre casos benignos y adversarios y
conservar evidencia saneada. No hay datos de entrenamiento ni un dataset
destinado a ajustar un modelo.

<!-- data-assets:start -->
| Activo | Familia | Contenido o función | Persistencia |
|---|---|---|---|
| `DAT-01` | Producto | 12 incidentes benignos sintéticos | JSONL versionado |
| `DAT-02` | Producto | 8 documentos de conocimiento sintético | JSONL versionado |
| `DAT-03` | Producto | Manifiesto benigno, procedencia, conteos y hashes | JSON versionado |
| `DAT-04` | Evidencia | Baseline funcional benigna; no es evaluación semántica | JSON versionado |
| `DAT-05` | Runtime | Resultado saneado de proceso | `stdout`/`stderr` efímero |
| `DAT-06` | Sandbox | Borradores ficticios | Markdown local ignorado por Git |
| `DAT-07` | Adversario | 18 entradas adversarias sintéticas | JSONL versionado |
| `DAT-08` | Adversario | 18 oráculos separados del target | JSONL versionado |
| `DAT-09` | Adversario | Manifiesto, RoE, conteos, estado y hashes | JSON versionado |
| `DAT-10` | Evidencia histórica | Configuración de baseline adversaria | JSON versionado |
| `DAT-11` | Evidencia histórica | Resultados de baseline adversaria | JSON versionado |
| `DAT-12` | Evidencia histórica | Eventos saneados de baseline adversaria | JSONL versionado |
| `DAT-13` | Evidencia histórica | Manifiesto y hashes de la baseline adversaria | JSON versionado |
| `DAT-14` | Runtime | Informe opt-in de eventos saneados | JSON efímero por `stdout` |
| `DAT-15` | Sandbox | Marker, staging e informe transaccional | Estado local efímero |
| `DAT-16` | Evidencia histórica | Configuración del retest adversario M01 | JSON versionado |
| `DAT-17` | Evidencia histórica | Resultados neutrales del retest M01 | JSON versionado |
| `DAT-18` | Evidencia histórica | Eventos saneados del retest M01 | JSONL versionado |
| `DAT-19` | Evidencia histórica | Manifiesto y hashes del retest M01 | JSON versionado |
| `DAT-20` | Evidencia histórica | Métricas adversarias comparativas M02 | JSON versionado |
| `DAT-21` | Evidencia histórica | Proyección y comparación benigna M03 | JSON versionado |
| `DAT-22` | Evidencia histórica | Métricas operativas M04; no mide el candidato final | JSON versionado |
| `DAT-23` | Evidencia histórica | Registro revisado de hallazgos M05 | JSON versionado |
| `DAT-24` | Contrato de evaluación | Rúbrica cerrada pre-run de M07 | JSON versionado |
| `DAT-25` | Evidencia final | Único retest final saneado de M07 | JSON versionado e inmutable |
<!-- data-assets:end -->

## Dataset benigno

| Propiedad | Valor |
|---|---|
| Identificador y versión | `GSL-DATASET-001` `1.0.0` |
| Procedencia | `authored_for_lab`, autor `GenAI Seguro Lab`, creado el 2026-07-25 |
| Clasificación | `synthetic: true`, `sensitivity: synthetic_internal` |
| Incidentes | 12 registros; `data/incidents.jsonl`; SHA-256 `928af933a23ffe2851f5bf5206fa691e18dd7e3a6a6d621d3ad8af06d4c4870a` |
| Conocimiento | 8 registros; `data/knowledge.jsonl`; SHA-256 `f62fd7bb0051c5b97f5f5ce40941e77c1c8019d2b0ac6ceb3d2fa099d8ab92da` |
| Contenido adversario | 0 registros |

`CMP-10` obtiene un único snapshot con límites preventivos antes de parsear o
hashear; `CMP-02` valida estructura, referencias, conteos y hashes. Una
instancia de `TOL-01` recibe únicamente la vista física referenciada por el
incidente elegido.

## Corpus adversario

| Propiedad | Valor |
|---|---|
| Identificador y versión | `GSL-ADVERSARIAL-CORPUS-001` `1.4.0` |
| Procedencia | `authored_for_lab`, autor `GenAI Seguro Lab`, creado el 2026-07-25 |
| Clasificación | `synthetic: true`, `sensitivity: synthetic_internal` |
| Entradas | 18 registros; `data/adversarial/inputs.jsonl`; SHA-256 `ebf1d1f58a2969e856291640a97c74e6071405c202f415ecba02cef54f35e6b4` |
| Oráculos | 18 registros; `data/adversarial/oracles.jsonl`; SHA-256 `ab0f70a8d225101168aa1be0e720b86320d9d910d1ef8358b3688ff7a5c6a9f0` |
| Cobertura declarada | 17 abuse cases, seis familias, 14 fixtures conectadas y evaluadas canónicamente, cuatro inertes |

Las entradas y los oráculos están en archivos separados. El target recibe solo
la entrada; pytest o el evaluador compara el oráculo después de congelar la
observación. Las cuatro fixtures `AC-DOS-01`, `AC-DOS-02`, `AC-DOS-03` y
`AC-SC-01` no fueron ejecutadas por `DAT-25` y no acreditan eficacia.

## Procedencia, privacidad y sensibilidad

- Todos los registros operativos fueron escritos para el laboratorio.
- Los manifiestos declaran datos sintéticos y sensibilidad
  `synthetic_internal`.
- La revisión del inventario no identifica datos personales, corporativos,
  credenciales, secretos o incidentes reales.
- La credencial sintética del flujo interno no entra en el modelo ni en la
  evidencia versionada.
- Los eventos y resultados persistidos excluyen payloads, salida bruta,
  credenciales y rutas personales según su contrato.

### Egress sintético opt-in

`GSL-OLLAMA-001` no crea un nuevo dataset ni modifica `DAT-01` a `DAT-25`.
Cuando el operador selecciona Ollama, se envían al endpoint fijo únicamente la
tarea enumerada, un incidente benigno sintético validado y el resultado
sintético de las referencias autorizadas de `DAT-02`. No se envían
`expected_result`, `DAT-08`, `DAT-24`, corpus adversario, datos reales o rutas
locales.

La clave Bearer procede de `OLLAMA_API_KEY`, no de los activos de datos, y no
se incorpora al prompt, resultado, journal o evidencia. Las pruebas
automatizadas usan transporte falso y un smoke instrumentado completó el flujo
con `INC-BEN-001`; retención, residencia y tratamiento del proveedor siguen
sin verificar y cualquier nueva prueba real requiere revisión previa.

La etiqueta sintética no elimina la necesidad de controles. Un cambio de
origen, contenido o sensibilidad obliga a detener la incorporación, revisar
privacidad y actualizar la evaluación antes de usar el activo.

## Calidad, representatividad y sesgo

Los manifiestos aportan conteos, hashes, referencias y validación cerrada. Las
pruebas verifican cardinalidad, esquemas, separación de oráculos y consistencia
de referencias. `DAT-25` conserva 12/12 ejecuciones benignas y 14/14
adversarias dentro del contrato fijado.

Limitaciones:

- el corpus es pequeño, diseñado y enumerado; no representa una distribución
  real de incidentes o ataques;
- no mide prevalencia, cobertura estadística, deriva temporal o idiomas
  distintos de los casos incluidos;
- no contiene atributos demográficos, por lo que no permite evaluar equidad
  entre grupos ni afirmar ausencia de sesgo;
- seis familias adversarias no equivalen a cobertura de amenazas desconocidas;
- los comparadores cerrados no demuestran comprensión semántica general;
- la coincidencia literal del retest final fue 0/24 hallazgos y 0/36 acciones,
  aunque las 84 cláusulas se conservaron mediante las reglas predeclaradas.

## Acceso, transformación y autoridad

- `ACT-01` solo selecciona un incidente por ID a través de la CLI.
- `CMP-02` carga y valida; no interpreta ni ejecuta contenido adversario.
- `TOL-01` recibe una proyección mínima ligada al incidente.
- `ACT-02`, mediante la autoridad del host y Git, puede modificar corpus,
  manifiestos y evidencia. La aplicación no crea separación de funciones.
- Los runners emiten proyecciones por `stdout`; el versionado de evidencia es
  una acción deliberada del mantenedor.
- `DAT-08`, `expected_result` y `DAT-24` no entran en las peticiones del
  candidato final.

## Ciclo de vida, conservación y eliminación

| Familia | Regla actual |
|---|---|
| Corpus y manifiestos | Permanecen versionados en Git. Un cambio exige nueva versión, hashes y pruebas coherentes. |
| Evidencia | Se conserva como historial inmutable y saneado; un nuevo run usa otro identificador y artefacto. `DAT-25` no se regenera. |
| Salida y eventos de runtime | Son efímeros por `stdout` o memoria; no hay persistencia automática. |
| Intercambio Ollama opt-in | Prompt y respuesta existen solo durante dos llamadas; la aplicación proyecta únicamente el resultado validado y no registra thinking, cuerpo remoto o respuesta cruda. La conservación del proveedor no está verificada. |
| Sandbox | Borradores y estado transaccional permanecen locales, ignorados por Git y sometidos a publicación create-only y recuperación acotada. |

La [política formal de logs y ciclo de vida](./security-events-policy.md)
completa `PGS-06-M05`: mantiene el journal sin persistencia, aplica redacción
antes de emitir y fija conservación o retirada por clase. No inventa plazos
legales ni promete purga de Git, memoria, terminales o soportes.

## Usos permitidos y no permitidos

Permitidos:

- pruebas y aprendizaje en este repositorio y laboratorio propios;
- análisis de calidad, seguridad y utilidad con las reglas declaradas;
- revisión documental de evidencia saneada.

No permitidos:

- sustituir registros sintéticos por información real sin una nueva
  autorización y evaluación;
- usar oráculos, `expected_result` o la rúbrica como entrada del target;
- publicar payloads, credenciales, rutas personales o salida bruta;
- entrenar o ajustar un modelo con estos datos atribuyéndoles una finalidad que
  no tienen;
- interpretar los recuentos como representatividad estadística o cobertura
  universal.

## Disparadores de revisión

Actualizar esta ficha y repetir las comprobaciones pertinentes si cambian el
contenido, procedencia, sensibilidad, esquema, hash, licencia, owner, acceso,
retención, herramienta consumidora, modelo, evaluación o ámbito de
publicación de cualquier activo.
