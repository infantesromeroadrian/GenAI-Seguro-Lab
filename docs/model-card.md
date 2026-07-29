# Model card — `MOD-01`

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-MODEL-CARD-001` |
| Versión | `1.0.0` |
| Fecha de corte | 2026-07-28 |
| Estado | `DESCRIPTIVA_ALCANCE_ACTUAL` |
| Corte de las fuentes del repositorio | commit `52e039f0c72f96671170e977a761691aa81c525e` |
| Candidato de producto evaluado | commit `77edd64037bb0e41edffa58cae2682ba7d2694d2` |
| Evidencia final | `DAT-25`, SHA-256 `05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d` |

`MOD-01` no es un modelo de machine learning ni un modelo GenAI real. Es un
doble determinista para pruebas reproducibles. Esta ficha documenta su
contrato y evita atribuirle capacidades, entrenamiento o garantías que no
existen. Esta ficha no constituye una certificación, una declaración de
conformidad o una aceptación de riesgo.

<!-- model-facts:start -->
| Propiedad | Valor observado |
|---|---|
| Componente | `MOD-01` |
| Clase | `DeterministicModelAdapter` |
| Proveedor declarado | `deterministic` |
| Modelo declarado | `scripted-v1` |
| Determinista | `true` |
| Llamadas externas | `false` |
| Coste externo registrado | `0` EUR |
| Respuesta desconocida | `UnknownModelRequestError` |
| Runtime | Mismo proceso Python que la aplicación |
| Entrenamiento, fine-tuning, pesos o parámetros aprendidos | Ninguno |
<!-- model-facts:end -->

## Finalidad

Usos previstos:

- repetir exactamente intercambios benignos y de evaluación;
- probar fronteras tipadas, flujo de herramienta y políticas sin variación,
  credenciales de proveedor o coste externo;
- producir una baseline funcional local reproducible.

Usos no previstos:

- responder a prompts libres o solicitudes no guionizadas;
- sustituir una evaluación de un LLM, SLM, modelo multimodal o agente real;
- generar conocimiento, razonar sobre casos nuevos o representar calidad
  semántica;
- autenticar identidades, conceder permisos, decidir riesgo o ejecutar
  herramientas;
- servir decisiones reales o un entorno de producción.

## Arquitectura e interfaz

`ModelRequest` exige:

- una única instrucción confiable al principio;
- datos de usuario clasificados explícitamente;
- al menos un elemento de contenido no confiable;
- como máximo los nombres de herramienta tipados
  `knowledge_search` y `draft_create`.

`ModelResponse` solo puede terminar con texto o con una solicitud de
herramienta tipada. `ModelToolRequest` exige argumentos JSON que formen un
objeto y respeta el límite de bytes de la aplicación. La huella SHA-256 de la
petición completa selecciona un intercambio preconfigurado; una huella no
registrada falla cerrada con `UnknownModelRequestError`.

El descriptor `ModelDescriptor` acompaña cada resultado con proveedor, nombre,
determinismo, llamadas externas y coste. El adaptador conserva las respuestas
en un mapping de solo lectura dentro de memoria.

## Datos y desarrollo del modelo

No existe entrenamiento, preentrenamiento, fine-tuning, aprendizaje online,
datos de entrenamiento, pesos, parámetros aprendidos, tokenizer, embeddings,
checkpoint o artefacto de modelo. Los `ScriptedExchange` se construyen desde
los escenarios deterministas de `CMP-04`.

Los datasets documentados en la [data card](./data-card.md) son entradas,
conocimiento, casos de prueba y evidencia; no deben describirse como corpus de
entrenamiento de `MOD-01`.

## Autoridad y seguridad

- El adaptador no autentica identidades ni concede permisos.
- La salida pertenece a `TB-03` y se considera no confiable.
- El modelo no posee identidad, credenciales, grants, red, filesystem ni
  autoridad de efecto.
- `CMP-03` valida la respuesta y decide si emite una solicitud a `TOL-01`.
- El grant a `TOL-01` deriva del incidente validado y de la política de
  aplicación, no del catálogo anunciado por el modelo.
- No existe ruta desde `MOD-01` hacia `TOL-02`; el flujo de borradores es
  interno y separado.
- `CMP-09`, `CMP-10` y `CMP-11` son controles de aplicación, no capacidades
  del adaptador.

Estas separaciones son lógicas dentro de un único proceso. No protegen frente
a código Python arbitrario ejecutado con la cuenta local.

## Evaluación observada

`DAT-25` evalúa el sistema completo en el que participa este doble; no es un
benchmark aislado de calidad del modelo:

- 14/14 casos adversarios completados, con éxito observado 1/14 a 0/14,
  operaciones no autorizadas aceptadas o ejecutadas 1 a 0, un caso mejorado y
  cero regresiones;
- 12/12 casos benignos completados, cero falsos rechazos, 12 outputs únicos,
  24/24 hallazgos, 36/36 acciones y 24/24 prohibiciones preservados mediante
  la rúbrica cerrada;
- dos intervenciones de la política de salida;
- cero llamadas de red o proveedor y cero coste externo atribuido al modelo;
- cuatro fixtures inertes no ejecutadas.

La presencia literal fue 0/24 hallazgos y 0/36 acciones. La evaluación usa
fuentes e invariantes autorizados y no un juez LLM. Por ello no demuestra
equivalencia semántica general, calidad generativa, factualidad abierta,
robustez frente a ataques desconocidos o comportamiento de un modelo real.

`DAT-22` es una medición operativa histórica de candidatos anteriores y no
debe atribuirse a `MOD-01` en el candidato final. No hay benchmark aislado de
throughput, latencia, memoria, energía, concurrencia o carga sostenida para el
adaptador actual.

## Equidad, privacidad y ética

El doble no aprende ni perfila individuos. Sus entradas son sintéticas y no
contienen atributos demográficos diseñados para evaluar grupos. Esto reduce
exposición de privacidad en el laboratorio, pero no demuestra equidad,
ausencia de sesgo o comportamiento responsable de un modelo real.

No se han evaluado:

- diferencias de rendimiento entre grupos o idiomas;
- daño por alucinación, persuasión o generación abierta;
- explicabilidad de un modelo aprendido;
- privacidad diferencial, memorización o inferencia sobre datos de
  entrenamiento, porque no existe entrenamiento.

## Limitaciones y riesgo residual

- Solo reconoce peticiones completas preconfiguradas.
- El determinismo mejora reproducibilidad, pero reduce la validez externa.
- No cubre prompts libres, variaciones semánticas, otros idiomas o
  codificaciones.
- No hay proveedor, endpoint remoto, autenticación de servicio o aislamiento
  de proceso.
- La evaluación DOS y supply chain sigue inerte.
- `RR-04`, `RR-05` y `RR-06`, junto con los demás riesgos del snapshot,
  continúan `PENDIENTE_HUMANA`.

La [system card](./system-card.md), el
[riesgo residual](./residual-risk-and-tradeoffs.md) y la
[matriz de autoridad](./authority-matrix.md) son necesarios para interpretar
estos límites.

## Operación, cambios y revisión

Revisar esta ficha y reevaluar antes de sustituir el adaptador, añadir
intercambios, exponer prompt libre, cambiar el esquema, incorporar un proveedor
o modelo real, habilitar red, cambiar herramientas o ampliar usuarios y
efectos.

La política
[`GSL-MODEL-CHANGE-001`](./model-change-reevaluation-policy.md) completa
`PGS-06-M09`: clasifica cambios de `MOD-01` y superficies futuras y asigna
paquetes de reevaluación. Cualquier cambio en `MOD-01` o su frontera sigue
siendo un disparador, no una mejora automáticamente aceptada.

## Anexo posterior — `MOD-02`

`GSL-OLLAMA-001` no sustituye ni modifica `MOD-01`: añade
`HostedModelDescriptor` y `OllamaCloudAdapter` como backend experimental
seleccionable solo para `analyze`, con `deterministic=false` y
`external_calls=true`.

| Propiedad | Valor declarado y evidencia acotada |
|---|---|
| Proveedor | `ollama` |
| Modelo | `gpt-oss:120b` |
| Determinista | `false`, incluso con `temperature=0` |
| Llamadas externas | `true`; exactamente dos por operación |
| Coste | desconocido |
| Herramienta | solo `knowledge_search` en la primera llamada; ninguna anunciada en la segunda |
| Salida | JSON solicitado por prompt y validado localmente con fallo cerrado |
| Evidencia actual | 408 tests con transporte falso; un smoke instrumentado end-to-end tras dos fallos cerrados |

El endpoint, modelo, `stream=false`, `think=low`, timeout de 60 s y cero
reintentos están fijados. La aplicación ignora y no proyecta `thinking`, trata
tool calls y contenido remoto como no confiables y conserva la autoridad en
los grants y esquemas locales. Prompt, cuerpo remoto, respuesta cruda y
`OLLAMA_API_KEY` no forman parte del resultado, journal o error.

`MOD-02` no ha sido benchmarkeado ni evaluado de forma general para calidad,
factualidad, robustez, sesgo, privacidad contractual, disponibilidad, latencia
o coste. El único éxito real acredita el flujo acotado, no esas propiedades.
No participa en baseline, corpus adversario, evaluadores o `DAT-25`; sus
métricas históricas no pueden atribuirse al modelo alojado.
