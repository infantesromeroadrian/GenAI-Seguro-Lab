# Ollama Cloud experimental — `GSL-OLLAMA-001`

## Estado

Este backend es una extensión opt-in para analizar **un único incidente
sintético**. El backend por defecto sigue siendo
`deterministic/scripted-v1`. Ollama no participa en `baseline`, evaluaciones,
corpus adversario ni `DAT-25`.

La integración real queda `PASSED_BOUNDED_REAL_SMOKE`. El primer smoke del
2026-07-28 alcanzó la tool call, pero el modelo devolvió `query` vacío y el
esquema local la rechazó antes de ejecutar la herramienta. Tras reforzar el
mapeo de argumentos, un smoke no instrumentado del 2026-07-29 volvió a terminar
con el error público saneado `functional baseline is unavailable`. Una única
ejecución diagnóstica posterior, autorizada y saneada, completó el flujo con
dos POST, dos invocaciones, una petición y resultado de `knowledge_search`,
política de salida permitida y `operation_completed`, sin excepción o señal de
seguridad. Las pruebas automatizadas usan transporte falso y suman 408 casos
superados. Este éxito acotado no demuestra disponibilidad, reproducibilidad,
calidad, coste, privacidad contractual ni seguridad empírica general del
servicio alojado.

## Contrato fijado

| Campo | Valor |
|---|---|
| Activación | `analyze --provider ollama` o `web --provider ollama` |
| Endpoint | `POST https://ollama.com/api/chat` |
| Modelo | `gpt-oss:120b` |
| Autenticación | `Authorization: Bearer` desde `OLLAMA_API_KEY` |
| Generación | `stream=false`, `think=low`, `temperature=0` |
| Presupuesto | exactamente dos llamadas; 60 s por llamada; cero reintentos |
| Herramientas | primera llamada: solo `knowledge_search`; segunda: campo `tools` ausente |
| Structured output | JSON solicitado en prompt y validado localmente; fallo cerrado |
| Coste | desconocido |
| Descriptor | `deterministic=false`, `external_calls=true` |
| Persistencia | ninguna en la aplicación |

El transporte usa TLS normal de la librería estándar, rechaza redirects y
acota el cuerpo antes de parsearlo. Los errores de credencial, transporte,
estado HTTP, timeout, tamaño o esquema se reducen a mensajes y señales
saneados. No hay fallback, retry ni cambio de endpoint.

## Datos, autoridad y secretos

El egress contiene exclusivamente la tarea enumerada, un incidente sintético
validado y, en la segunda llamada, el resultado sintético de la búsqueda local.
No se envían `expected_result`, oráculos, rúbrica, corpus adversario, datos
reales, rutas locales ni credenciales distintas de la cabecera de
autenticación.

La tool call remota es contenido no confiable. La aplicación exige exactamente
una solicitud inicial, rechaza cualquier herramienta distinta de
`knowledge_search` antes de crear o usar la vista y vuelve a aplicar el grant,
scope, allowlist y esquema locales. La segunda respuesta debe ser un único
objeto JSON que cumpla `BenignFinalOutput`; después se aplican el límite de
resumen y la política de salida.

`thinking`, prompts, cuerpos remotos, respuestas crudas y el secreto no se
registran ni forman parte del resultado, journal o error. `OLLAMA_API_KEY`
debe proporcionarse en el entorno del proceso; `.env.example` solo documenta
el nombre con valor vacío. El proyecto no carga automáticamente archivos
`.env`.

## Uso

```bash
printf 'OLLAMA_API_KEY: ' >&2
IFS= read -r -s OLLAMA_API_KEY
printf '\n' >&2
export OLLAMA_API_KEY
uv run --frozen python main.py analyze \
  --incident INC-BEN-001 \
  --provider ollama \
  --security-report
unset OLLAMA_API_KEY
```

```bash
printf 'OLLAMA_API_KEY: ' >&2
IFS= read -r -s OLLAMA_API_KEY
printf '\n' >&2
export OLLAMA_API_KEY
uv run --frozen python main.py web --provider ollama
unset OLLAMA_API_KEY
```

El frontal queda fijado al proveedor elegido al arrancar. Su status declara
proveedor, modelo, determinismo, egress, coste desconocido y si la credencial
está configurada. Con credencial ausente, `analyze` queda no disponible y
`baseline` continúa local y determinista.

## Límites y prueba real

- Solo se admiten los IDs benignos sintéticos versionados; no hay prompt libre,
  uploads, datos reales ni búsqueda remota.
- El modelo alojado es probabilístico aunque `temperature=0`; no existe una
  promesa de reproducibilidad.
- Dos llamadas pueden generar coste y transferir datos sintéticos al proveedor;
  no se ha verificado precio, cuota, residencia, retención o términos.
- El timeout no constituye cancelación garantizada del cómputo remoto.
- Las pruebas con transporte falso demuestran el contrato de aplicación. La
  ejecución instrumentada acredita un análisis completo de `INC-BEN-001`, pero
  los dos fallos previos y el carácter probabilístico impiden extrapolarlo a
  disponibilidad o reproducibilidad de Ollama o `gpt-oss:120b`.
- Una nueva prueba real requiere autorización raíz vigente, credencial válida,
  revisión de egress/coste/términos e instrumentación saneada de etapa y número
  de llamadas. Nunca debe regenerar ni reinterpretar `DAT-25`.
