# ADR — backend alojado opt-in de Ollama

| Campo | Valor |
|---|---|
| Identificador | `GSL-ADR-002` |
| Estado | `ACEPTADA_EXPERIMENTAL` |
| Fecha | 2026-07-28 |
| Alcance | solo `analyze` de un incidente benigno sintético |
| Relación | extensión posterior de `GSL-ADR-001`; no sustituye su baseline determinista |
| Evidencia | 408 tests; smoke instrumentado end-to-end superado tras dos fallos cerrados |

## Contexto

`GSL-ADR-001` seleccionó la ruta determinista, local y reproducible y dejó un
proveedor alojado sujeto a trigger. `GSL-OLLAMA-001` materializa ese trigger
con un objetivo limitado: observar el mismo flujo seguro con un modelo real sin
convertirlo en baseline, evaluación o nueva autoridad.

## Decisión

Mantener `deterministic/scripted-v1` como default y único backend de baseline y
evaluaciones. Añadir `ollama/gpt-oss:120b` únicamente mediante
`--provider ollama` en `analyze` y `web`, fijado al arrancar el frontal.

El adaptador usa la API nativa directa, stdlib y un transporte inyectable:

- `POST https://ollama.com/api/chat`, TLS normal y redirects rechazados;
- Bearer desde `OLLAMA_API_KEY`, sin almacenarlo o proyectarlo;
- `stream=false`, `think=low`, `temperature=0`;
- exactamente dos llamadas de 60 s y cero retries;
- primera llamada con solo `knowledge_search`; segunda sin `tools`;
- tool call no confiable sometida a grants, scope, allowlist y esquema locales;
- JSON final pedido en prompt, validado localmente y tratado con fallo cerrado;
- coste desconocido, `deterministic=false`, `external_calls=true`;
- sin thinking, prompt, cuerpo remoto o respuesta cruda en resultados, journal
  o errores.

## Consecuencias

Se obtiene fidelidad a un modelo alojado para una ruta sintética, pero aparecen
egress, secreto, dependencia de tercero, comportamiento probabilístico,
disponibilidad y coste desconocidos. `temperature=0` no convierte el servicio
en determinista.

La suite demuestra endpoint, cabeceras saneadas, timeout, protocolo de
herramienta, límites, rechazo de redirects/errores y ausencia de retries con
transporte falso. Tras dos smokes fail-closed, una ejecución instrumentada del
2026-07-29 completó dos POST, una búsqueda local, la respuesta final y la
política de salida sin excepción ni señal. Es evidencia acotada a un incidente
y no demuestra disponibilidad, reproducibilidad, calidad, robustez, privacidad
contractual, retención, residencia o precio del proveedor.

## Límites y rollback

Baseline, evaluaciones, corpus y `DAT-25` no admiten proveedor. Ante error,
deriva o retirada de autoridad, el operador deja de seleccionar Ollama o
reinicia el frontal con `--provider deterministic`; no existe fallback
automático. La clave se retira del entorno. La evidencia histórica no se
modifica, regenera ni reinterpreta.

Cambiar endpoint, modelo, herramienta, datos, número de llamadas, timeout,
persistencia o uso real exige revisar RoE, AIA, riesgos y esta decisión antes de
actuar.
