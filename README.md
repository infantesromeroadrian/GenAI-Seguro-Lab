# GenAI Seguro Lab

Laboratorio local para estudiar, implementar y evaluar controles de seguridad
en una aplicación GenAI con herramientas.

El proyecto reproduce un flujo de análisis de incidentes sobre datos sintéticos,
lo somete a casos adversarios autorizados y compara su comportamiento antes y
después del endurecimiento. Incluye CLI, frontal web local, threat model,
controles, pruebas, métricas y evidencia versionada.

> El runtime usa por defecto un doble determinista. Existe además un backend
> experimental y explícito para Ollama Cloud que solo analiza un incidente
> sintético; no participa en la baseline ni en la evidencia histórica.

## Qué demuestra

- Separación entre instrucciones confiables y contenido no confiable.
- Validación estricta de entradas, esquemas y allowlists.
- Mínimo privilegio para conocimiento, herramientas y efectos.
- Aprobaciones sintéticas autenticadas y ligadas a una operación.
- Filtrado y redacción deterministas antes de entregar una salida.
- Límites de recursos, eventos saneados y recuperación create-only.
- Evaluación de prompt injection, jailbreak, exfiltración y abuso de
  herramientas.
- Trazabilidad entre requisitos, amenazas, controles, riesgos y pruebas.

## Frontal local

El frontal permite seleccionar uno de los 12 incidentes benignos, ejecutar su
análisis, lanzar la baseline completa y revisar las señales de seguridad
generadas durante la operación.

```bash
uv sync --frozen
uv run --frozen python main.py web
```

Después, abre [http://127.0.0.1:8765](http://127.0.0.1:8765).

La interfaz está fijada a loopback y no incorpora prompt libre, cargas de
archivos, persistencia ni telemetría externa. El backend queda fijado al
arrancar; para activar el egress sintético experimental:

```bash
printf 'OLLAMA_API_KEY: ' >&2
IFS= read -r -s OLLAMA_API_KEY
printf '\n' >&2
export OLLAMA_API_KEY
uv run --frozen python main.py web --provider ollama
unset OLLAMA_API_KEY
```

La baseline del frontal permanece siempre determinista. Su contrato y su
modelo de amenazas están en la
[especificación web](./docs/web-interface-spec.md) y el
[threat model del frontal](./docs/web-threat-model.md).

## Demo pública estática

El mismo frontal admite un perfil público de solo lectura basado en snapshots
deterministas. No publica Python, Functions, API, POST, Ollama o secretos y
etiqueta sus resultados como precomputados. El checkout contiene la
configuración y el artefacto reproducible, pero no se declara aquí una URL o
un despliegue verificado.

Consulta la [especificación pública](./docs/public-static-profile-spec.md) y su
[threat model](./docs/public-static-threat-model.md).

## Uso por CLI

Analizar un incidente sintético:

```bash
uv run --frozen python main.py analyze --incident INC-BEN-001
```

Incluir el informe de seguridad saneado:

```bash
uv run --frozen python main.py analyze \
  --incident INC-BEN-001 \
  --security-report
```

Analizar un único incidente con Ollama Cloud, de forma opt-in:

```bash
printf 'OLLAMA_API_KEY: ' >&2
IFS= read -r -s OLLAMA_API_KEY
printf '\n' >&2
export OLLAMA_API_KEY
uv run --frozen python main.py analyze \
  --incident INC-BEN-001 \
  --provider ollama
unset OLLAMA_API_KEY
```

El endpoint y modelo están fijados, se realizan exactamente dos llamadas sin
reintentos y el coste se declara desconocido. Consulta el
[contrato experimental de Ollama Cloud](./docs/ollama-cloud-experimental.md)
antes de habilitarlo. No introduzcas la clave en argumentos, ficheros
versionados o salida.

Ejecutar los 12 casos benignos:

```bash
uv run --frozen python main.py baseline
```

## Arquitectura

```text
Operador local
   │
   ├── CLI
   └── Web en 127.0.0.1
          │
          ▼
Validación y contexto de ejecución
          │
          ▼
Doble determinista u Ollama opt-in ──► conocimiento y herramienta local
          │
          ▼
Política de salida ──► resultado saneado
          │
          └──────────► journal de seguridad efímero
```

Todo se ejecuta en un único host con datos sintéticos. Los límites de confianza
son lógicos; no equivalen a aislamiento de sistema operativo. El mapa
conceptual completo está en
[`architecture/manifest.json`](./architecture/manifest.json).

## Resultados verificados

| Indicador | Antes | Después |
|---|---:|---:|
| Éxito adversario observado | 1/14 | 0/14 |
| Operaciones no autorizadas aceptadas y ejecutadas | 1 | 0 |
| Casos benignos completados | 12/12 | 12/12 |
| Falsos rechazos benignos | 0 | 0 |
| Llamadas y coste externos | 0 / 0 € | 0 / 0 € |

Estos resultados pertenecen exclusivamente al candidato determinista, corpus
sintético y rúbrica versionados. Son anteriores a `GSL-OLLAMA-001` y no
demuestran seguridad universal, resistencia frente a ataques desconocidos ni
comportamiento de Ollama Cloud o `gpt-oss:120b`.

La evidencia principal está en:

- [retest final](./evaluations/final-retest-v1.json);
- [métricas adversarias](./evaluations/adversarial-metrics-v1.json);
- [utilidad benigna](./evaluations/benign-utility-v1.json);
- [métricas operativas](./evaluations/operational-metrics-v1.json).

## Verificación

```bash
uv run --frozen pytest -q
```

La suite cubre contratos de datos, flujo benigno, controles, evaluaciones,
evidencia, documentación y superficie web. La evidencia histórica del retest
final permanece inmutable y no se regenera durante una ejecución ordinaria.

## Documentación

### Diseño y seguridad

- [Inventario del sistema](./docs/system-inventory.md)
- [System card](./docs/system-card.md)
- [Data card](./docs/data-card.md)
- [Model card](./docs/model-card.md)
- [Matriz de autoridad](./docs/authority-matrix.md)
- [Catálogo de abuse cases](./docs/abuse-cases.md)
- [Crosswalk de amenazas](./docs/threat-crosswalk.md)
- [Mapa de controles](./docs/control-responsibility-mapping.md)
- [Rules of Engagement](./docs/rules-of-engagement.md)
- [Decisión de arquitectura](./docs/architecture-decision-record.md)
- [Backend experimental de Ollama Cloud](./docs/ollama-cloud-experimental.md)
- [Perfil público estático](./docs/public-static-profile-spec.md)
- [Threat model público](./docs/public-static-threat-model.md)

### Gobierno y operación

- [Evaluación de impacto de IA](./docs/ai-impact-assessment.md)
- [RACI](./docs/raci.md)
- [Registro de riesgos](./docs/risk-register.md)
- [Mapa de cumplimiento](./docs/compliance-map.md)
- [Política de eventos de seguridad](./docs/security-events-policy.md)
- [Runbook de incidentes de IA](./docs/ai-incident-response-runbook.md)
- [Parada y recuperación](./docs/stop-recovery-procedure.md)
- [Dependencias y supply chain](./docs/dependency-supply-chain-register.md)
- [Cambios de modelo y reevaluación](./docs/model-change-reevaluation-policy.md)

### Evidencia y cierre

- [Matriz final de trazabilidad](./docs/final-traceability-matrix.md)
- [Resumen técnico](./docs/technical-summary.md)
- [Resumen ejecutivo](./docs/executive-summary.md)
- [Revisión de criterios](./docs/phase-01-criteria-review.md)
- [Estado de SEC-1](./docs/sec-1-status.md)
- [Disposición de revisión independiente](./docs/independent-review-disposition.md)
- [Reconstrucción limpia](./evaluations/clean-rebuild-v1.json)
- [Ejecución de cierre](./evaluations/closure-execution-v1.json)
- [Escaneo de contenido](./evaluations/content-scan-v1.json)
- [Paquete de revisión independiente](./reviews/independent-review-pack-v1.json)
- [Registro de omisión](./reviews/independent-review-omission-v1.json)

El [índice técnico completo](./docs/README.md) reúne el resto de políticas,
artefactos y evidencias.

## Estado y límites

La implementación local, el frontal y la evaluación automatizada están
disponibles. La revisión humana independiente fue omitida, no completada, y
`SEC-1` permanece `OPEN_NOT_ACHIEVED`; por tanto, el proyecto no debe
presentarse como revisión independiente, certificación, conformidad legal
integral ni sistema preparado para producción.

Cuatro casos de disponibilidad y supply chain permanecen inertes, y el
laboratorio no incorpora autenticación multiusuario, despliegue remoto, datos
reales ni aislamiento kernel. El backend Ollama es experimental, probabilístico
y se ha ejercitado una vez end-to-end con `INC-BEN-001` tras dos fallos
cerrados previos. Esa evidencia acotada no demuestra disponibilidad,
reproducibilidad, coste o comportamiento general del servicio real.

El detalle del trabajo planificado y su trazabilidad se conserva en el
[plan del proyecto](./plan-proyecto-GenAI-Seguro-Lab.md), separado de esta
portada.

## Uso responsable

Ejecuta únicamente los casos incluidos contra este laboratorio local y propio.
No introduzcas secretos, datos personales, incidentes corporativos ni objetivos
de terceros.
