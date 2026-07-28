# Resumen técnico

## Resultado

GenAI Seguro Lab es un laboratorio Python 3.12 local, reproducible y
deliberadamente acotado. Usa un **doble determinista**, no un LLM real, para
probar fronteras de instrucciones, conocimiento, herramientas, autoridad,
salida, recursos, eventos y recuperación sin red ni efectos externos.

La extensión posterior [`GSL-WEB-001`](./web-interface-spec.md) añade un
frontal visual fijado a loopback. Reutiliza el flujo benigno y no altera la
evidencia ni los contadores del cierre descritos en este documento.

La [matriz final](./final-traceability-matrix.md) traza 25 requisitos:
8 `DEMONSTRATED`, 14 `DEMONSTRATED_BOUNDED`, 2 `PARTIAL` y 1
`NOT_DEMONSTRATED`. La revisión humana independiente fue omitida; por ello
`SC-12`, `DEL-10`, `P01-M11` y la reproducción por un tercero de `SEC-1`
permanecen no demostrados.

## Arquitectura y límites de confianza

El [mapa C4](../architecture/manifest.json) describe un proceso local, datos
sintéticos, doble determinista, herramientas confinadas, harness adversario y
evidencia versionada. Sus seis trust boundaries son lógicos; no constituyen
aislamiento de sistema operativo.

Las superficies y la autoridad se localizan en:

- [inventario del sistema](./system-inventory.md);
- [matriz de autoridad](./authority-matrix.md);
- [Rules of Engagement](./rules-of-engagement.md);
- [system, data y model cards](./system-card.md), [data card](./data-card.md) y
  [model card](./model-card.md).

No existen proveedor, modelo GenAI real, API pública o frontal remoto, Docker,
cloud, base de datos, telemetría externa, SIEM o identidad humana de
producción. Sí existe un frontal local en `127.0.0.1`, sin prompt libre,
persistencia o llamadas externas.

## Amenazas y controles

El [catálogo](./abuse-cases.md) contiene 17 abuse cases de prompt injection,
jailbreak, exfiltración, abuso de herramientas, disponibilidad y supply chain.
El [crosswalk](./threat-crosswalk.md) los relaciona con OWASP LLM, OWASP
Agentic y MITRE ATLAS sin afirmar equivalencia total.

El [mapa de controles](./control-responsibility-mapping.md) conserva trece
controles y sus pruebas. La defensa observada combina:

- separación de dominios de confianza, esquemas y allowlists;
- mínimo privilegio lógico y grants ligados a contexto;
- aprobación sintética autenticada y de un solo uso;
- política de salida y redacción determinista;
- límites cooperativos de tamaño, tiempo, iteraciones y consumo;
- eventos saneados en memoria;
- publicación create-only, parada y reconciliación del sandbox.

La eficacia está demostrada únicamente frente a los casos y contratos
versionados. Tres fixtures DOS y una de supply chain permanecen inertes.

## Evaluación

| Evidencia | Resultado observado | Límite principal |
|---|---|---|
| [Baseline adversaria](../evaluations/adversarial-baseline-v1/README.md) | 14 casos; 1 residual en `ADV-TOL-005` | Candidato histórico y variantes conocidas |
| [`DAT-25`](../evaluations/final-retest-v1.json) | éxito 1/14 → 0/14; operaciones no autorizadas 1 → 0; 0 regresiones | Candidato `77edd640`, rúbrica cerrada y doble determinista |
| [`DAT-25`](../evaluations/final-retest-v1.json) | 12/12 benignos, 0 falsos rechazos y 84/84 cláusulas preservadas | No evalúa equivalencia semántica general |
| [Métricas operativas](../evaluations/operational-metrics-v1.json) | 30 pares pre/post; pared, CPU, RSS y consumo medidos; 0 € externo | Un host y sesión, sin umbral universal |
| [Reconstrucción limpia](../evaluations/clean-rebuild-v1.json) | lock, instalación y smoke correctos | Usó red; no es build hermético |
| [Ejecución de cierre](../evaluations/closure-execution-v1.json) | 327/327 tests, 12 benignos y 14 adversarios autorizados | Commit, host y sesión fijados |
| [Escaneo de contenido](../evaluations/content-scan-v1.json) | 0 hallazgos Gitleaks y 56/56 registros sintéticos | Escaneo finito; procedencia personal histórica declarada |

`DAT-25` es inmutable, no se volvió a ejecutar y conserva SHA-256
`05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d`.

## Gobierno y operación

La [evaluación de impacto](./ai-impact-assessment.md), la
[RACI](./raci.md), el [registro de riesgos](./risk-register.md), el
[mapa de cumplimiento](./compliance-map.md), los
[runbooks](./ai-incident-response-runbook.md) y la
[política de cambios](./model-change-reevaluation-policy.md) describen el
alcance humano y operativo sin inventar automatización.

`RR-01` a `RR-06` siguen `ABIERTO`; las seis decisiones asociadas permanecen
`PENDIENTE_HUMANA`. La
[disposición](./independent-review-disposition.md) conserva `D-REV-01` como
`OPEN_RETAINED`, con cero observaciones y cero correcciones atribuidas a un
tercero.

## Uso técnico admisible

El repositorio sirve para:

1. reconstruir y ejecutar un flujo benigno sintético;
2. estudiar un threat model trazable;
3. reproducir las pruebas PI/JB/EX/TOL ya autorizadas;
4. comparar una baseline histórica con controles y retest;
5. inspeccionar controles, evidencia, límites y riesgo residual.

No acredita seguridad universal, cumplimiento legal integral, certificación,
preparación para producción, resistencia de un LLM real ni aceptación de
riesgo.
