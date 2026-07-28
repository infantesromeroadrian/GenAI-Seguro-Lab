# Revisión de criterios de la fase 01

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-P01-CRITERIA-REVIEW-001` |
| Microtarea | `PGS-07-M09` |
| Fecha de consulta | 2026-07-28 |
| Fuente autoritativa | Roadmap padre vigente, fase 01 — Fundamentos de AI Security |
| Alcance | `P01-M01` y `P01-M04` a `P01-M11` |
| Fuera de alcance | `P01-M02` y `P01-M03`, gestionadas como formación fuera de este proyecto |

La revisión compara cada criterio padre con evidencia versionada. Satisfacer una
microtarea no cierra automáticamente la fase ni `SEC-1`: el gate mantiene su
prerrequisito `BASE` y exige reproducción por un tercero.

## Resultado por microtarea

<!-- p01-criteria-review:start -->
| ID | Criterio padre vigente | Evidencia | Resultado | Límite |
|---|---|---|---|---|
| `P01-M01` | Elegir un sistema AI propio y acotado mantenible como caso de estudio | [Contrato PGS-00](../plan-proyecto-GenAI-Seguro-Lab.md#fase-pgs-00--contrato-del-proyecto), [system card](./system-card.md) | `SATISFIED`: GenAI Seguro Lab está identificado, acotado y mantenido como único caso | Doble determinista local; no es un sistema GenAI real |
| `P01-M04` | Registrar versiones de OWASP LLM, OWASP Agentic, NIST AI RMF, NIST SP 800-218A y MITRE ATLAS | [Baseline de marcos](./framework-versions.md) | `SATISFIED`: las cinco fuentes tienen versión y fecha de consulta | Fuentes y guías no equivalen a certificación o conformidad |
| `P01-M05` | Delimitar usuarios, datos, modelos, agentes, herramientas, identidades, integraciones, infraestructura y supply chain | [Inventario](./system-inventory.md), [autoridad](./authority-matrix.md), [supply chain](./dependency-supply-chain-register.md) | `SATISFIED`: las categorías existentes y ausentes están inventariadas | No hay modelo real, agente autónomo, cloud o integración externa |
| `P01-M06` | Dibujar arquitectura, flujo de datos, activos, actores, superficies y trust boundaries | [Mapa C4](../architecture/manifest.json), [descripciones](../architecture/descriptions) | `SATISFIED`: contexto, contenedores, componentes, flujos y seis límites están versionados | Varios límites son lógicos dentro del mismo proceso |
| `P01-M07` | Enumerar y priorizar abuse cases y mapearlos a OWASP y MITRE ATLAS | [Abuse cases](./abuse-cases.md), [priorización](./risk-prioritization.md), [crosswalk](./threat-crosswalk.md) | `SATISFIED`: 17 casos están enumerados, priorizados y relacionados | Cuatro casos DOS/SC siguen inertes y algunos mapeos son parciales |
| `P01-M08` | Mapear controles, responsables y pruebas a NIST AI RMF y NIST SP 800-218A | [Mapa de controles](./control-responsibility-mapping.md), [RACI](./raci.md) | `SATISFIED`: 13 controles cubren 17 casos con owner, prueba y límite | El mapeo no demuestra eficacia ni conformidad |
| `P01-M09` | Ejecutar al menos una prueba reproducible antes y después de aplicar un control | [Baseline](../evaluations/adversarial-baseline-v1/README.md), [`DAT-25`](../evaluations/final-retest-v1.json), [matriz final](./final-traceability-matrix.md) | `SATISFIED`: el mismo corpus ejecutado pre/post fija 1/14 → 0/14 éxitos y 1 → 0 operaciones no autorizadas | Variantes conocidas, doble determinista y cuatro casos inertes |
| `P01-M10` | Documentar alternativas, decisión, rollback y riesgo residual en un ADR | [ADR](./architecture-decision-record.md), [riesgo residual](./residual-risk-and-tradeoffs.md), [registro de riesgos](./risk-register.md) | `SATISFIED`: alternativas, decisión acotada, triggers, rollback y seis riesgos están versionados | La decisión arquitectónica no acepta ni cierra los riesgos |
| `P01-M11` | Obtener revisión independiente y revisar `SEC-1` | [Omisión](./independent-review-omission.md), [disposición](./independent-review-disposition.md) | `NOT_SATISFIED`: no hubo revisión humana ni reproducción independiente | `REV-01` sin asignar; `D-REV-01` abierta y `SC-12` no demostrado |
<!-- p01-criteria-review:end -->

## Definition of Done y gate

El threat model versionado cubre aplicación, doble de modelo, datos,
herramientas, identidad, infraestructura y supply chain. Cada uno de los seis
riesgos tiene fuente, prueba, control y riesgo residual.

No se satisface la cláusula “un tercero puede reproducir al menos una prueba”.
Además, `BASE` continúa pendiente en el roadmap global. Por tanto:

- `P01-M01` y `P01-M04` a `P01-M10` pueden registrarse como completadas por
  criterio;
- `P01-M11` permanece abierta;
- la fase 01 y `SEC-1` permanecen abiertas;
- esta revisión no es una aprobación, waiver o aceptación de riesgo.
