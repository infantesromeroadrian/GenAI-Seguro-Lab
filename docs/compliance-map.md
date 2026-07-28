# Mapa de cumplimiento — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-COMPLIANCE-MAP-001` |
| Versión | `1.0.0` |
| Fecha de consulta | 2026-07-28 |
| Estado | `VIGENTE_ALCANCE_ACTUAL` |
| Owner | `ACT-02` |
| Alcance | laboratorio local, determinista, sintético, sin red, usuarios externos ni despliegue |

Este mapa separa obligaciones potenciales, estándares y guías voluntarias y
decisiones internas. No es asesoramiento jurídico, una declaración de
conformidad, una certificación, una autorización de producción ni una
aceptación de riesgo. La aplicabilidad legal definitiva requiere jurisdicción,
rol, finalidad, datos, personas afectadas y forma de puesta en servicio
concretos; esos hechos no existen en el alcance actual.

## Convención

| Naturaleza | Significado |
|---|---|
| `OBLIGACION_POTENCIAL` | Norma jurídica que puede resultar obligatoria si se activa su ámbito material, territorial o subjetivo. El mapa no decide por sí solo que sea aplicable. |
| `ESTANDAR_VOLUNTARIO` | Estándar adoptable por decisión propia o exigencia contractual. No equivale a certificación ni obligación legal automática. |
| `GUIA_VOLUNTARIA` | Marco, taxonomía o práctica utilizada para estructurar el trabajo sin atribuir conformidad. |
| `DECISION_INTERNA_VOLUNTARIA` | Regla del proyecto elegida para gobernar este alcance. Solo obliga al proyecto dentro de la autoridad ya concedida. |

Los estados `POR_CONFIRMAR`, `NO_ACTIVADA_ALCANCE_ACTUAL`, `NO_ADOPTADO`,
`APLICADA_PARCIAL` y `VIGENTE_INTERNA` describen únicamente este corte.

## Mapa

<!-- compliance-map:start -->
| ID | Fuente | Naturaleza | Estado actual | Evidencia y uso observado | Gap o trigger | Owner |
|---|---|---|---|---|---|---|
| `CMPMAP-01` | Reglamento de IA de la UE y AI Omnibus | `OBLIGACION_POTENCIAL` | `POR_CONFIRMAR` | El sistema es un doble determinista local y no se ha clasificado jurídicamente como sistema de IA, modelo de propósito general, proveedor, responsable del despliegue o producto de alto riesgo. `GSL-AIA-001` prohíbe inferir producción o alto impacto. | Revisión jurídica antes de puesta en servicio, uso en la UE, modelo real, usuarios externos, finalidad regulada o cambio de rol. | `ACT-02`; asesoría jurídica no asignada |
| `CMPMAP-02` | RGPD | `OBLIGACION_POTENCIAL` | `NO_ACTIVADA_ALCANCE_ACTUAL` | `GSL-DATA-CARD-001` registra solo datos sintéticos y ningún dato personal, titular real o decisión sobre personas. | Reevaluar antes de introducir datos personales, identificadores, telemetría de personas, reidentificación o tratamiento por un tercero. | `ACT-02`; responsable de protección de datos no asignado |
| `CMPMAP-03` | ISO/IEC 42001:2023 | `ESTANDAR_VOLUNTARIO` | `NO_ADOPTADO` | Las fichas, RACI, evaluación de impacto y registro de riesgos aportan artefactos reutilizables, pero no existe un sistema de gestión de IA auditado. | Decisión expresa de adopción, alcance del AIMS, auditoría y organismo competente antes de cualquier afirmación de certificación. | `ACT-02` |
| `CMPMAP-04` | NIST AI RMF 1.0 y perfil GenAI NIST AI 600-1 | `GUIA_VOLUNTARIA` | `APLICADA_PARCIAL` | `GSL-NIST-CONTROLS-001` usa identificadores seleccionados de Govern, Map, Measure y Manage; no demuestra cobertura integral ni eficacia general. | Revalidar cuando NIST publique una revisión final o cambien modelo, datos, interfaz, efectos o despliegue. | `ACT-02` |
| `CMPMAP-05` | NIST SP 800-218A con SSDF 1.1 | `GUIA_VOLUNTARIA` | `APLICADA_PARCIAL` | El mapa de controles relaciona prácticas de desarrollo seguro con pruebas y limitaciones existentes. Operación, respuesta general y varias decisiones humanas siguen fuera. | Nueva dependencia, pipeline, proveedor, release, distribución o cambio del ciclo de desarrollo. | `ACT-02` |
| `CMPMAP-06` | OWASP Top 10 for LLM Applications 2025 y Agentic Applications 2026 | `GUIA_VOLUNTARIA` | `APLICADA_PARCIAL` | `GSL-THREAT-CROSSWALK-001` mapea los 17 abuse cases sin forzar equivalencias ni afirmar cobertura frente a ataques desconocidos. | Nuevo modelo LLM, RAG, agente, herramienta, memoria, entrada libre o edición publicada relevante. | `ACT-02` |
| `CMPMAP-07` | MITRE ATLAS data `v2026.06` | `GUIA_VOLUNTARIA` | `APLICADA_PARCIAL` | El crosswalk fija la release y las técnicas utilizadas; ATLAS se usa como taxonomía y no como certificado. | Nueva técnica aplicable, cambio de threat model o actualización deliberadamente adoptada. | `ACT-02` |
| `CMPMAP-08` | CISA/NCSC Guidelines for Secure AI System Development | `GUIA_VOLUNTARIA` | `APLICADA_PARCIAL` | El proyecto aplica secure-by-design, mínimos privilegios, pruebas y documentación dentro de un laboratorio local, pero no opera un servicio desplegado ni una cadena organizativa completa. | Proveedor real, infraestructura operada, distribución, despliegue o nueva obligación contractual. | `ACT-02` |
| `CMPMAP-09` | `GSL-ADR-001`, `GSL-AIA-001`, RACI y registro de riesgos | `DECISION_INTERNA_VOLUNTARIA` | `VIGENTE_INTERNA` | Mantienen la baseline local-first, el alcance sintético, la autoridad fuera del modelo y seis decisiones `PENDIENTE_HUMANA`. | Cualquier trigger `ADR-TRG-*` o `AIA-TRG-*`, decisión de riesgo, nueva autoridad o cambio de alcance. | `ACT-02` |
<!-- compliance-map:end -->

## Fuentes oficiales consultadas

- [Comisión Europea — marco regulador de la IA](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai).
- [Comisión Europea — AI Omnibus en vigor](https://digital-strategy.ec.europa.eu/en/news/ai-omnibus-enters-force).
- [Comisión Europea — preguntas frecuentes del Reglamento de IA](https://digital-strategy.ec.europa.eu/en/faqs/navigating-ai-act).
- [EUR-Lex — Reglamento (UE) 2016/679, RGPD](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX%3A32016R0679).
- [ISO — ISO/IEC 42001:2023](https://www.iso.org/standard/42001).
- [NIST — AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework).
- [NIST — SP 800-218A, final](https://csrc.nist.gov/pubs/sp/800/218/a/final).
- [OWASP — Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/).
- [MITRE — ATLAS](https://atlas.mitre.org/).
- [CISA — Guidelines for Secure AI System Development](https://www.cisa.gov/news-events/alerts/2023/11/26/cisa-and-uk-ncsc-unveil-joint-guidelines-secure-ai-system-development).

La consulta de 2026-07-28 observa que el Reglamento de IA tiene un calendario
de aplicación escalonado y que el AI Omnibus modificó hitos para sistemas de
alto riesgo. Como el laboratorio no tiene una clasificación jurídica ni una
puesta en servicio, esas fechas se registran como contexto y no como una
obligación atribuida al proyecto.

## Correspondencia operativa

| Necesidad | Evidencia actual | Límite |
|---|---|---|
| Gobierno y accountability | `GSL-AIA-001`, `GSL-RACI-001`, `GSL-RISK-REGISTER-001` | `ACT-02` concentra funciones y `REV-01` no está asignado. |
| Desarrollo seguro | `GSL-NIST-CONTROLS-001`, políticas `GSL-*`, suite de pruebas | La validación documental no demuestra conformidad ni resistencia universal. |
| Threat model | `GSL-ABUSE-CASES-001`, priorización y `GSL-THREAT-CROSSWALK-001` | Cuatro fixtures DOS/SC permanecen inertes y no existe modelo real. |
| Privacidad | datos sintéticos, redacción y ausencia de red | No se ha evaluado un tratamiento real ni una base jurídica. |
| Trazabilidad y cambio | Git, hashes, ADR, fichas y triggers | No hay firma, SBOM, CI, release ni revisión independiente ejercida. |

## Regla de mantenimiento

1. Revalidar las fuentes oficiales durante el cierre PGS-07 y ante un trigger.
2. No cambiar silenciosamente una versión fijada; registrar el nuevo corte y
   el impacto sobre controles, riesgos y pruebas.
3. No convertir una guía o estándar en obligación sin la fuente y el hecho que
   la activan.
4. No declarar cumplimiento, certificación o ausencia de obligaciones sin una
   evaluación competente del alcance real.
5. Mantener `RR-01` a `RR-06` abiertos hasta su decisión humana; este mapa no
   modifica su estado.

## Relación con Tecture

El mapa clasifica fuentes y decisiones sobre los componentes, flujos y límites
ya documentados. No añade servicios, almacenes, integraciones, interfaces,
despliegues ni trust boundaries, por lo que no modifica `architecture/`.
