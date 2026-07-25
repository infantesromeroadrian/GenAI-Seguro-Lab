# Baseline de marcos y fuentes

## Propósito

Esta nota fija las versiones que utilizará GenAI Seguro Lab para construir su
arquitectura, threat model, controles y trazabilidad. La fotografía se consultó
el **25 de julio de 2026** exclusivamente en fuentes oficiales.

Fijar una versión no convierte la guía en requisito legal, certificación o
control implementado. El crosswalk de amenazas pertenece a PGS-02-M07 y el
mapeo de responsabilidades y controles a PGS-02-M08.

## Versiones seleccionadas

| Referencia | Versión o edición fijada | Fecha oficial | Estado al consultar | Uso previsto |
|---|---|---|---|---|
| OWASP Top 10 for LLM Applications | **Version 2025**; el documento se identifica también como **v2.0** | 18-11-2024 en el PDF; página del recurso publicada el 17-11-2024 | Edición publicada que el catálogo oficial mantiene como referencia para aplicaciones LLM | Identificar y mapear riesgos de prompt injection, divulgación, supply chain, tratamiento de salidas, agencia y consumo |
| OWASP Top 10 for Agentic Applications | **Version 2026** | 09-12-2025; el PDF indica diciembre de 2025 | Edición publicada para aplicaciones agentic | Cubrir secuestro de objetivos, abuso de herramientas, identidad, supply chain agentic, ejecución y cascadas entre agentes |
| MITRE ATLAS data | release **`v2026.06`**, commit **`651dad90d3c007e797c89356fa1f4d8732f90c8d`**; `ATLAS.yaml` declara **`version: 5.6.0`** | 30-06-2026 | Última release oficial al revalidar para PGS-02-M07 | Relacionar abuse cases con tácticas, técnicas, mitigaciones y estudios de caso |
| NIST AI Risk Management Framework | **AI RMF 1.0**, **NIST AI 100-1** | 26-01-2023 | Vigente como versión publicada; NIST avisa de que está siendo revisada | Estructurar gobierno y gestión del riesgo mediante Govern, Map, Measure y Manage |
| NIST SP 800-218A | **Final**, sin revisión numerada adicional | 26-07-2024 | Publicación final | Aplicar prácticas de desarrollo seguro específicas para modelos y sistemas de IA |

## Perfil complementario para GenAI

Se incorpora como referencia complementaria **NIST AI 600-1, Artificial
Intelligence Risk Management Framework: Generative Artificial Intelligence
Profile**, publicado el **26 de julio de 2024**.

Este perfil adapta AI RMF 1.0 a riesgos de IA generativa. No sustituye a
NIST AI 100-1 ni se contabiliza como una nueva versión del marco base.

## Fuentes oficiales

### OWASP

- [OWASP Top 10 for LLM Applications 2025 — recurso oficial](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP Top 10 for LLM Applications 2025 — PDF oficial](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [OWASP Top 10 for Agentic Applications 2026 — recurso oficial](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Top 10 for Agentic Applications 2026 — anuncio de publicación](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)

### MITRE

- [MITRE ATLAS](https://atlas.mitre.org/)
- [MITRE ATLAS data v2026.06 — release oficial](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.06)
- [ATLAS.yaml de la etiqueta v2026.06](https://raw.githubusercontent.com/mitre-atlas/atlas-data/v2026.06/dist/ATLAS.yaml)
- [Snapshot anterior v5.6.0](https://github.com/mitre-atlas/atlas-data/releases/tag/v5.6.0)

La etiqueta y el commit fijan una base reproducible. La web de ATLAS es una
base viva y puede mostrar contenido posterior sin cambiar este registro.

## Revalidación para PGS-02-M07

La fotografía inicial utilizaba la etiqueta `v5.6.0`, commit `c1050fc`, del 4
de mayo de 2026. La consulta previa al crosswalk encontró una release posterior:

- etiqueta `v2026.06`;
- fecha de publicación 30 de junio de 2026;
- commit `651dad90d3c007e797c89356fa1f4d8732f90c8d`;
- 170 técnicas y `version: 5.6.0` dentro de `dist/ATLAS.yaml`.

Se compararon las 18 técnicas candidatas para los abuse cases. Conservan ID,
nombre, madurez y tácticas. Entre ellas, solo cambió el campo de descripción de
`AML.T0054 LLM Jailbreak`; la release añadió además técnicas no necesarias
para este crosswalk. La decisión versionada es utilizar `v2026.06` en
`GSL-THREAT-CROSSWALK-001` y conservar `v5.6.0` como snapshot histórico, sin
reescribir silenciosamente análisis anteriores.

La revalidación oficial mantuvo OWASP LLM 2025 y OWASP Agentic 2026 como las
ediciones publicadas usadas por el proyecto.

### NIST

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI 100-1 — DOI](https://doi.org/10.6028/NIST.AI.100-1)
- [NIST AI 600-1 — perfil GenAI](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [NIST SP 800-218A — publicación final](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [NIST SP 800-218A — DOI](https://doi.org/10.6028/NIST.SP.800-218A)
- [NIST SP 800-218, SSDF 1.1 — documento base](https://csrc.nist.gov/pubs/sp/800/218/final)

NIST indica que SP 800-218A se utiliza junto con **SP 800-218, SSDF
Version 1.1**.

## Regla de cambio

1. Los análisis del proyecto deben indicar la versión concreta utilizada.
2. Una actualización externa no cambia silenciosamente los mapeos ya
   versionados.
3. Antes de PGS-02-M07, PGS-02-M08 y el cierre PGS-07 se volverá a consultar
   el estado oficial.
4. Si aparece una edición final nueva, se registrará otra fotografía, se
   compararán los cambios relevantes y se decidirá qué mapeos repetir.
5. Mientras la revisión de AI RMF no sea final, el proyecto conserva
   **AI RMF 1.0** como baseline.

## Límites

- OWASP Top 10 y MITRE ATLAS son fuentes de identificación y análisis, no
  certificados de conformidad.
- AI RMF es un marco voluntario y adaptable.
- Este registro no demuestra que GenAI Seguro Lab implemente todavía ningún
  control de estas fuentes.
- No se han copiado los documentos al repositorio; se conservan identificadores
  y enlaces oficiales para evitar duplicar material vivo.
