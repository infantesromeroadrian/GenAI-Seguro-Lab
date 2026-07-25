# Crosswalk de amenazas

## Ficha del crosswalk

| Campo | Valor |
|---|---|
| Identificador | `GSL-THREAT-CROSSWALK-001` |
| Versión | `1.0.1` |
| Fecha de corte | 2026-07-25 |
| Estado de código observado | commit `8e575eae14b8dffd1a7ff4922fa9b83841c87f79` |
| Catálogo de origen | [`GSL-ABUSE-CASES-001`](./abuse-cases.md) |
| Priorización de origen | [`GSL-RISK-PRIORITY-001`](./risk-prioritization.md) |
| Baseline de marcos | [Versiones y fuentes fijadas](./framework-versions.md) |
| Alcance | 17 abuse cases del sistema local, determinista y sintético actual |

Este documento relaciona los abuse cases propios con taxonomías externas. No
convierte una categoría en una vulnerabilidad demostrada, no acredita
conformidad y no implica que el laboratorio sea un agente autónomo.

## Fuentes y versiones

| Fuente | Edición usada |
|---|---|
| OWASP Top 10 for LLM Applications | Version 2025, documento v2.0 del 18-11-2024 |
| OWASP Top 10 for Agentic Applications | Version 2026, documento de diciembre de 2025 |
| MITRE ATLAS data | release `v2026.06`, commit `651dad90d3c007e797c89356fa1f4d8732f90c8d`; `ATLAS.yaml` declara `version: 5.6.0` |

La consulta oficial se repitió el 25 de julio de 2026. OWASP mantiene las
ediciones anteriores como Top 10 publicados. MITRE había publicado
`v2026.06` después del snapshot inicial `v5.6.0`; por ello este crosswalk usa
la release más reciente y conserva el detalle de la comparación en
[`framework-versions.md`](./framework-versions.md).

## Regla de correspondencia

| Marca | Significado |
|---|---|
| `D` | Correspondencia directa: el objetivo y el mecanismo principal del caso encajan en la definición |
| `P` | Correspondencia parcial: comparte un mecanismo, impacto o superficie, pero la categoría no representa el caso completo |
| `—` | No existe una equivalencia suficientemente específica en esa edición |

Una misma fila puede incluir más de una categoría cuando describen dimensiones
distintas. El mapeo no cambia automáticamente `I`, `L`, `K`, la puntuación o la
prioridad de `GSL-RISK-PRIORITY-001`.

## Identificadores OWASP utilizados

### LLM Applications 2025

| ID | Nombre oficial |
|---|---|
| `LLM01:2025` | Prompt Injection |
| `LLM02:2025` | Sensitive Information Disclosure |
| `LLM03:2025` | Supply Chain |
| `LLM04:2025` | Data and Model Poisoning |
| `LLM05:2025` | Improper Output Handling |
| `LLM06:2025` | Excessive Agency |
| `LLM07:2025` | System Prompt Leakage |
| `LLM09:2025` | Misinformation |
| `LLM10:2025` | Unbounded Consumption |

`LLM08:2025 Vector and Embedding Weaknesses` no se utiliza: `TOL-01` recupera
documentos por ID exacto en memoria y no implementa vectores ni embeddings.

### Agentic Applications 2026

| ID | Nombre oficial |
|---|---|
| `ASI01` | Agent Goal Hijack |
| `ASI02` | Tool Misuse and Exploitation |
| `ASI03` | Identity and Privilege Abuse |
| `ASI04` | Agentic Supply Chain Vulnerabilities |
| `ASI05` | Unexpected Code Execution (RCE) |
| `ASI06` | Memory & Context Poisoning |
| `ASI08` | Cascading Failures |
| `ASI09` | Human-Agent Trust Exploitation |

Estas referencias describen analogías de riesgo en el ciclo de herramientas.
No afirman que `MOD-01` planifique autónomamente, posea identidad o pueda
ejecutar una acción por sí mismo.

## Técnicas MITRE ATLAS utilizadas

Los identificadores y nombres se verificaron en
[`ATLAS.yaml` de `v2026.06`](https://raw.githubusercontent.com/mitre-atlas/atlas-data/v2026.06/dist/ATLAS.yaml).

| ID | Nombre oficial |
|---|---|
| `AML.T0051.000` | Direct |
| `AML.T0051.001` | Indirect |
| `AML.T0070` | RAG Poisoning |
| `AML.T0054` | LLM Jailbreak |
| `AML.T0053` | AI Agent Tool Invocation |
| `AML.T0034.002` | Agentic Resource Consumption |
| `AML.T0085.001` | AI Agent Tools |
| `AML.T0036` | Data from Information Repositories |
| `AML.T0057` | LLM Data Leakage |
| `AML.T0056` | Extract LLM System Prompt |
| `AML.T0037` | Data from Local System |
| `AML.T0034.000` | Excessive Queries |
| `AML.T0029` | Denial of AI Service |
| `AML.T0059` | Erode Dataset Integrity |
| `AML.T0034.001` | Resource-Intensive Queries |
| `AML.T0081` | Modify AI Agent Configuration |
| `AML.T0010.001` | AI Software |
| `AML.T0010.002` | Data |

## Crosswalk por abuse case

| Caso | OWASP LLM 2025 | OWASP Agentic 2026 | MITRE ATLAS `v2026.06` | Justificación acotada |
|---|---|---|---|---|
| `AC-PI-01` | `D LLM01:2025` | `P ASI01` | `D AML.T0051.000` | El objetivo es una inyección directa, aunque la CLI actual no ofrece esa entrada ni un comportamiento agentic |
| `AC-PI-02` | `D LLM01:2025` | `D ASI01` | `D AML.T0051.001` | Instrucciones almacenadas en el incidente intentarían redirigir la respuesta y el ciclo |
| `AC-PI-03` | `D LLM01:2025` | `D ASI01`; `P ASI06` | `D AML.T0051.001`; `P AML.T0070` | El documento recuperado transporta la inyección; `RAG Poisoning` es parcial porque no existen vectores ni una base RAG |
| `AC-JB-01` | `D LLM01:2025`; `P LLM09:2025` | `D ASI01`; `P ASI09` | `D AML.T0054` | Busca eludir límites y producir afirmaciones falsas o prohibidas |
| `AC-JB-02` | `D LLM06:2025`; `P LLM10:2025` | `D ASI02`; `P ASI08` | `D AML.T0053`; `P AML.T0034.002` | Pretende ampliar herramientas y prolongar el ciclo más allá de la terminación autorizada |
| `AC-EX-01` | `D LLM02:2025`; `P LLM06:2025` | `D ASI02`; `P ASI03` | `D AML.T0085.001` | Abusa de la herramienta de conocimiento para leer un objeto fuera de la allowlist del incidente |
| `AC-EX-02` | `D LLM02:2025` | `P ASI02` | `D AML.T0036` | La enumeración busca obtener datos de un repositorio mediante una capacidad interna |
| `AC-EX-03` | `D LLM02:2025`; `D LLM07:2025`; `P LLM05:2025` | `—` | `D AML.T0057`; `D AML.T0056`; `P AML.T0037` | Cubre fuga por salida o error, incluido prompt de sistema, rutas y datos locales; Agentic 2026 no ofrece una categoría específica equivalente |
| `AC-TOL-01` | `D LLM06:2025` | `D ASI02`; `P ASI05` | `D AML.T0053` | Intenta convertir una propuesta en una herramienta no autorizada; RCE solo describe parcialmente el objetivo de shell |
| `AC-TOL-02` | `D LLM06:2025`; `P LLM10:2025` | `D ASI02`; `P ASI08` | `D AML.T0053`; `P AML.T0034.002` | Múltiples solicitudes o recursión amplían agencia y consumo, aunque no existe efecto persistente actual |
| `AC-TOL-03` | `D LLM06:2025` | `D ASI03` | `—` | Autoconsentimiento, huella alterada y replay son fallos de autorización; ATLAS no contiene una técnica específica para este consentimiento |
| `AC-TOL-04` | `P LLM06:2025` | `D ASI02` | `P AML.T0053` | Traversal, symlink y overwrite son abuso de una herramienta; las categorías LLM y ATLAS son más generales que el fallo de filesystem |
| `AC-TOL-05` | `D LLM06:2025` | `D ASI03`; `P ASI09` | `P AML.T0053` | El sistema confía en un literal de confirmación sin autenticar identidad; ATLAS solo representa de forma genérica la invocación |
| `AC-DOS-01` | `D LLM10:2025` | `—` | `D AML.T0034.000`; `P AML.T0029` | Muchas ejecuciones CLI equivalen a consultas excesivas sobre un proceso local, no a una cascada agentic |
| `AC-DOS-02` | `P LLM04:2025` | `P ASI06` | `D AML.T0059` | La corrupción del corpus erosiona su integridad y disponibilidad, pero no envenena datos de entrenamiento |
| `AC-DOS-03` | `D LLM10:2025` | `—` | `D AML.T0029`; `P AML.T0034.001` | Un corpus válido sobredimensionado consume recursos al cargar y recorrer el proceso local |
| `AC-SC-01` | `D LLM03:2025`; `P LLM04:2025` | `D ASI04`; `P ASI06` | `P AML.T0081`; `P AML.T0010.001`; `P AML.T0010.002` | El caso mezcla código, dependencias, configuración, corpus y evidencia; ATLAS cubre sus partes, no la autoridad de mantenimiento completa |

## Cobertura resultante

| Fuente | Directa | Solo parcial | Sin mapeo |
|---|---:|---:|---:|
| OWASP LLM 2025 | 15 | 2 | 0 |
| OWASP Agentic 2026 | 11 | 3 | 3 |
| MITRE ATLAS `v2026.06` | 13 | 3 | 1 |

Cada fila se contabiliza por su mejor relación en la fuente correspondiente.
Las relaciones adicionales no aumentan el número de casos cubiertos.

## Gaps y decisiones explícitas

- `AC-TOL-03` conserva un gap en ATLAS: usar `AI Agent Tool Invocation` como
  equivalencia de consentimiento, huella o replay ocultaría el problema real.
- `AC-TOL-05` solo recibe un mapeo ATLAS parcial por la misma razón.
- `AC-EX-03`, `AC-DOS-01` y `AC-DOS-03` no se fuerzan dentro del Top 10
  Agentic cuando el caso no depende de autonomía, delegación o cascadas.
- `AC-SC-01` es compuesto y deberá dividirse en pruebas distintas antes de
  afirmar cobertura empírica.
- `AML.T0070 RAG Poisoning` es parcial para `AC-PI-03`: el laboratorio posee
  recuperación aumentada por documentos, pero no una base vectorial.
- Ninguna relación demuestra que el control actual funcione; esa evidencia
  pertenece al futuro harness.

## Fuentes oficiales

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [PDF oficial OWASP LLM 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MITRE ATLAS data `v2026.06`](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.06)
- [`ATLAS.yaml` fijado](https://raw.githubusercontent.com/mitre-atlas/atlas-data/v2026.06/dist/ATLAS.yaml)

## Siguiente tratamiento

[`GSL-NIST-CONTROLS-001`](./control-responsibility-mapping.md) asigna
responsables y controles previstos a los 17 casos y los relaciona con NIST AI
RMF 1.0 y NIST SP 800-218A. Este crosswalk no altera las prioridades actuales
y debe revisarse si cambia un abuse case, la arquitectura o alguna edición
fijada.
