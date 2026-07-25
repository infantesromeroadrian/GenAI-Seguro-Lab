# Documentación

Este directorio contiene la documentación estable que describe las fuentes,
arquitectura, threat model, decisiones, riesgos, fichas y runbooks del sistema
real.

## Inventario actual

- [Baseline de marcos y fuentes](./framework-versions.md): versiones oficiales
  fijadas para OWASP, MITRE ATLAS y NIST, con fecha de consulta y regla de
  actualización.
- [Inventario del sistema actual](./system-inventory.md): actores, datos,
  componentes, modelo, herramientas, identidades, dependencias,
  infraestructura, integraciones y ausencias verificadas.
- [Mapa C4 de arquitectura](../architecture/manifest.json): contexto,
  contenedores locales, componentes, flujo de datos y seis trust boundaries
  sustentados por el inventario.
- [Matriz de autoridad y consecuencias](./authority-matrix.md): cadenas
  verificadas entre actores, modelo, identidades, datos, herramientas, acciones
  y efectos máximos actuales, incluidas las rutas que no existen.
- [Catálogo de abuse cases](./abuse-cases.md): 17 escenarios de prompt
  injection, jailbreak, exfiltración, abuso de herramientas, disponibilidad y
  supply chain, separados por alcanzabilidad actual.
- [Priorización de abuse cases](./risk-prioritization.md): método reproducible
  que combina impacto, probabilidad condicionada y capacidad real, con los 17
  casos ordenados como backlog de pruebas.
- [Crosswalk de amenazas](./threat-crosswalk.md): correspondencias directas,
  parciales y gaps explícitos entre los 17 casos, OWASP LLM 2025, OWASP
  Agentic 2026 y MITRE ATLAS `v2026.06`.
- [Mapa de responsabilidades y controles
  NIST](./control-responsibility-mapping.md): propietarios, estados, evidencia
  y correspondencias seleccionadas con NIST AI RMF 1.0 y NIST SP 800-218A,
  sin atribuir conformidad ni eficacia no demostrada.
- [Rules of Engagement](./rules-of-engagement.md): autorización por ejecución,
  targets, acciones, datos, presupuestos, evidencias y condiciones de parada
  para los 17 abuse cases del laboratorio propio.
- [Corpus adversario sintético](../data/adversarial/README.md): 18 entradas y
  18 oráculos separados para los 17 casos y seis familias; 14 fixtures están
  conectadas al harness interno, evaluadas canónicamente y 4 permanecen
  inertes.
- [Baseline adversaria canónica](../evaluations/adversarial-baseline-v1/README.md):
  candidato exacto, reproducción, 13 `PASS`, 1 `RESIDUAL`, métricas, artefactos
  saneados y límites de interpretación.
- [Hallazgos de la baseline adversaria](./adversarial-baseline-findings.md):
  uso actual del laboratorio, impacto de las variantes observadas,
  reproducción, residual conocido y límites de la evidencia.
- [Política de validación y allowlists](./validation-policy.md): sobres
  estrictos de entrada y salida, grants de ejecución, comportamiento de fallo
  cerrado y límites de PGS-04-M02/M03.
- [Política de mínimo privilegio](./least-privilege-policy.md): principales y
  scopes lógicos, proyección de conocimiento, grants de herramienta y efecto,
  entorno mínimo de subproceso y límites de PGS-04-M03.

La documentación se añade junto al hito técnico correspondiente y debe
distinguir el estado implementado de las decisiones o trabajos futuros.
