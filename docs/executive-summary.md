# Resumen ejecutivo

## Qué es

GenAI Seguro Lab es un proyecto educativo y de portfolio que demuestra, de
forma reproducible, cómo diseñar y evaluar controles de seguridad para una
aplicación con comportamiento parecido al de un sistema GenAI con
herramientas. Funciona localmente con datos ficticios y un doble determinista;
no conecta un modelo de IA real ni servicios externos.

## Qué aporta

- Un caso de estudio público con arquitectura, amenazas, controles, pruebas,
  métricas, riesgos y decisiones enlazados.
- Una comparación repetible entre una versión vulnerable y otra endurecida.
- Un entorno sin datos reales, gasto cloud o efectos fuera del sandbox.
- Documentación de operación, incidentes, recuperación, dependencias y cambios.

En el alcance probado, el éxito adversario observado bajó de 1 de 14 casos a
0 de 14 y las operaciones no autorizadas de 1 a 0. Los 12 casos benignos
terminaron sin falsos rechazos y conservaron las 84 reglas de resultado fijadas
antes del retest. Estos números describen únicamente el candidato, los datos y
la rúbrica versionados; no predicen el comportamiento de cualquier IA real.

## Estado verificable

La [matriz final](./final-traceability-matrix.md) cubre los 25 requisitos:
22 están demostrados de forma total o acotada, 2 son parciales y 1 no está
demostrado.

El requisito no demostrado es la reproducción por una persona independiente.
La revisión humana se omitió por decisión expresa; `REV-01` sigue sin asignar.
Esto no es una aprobación, exención ni aceptación de riesgo.

## Riesgos que siguen abiertos

- agotamiento y límites no probados mediante cargas DOS;
- integridad de corpus futuros y supply chain;
- ausencia de firma, CI y revisión independiente ejercida;
- aprobación sintética sin demostrar presencia humana real;
- confinamiento lógico sin aislamiento del sistema operativo;
- generalización no demostrada a prompts libres, idiomas, ataques desconocidos
  o modelos reales.

Los seis riesgos conservan una decisión humana pendiente. `SEC-1` no debe
declararse superado mientras falte su base global y la reproducción
independiente exigida.

## Uso correcto

Puede utilizarse para aprendizaje, demostraciones técnicas, entrevistas,
revisión de código y reproducción de los casos autorizados. No debe presentarse
como producto listo para producción, certificación, cumplimiento normativo
integral o prueba de que un LLM real es seguro.
