# Registro formal de riesgos — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-RISK-REGISTER-001` |
| Versión | `1.1.0` |
| Fecha | 2026-07-29 |
| Estado | `ABIERTO_ALCANCE_ACTUAL` |
| Corte de las fuentes | commit `648dd9afe9ef696388257ebf8dda4b59ece1aeb5` |
| Candidato evaluado | commit `77edd64037bb0e41edffa58cae2682ba7d2694d2` |
| Evidencia final | `DAT-25`, SHA-256 `05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d` |
| Owner actual | `ACT-02` |

Este es el registro vivo de `RR-01` a `RR-06`. Parte del snapshot
[`GSL-RESIDUAL-RISK-001`](./residual-risk-and-tradeoffs.md), conserva sin
recalcular la priorización de `GSL-RISK-PRIORITY-001` y separa el tratamiento
propuesto de la decisión humana. Crear el registro no acepta, transfiere,
cierra ni reduce por sí mismo ningún riesgo.

## Estados y reglas

| Estado | Condición mínima |
|---|---|
| `ABIERTO` | Existe exposición o incertidumbre no resuelta. |
| `EN_TRATAMIENTO` | Hay una respuesta elegida por `ACT-02`, un owner, un target y trabajo autorizado en curso. |
| `PENDIENTE_VERIFICACION` | El tratamiento terminó y existe evidencia candidata por revisar. |
| `CERRADO` | Una decisión humana explícita y evidencia verificable justifican el cierre para un alcance identificado. |

Todos los tratamientos de este corte están `PROPUESTO_NO_APROBADO`. Una
referencia a una microtarea futura no la autoriza ni decide su resultado.
`PENDIENTE_HUMANA` solo puede cambiar tras una decisión explícita de `ACT-02`
registrada con fecha, alcance y evidencia. La
[RACI formal](./raci.md) define consulta, ejecución y accountability.

## Registro

<!-- formal-risk-register:start -->
| ID y casos | Riesgo y activos | Owner | Estado y evidencia | Controles existentes | Brecha o incertidumbre | Respuesta propuesta | Target | Decisión | Trigger de revisión |
|---|---|---|---|---|---|---|---|---|---|
| `RR-01` — `AC-DOS-01` | Agotamiento repetido de recursos sobre proceso y host local | `ACT-02` | `ABIERTO`; fixture `INERT` y fuera del denominador; `DAT-25` solo conserva su no ejecución | Presupuestos, checkpoints y lock advisory de `CMP-10` | Sin cuota persistente, rate limit, cancelación síncrona, aislamiento de SO ni prueba de carga | `PROPUESTO_NO_APROBADO`: diseñar una ejecución DOS separada, acotada, con parada y recuperación | `PGS-06-M07`, `PGS-07-M02` | `PENDIENTE_HUMANA` | Autorizar prueba DOS, cambiar límites, observar agotamiento o ampliar concurrencia |
| `RR-02` — `AC-DOS-02`, `AC-DOS-03` | Corpus corrupto o sobredimensionado sobre integridad y disponibilidad de carga | `ACT-02` | `ABIERTO`; dos fixtures `INERT` y fuera del denominador; sin medición final de consumo | Esquemas estrictos, procedencia, hashes y límites preventivos con fallo cerrado | La autoridad de mantenimiento puede versionar artefactos incompatibles; no se probó el límite materializado | `PROPUESTO_NO_APROBADO`: verificar procedencia y reconstrucción y ejecutar copias temporales con límites y parada | `PGS-06-M08`, `PGS-07-M01`, `PGS-07-M02` | `PENDIENTE_HUMANA` | Cambiar corpus, esquema, tamaño, procedencia o autorización de la prueba |
| `RR-03` — `AC-SC-01` | Compromiso de supply chain o abuso de mantenimiento sobre código, dependencias, corpus y evidencia | `ACT-02` | `ABIERTO`; fixture `INERT`; `DAT-25` fija hashes y no ejercita compromiso o recuperación; [`GSL-SUPPLY-CHAIN-001`](./dependency-supply-chain-register.md) inventaría el corte sin escanear advisories | Git, `uv.lock`, manifiestos y SHA-256 detectan drift cubierto | Sin firma, CI, SBOM, política de release, separación de funciones, revisión de licencias/vulnerabilidades ni revisión independiente ejercida | `PROPUESTO_NO_APROBADO`: reconstruir desde limpio y revisar independientemente un cambio y una prueba | `PGS-07-M01`, `PGS-07-M04` | `PENDIENTE_HUMANA` | Nueva dependencia, cambio de fuente, release, alerta de vulnerabilidad o asignación de `REV-01` |
| `RR-04` — `AC-TOL-05` | Aprobación sin presencia humana real sobre la creación confinada de borradores | `ACT-02` | `ABIERTO`; `DAT-25` observa rechazo y cero efecto no autorizado para la variante fijada | Identidad sintética, challenge ligado, TTL y grant de un solo uso consumido antes de I/O | No demuestra presencia, comprensión, accesibilidad ni control humano real | `PROPUESTO_NO_APROBADO`: conservar solo el flujo sintético o exigir autenticador e interfaz humana antes de ampliar capacidades | `PGS-07-M04` | `PENDIENTE_HUMANA` | Exponer `TOL-02`, añadir interfaz o autenticador, cambiar efecto o decidir equivalencia humana |
| `RR-05` — `AC-TOL-03`, `AC-TOL-04` | Bypass del host, replay o escape de filesystem sobre sandbox y archivos del usuario | `ACT-02` | `ABIERTO`; `DAT-25` completa las dos variantes fijadas sin regresión observada | Binding y consumo único, ruta validada, no-follow, modo `0600` y publicación create-only | Misma cuenta macOS, sin aislamiento de SO, prueba multiusuario ni otras carreras o rutas | `PROPUESTO_NO_APROBADO`: reconstruir, repetir pruebas autorizadas y verificar parada y recuperación antes de ampliar efectos | `PGS-06-M07`, `PGS-07-M01`, `PGS-07-M02` | `PENDIENTE_HUMANA` | Nuevo efecto, ruta, principal, usuario, host, aislamiento o fallo de recuperación |
| `RR-06` — `AC-PI-01`, `AC-PI-02`, `AC-PI-03`, `AC-JB-01`, `AC-JB-02`, `AC-EX-01`, `AC-EX-02`, `AC-EX-03`, `AC-TOL-01`, `AC-TOL-02` | Generalización no demostrada de límites de instrucciones, conocimiento, salida y autoridad | `ACT-02` | `ABIERTO`; `DAT-25` completa diez variantes del candidato determinista; `GSL-OLLAMA-001` prueba el contrato con transporte falso y un smoke end-to-end acotado tras dos fallos cerrados | Dominios de confianza, esquemas, allowlists, mínimo privilegio, política de salida, presupuestos y oráculos separados; endpoint/modelo fijos y cero retries en el opt-in | Sin prompt libre, semántica general, idiomas alternativos, ataques desconocidos ni evidencia general del comportamiento, privacidad, disponibilidad o coste real de `MOD-02` | `PROPUESTO_NO_APROBADO`: mantener Ollama experimental y producir evaluación separada antes de ampliar cualquier afirmación | `PGS-07-M02`, `PGS-07-M04`, `PGS-07-M06` | `PENDIENTE_HUMANA` | Cambiar modelo, prompt, idioma, interfaz, herramienta, proveedor, distribución o afirmación de robustez |
<!-- formal-risk-register:end -->

Los 17 abuse cases aparecen exactamente una vez en el registro. Los resultados
de `DAT-20` a `DAT-23` son históricos; `DAT-25` sigue siendo el único retest
final y no se regenera ni se reejecuta para mantener este documento.

### Extensión alojada

`GSL-OLLAMA-001` materializa el trigger de proveedor/red sin cerrar ni aceptar
ningún riesgo. El egress se limita a datos sintéticos, la credencial no se
proyecta y los errores son saneados. Un smoke instrumentado completó el flujo
de `INC-BEN-001` tras dos fallos cerrados; permanecen desconocidos el
comportamiento general del modelo alojado, retención y residencia del
proveedor, coste, disponibilidad y respuesta ante ataques. Cualquier nueva
prueba real requiere decisión y evidencia nuevas, nunca una reinterpretación
de `DAT-25`.
La [política de cambios de modelo](./model-change-reevaluation-policy.md)
mantiene el paquete de reevaluación aplicable.

### Extensión pública estática

`GSL-PUBLIC-STATIC-001` materializa la distribución/supply chain de `RR-03` y
el riesgo de representación de `RR-06`; no crea otro registro. La demo no
ejecuta modelos o herramientas y se etiqueta como snapshot precomputado.
Persisten la posible manipulación u obsolescencia del artefacto, su confusión
con una ejecución y las incertidumbres operativas del proveedor. La URL,
cabeceras y ausencia temprana de errores o `5xx` se verificaron, pero no
demuestran disponibilidad futura, residencia, retención o controles internos.
La regeneración reproducible y las cabeceras no aceptan ni cierran esos riesgos
y no reinterpretan `DAT-25`.

## Cola de decisiones humanas

Las opciones disponibles son mitigar, evitar o no ampliar, transferir cuando
exista un tercero real, aceptar dentro de un alcance y plazo explícitos, o
diferir y escalar. No hay una opción seleccionada en este corte.

<!-- risk-decision-queue:start -->
| ID | Riesgo | Pregunta que debe resolver `ACT-02` | Opciones no seleccionadas | Evidencia mínima previa | Estado |
|---|---|---|---|---|---|
| `RDEC-01` | `RR-01` | ¿Se autoriza una prueba DOS acotada y qué indisponibilidad local sería tolerable? | mitigar; evitar o no ampliar; aceptar; diferir y escalar | topes, parada, recuperación y observación de consumo | `PENDIENTE_HUMANA` |
| `RDEC-02` | `RR-02` | ¿Qué condiciones de integridad, tamaño y recuperación debe cumplir un corpus futuro? | mitigar; evitar o no ampliar; aceptar; diferir y escalar | procedencia, hash, reconstrucción y prueba temporal autorizada | `PENDIENTE_HUMANA` |
| `RDEC-03` | `RR-03` | ¿Qué controles de procedencia y revisión serán obligatorios antes del siguiente artefacto? | mitigar; evitar o no ampliar; transferir si aparece un tercero; aceptar; diferir y escalar | inventario, vulnerabilidades, build limpio y revisión independiente | `PENDIENTE_HUMANA` |
| `RDEC-04` | `RR-04` | ¿El flujo seguirá siendo solo sintético o deberá demostrar presencia humana antes de ampliarse? | mitigar; evitar o no ampliar; aceptar solo el laboratorio sintético; diferir y escalar | diseño de interfaz, autenticación, revocación y prueba con persona | `PENDIENTE_HUMANA` |
| `RDEC-05` | `RR-05` | ¿El confinamiento lógico del host basta para el siguiente alcance autorizado? | mitigar; evitar o no ampliar; aceptar alcance local; diferir y escalar | reconstrucción, pruebas de escape, parada y recuperación | `PENDIENTE_HUMANA` |
| `RDEC-06` | `RR-06` | ¿Qué cobertura adicional se exige antes de cambiar modelo, interfaz o afirmación de robustez? | mitigar; evitar o no ampliar; transferir si aparece proveedor; aceptar alcance cerrado; diferir y escalar | corpus actualizado, evaluación repetible y revisión independiente | `PENDIENTE_HUMANA` |
<!-- risk-decision-queue:end -->

## Cadencia y triggers

Revisar el registro al completar un target, observar un incidente, cambiar un
control o evidencia, activar un trigger de `GSL-AIA-001` o `GSL-ADR-001`,
recibir una vulnerabilidad de supply chain o incorporar un modelo, dato,
interfaz, efecto, persona, proveedor o despliegue. La revisión puede mantener
el riesgo abierto; no equivale a aceptar o cerrar.

`PGS-06-M04` podrá añadir correspondencias de obligación, guía y decisión
voluntaria, pero no debe convertir por sí misma ninguna respuesta propuesta en
una decisión.
