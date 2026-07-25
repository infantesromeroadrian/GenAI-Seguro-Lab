# Priorización de abuse cases

## Ficha de la priorización

| Campo | Valor |
|---|---|
| Identificador | `GSL-RISK-PRIORITY-001` |
| Versión | `1.3.0` |
| Fecha de corte | 2026-07-25 |
| Baseline de código | commit `3c4657efbc7dc92b232b83f3185d27968c2ba78b` + candidato PGS-03-M03 |
| Catálogo de origen | [`GSL-ABUSE-CASES-001`](./abuse-cases.md) |
| Autoridad de origen | [`GSL-AUTH-MATRIX-001`](./authority-matrix.md) |
| Crosswalk actual | [`GSL-THREAT-CROSSWALK-001`](./threat-crosswalk.md) |
| Alcance | sistema local sintético, incluida la configuración aislada `CMP-06` |

Esta priorización ordena el backlog de pruebas del laboratorio. No es una
clasificación CVSS, no estima la frecuencia de incidentes reales y no afirma
que un ataque haya sido reproducido. Cada caso se valora únicamente contra las
capacidades presentes en el checkout observado.

## Método

La puntuación utiliza tres ejes separados:

```text
S = (I + 1) × L × K
```

- `I` representa el impacto máximo que los componentes actuales podrían
  producir si el caso tuviera éxito.
- `L` representa la probabilidad condicionada de éxito una vez satisfecha la
  precondición del caso.
- `K` representa la capacidad real de alcanzar el camino en la interfaz
  actual.

El término «probabilidad» no expresa un porcentaje ni una previsión de
incidentes. Permite distinguir un residual aceptado actualmente de un
comportamiento que los controles ya rechazan.

### Impacto `I`

La escala reutiliza las consecuencias de `GSL-AUTH-MATRIX-001`.

| Valor | Consecuencia actual usada para puntuar |
|---:|---|
| `I0` | `C0`: datos tipados en memoria, sin efecto persistente directo |
| `I1` | `C1`: lectura o salida de datos sintéticos, o disponibilidad del proceso local |
| `I2` | `C2`: creación confinada de un Markdown sintético |
| `I3` | `C3`: mutación de código, corpus, dependencias o evidencia por mantenimiento |

No se puntúa el efecto imaginado por el adversario. Por ejemplo, pedir una
shell inexistente conserva `I0`; no se le atribuye ejecución arbitraria.

### Probabilidad condicionada `L`

| Valor | Criterio observable |
|---:|---|
| `L1` | Éxito improbable en el estado actual: el control está verificado o el adaptador determinista no puede interpretar la entrada |
| `L2` | Éxito plausible: falta cobertura explícita, existe un límite parcial o el resultado no está demostrado de extremo a extremo |
| `L3` | Éxito probable tras cumplir la precondición: el comportamiento se acepta actualmente o no existe el límite preventivo relevante |

`L3` no implica que un tercero pueda entrar en el sistema. La accesibilidad se
mantiene separada en `K`.

### Capacidad real `K`

| Valor | Estado de alcance del catálogo |
|---:|---|
| `K0` | `SIN-RUTA`: la entrada o capacidad no existe |
| `K1` | `MANTENIMIENTO`: exige autoridad sobre checkout, corpus, manifiesto o evidencia |
| `K2` | `INTERNO`: requiere una llamada Python directa o un doble de modelo |
| `K3` | `CLI`: puede intentarse mediante `main.py` |

Un caso `K0` siempre queda en `PR-0`, con puntuación cero, aunque su objetivo
adversario pudiera ser grave en otro sistema.

### Bandas de prioridad

| Prioridad | Puntuación | Tratamiento |
|---|---:|---|
| `PR-1` | 18–36 | Probar primero después de aprobar las Rules of Engagement |
| `PR-2` | 8–17 | Incorporar al siguiente bloque del harness |
| `PR-3` | 1–7 | Mantener como regresión o activar cuando exista el corpus o la ruta necesaria |
| `PR-0` | 0 por `K0` | Esperar hasta que una revisión de arquitectura cree una ruta real |

En empates se ordena primero un residual aceptado, después una superficie
ordinaria, luego una frontera interna y finalmente una capacidad exclusiva de
mantenimiento. El orden es un backlog técnico, no una etiqueta universal de
severidad.

## Registro priorizado

| Orden | Caso | `I` | `L` | `K` | `S` | Prioridad | Fundamento actual |
|---:|---|---:|---:|---:|---:|---|---|
| 1 | `AC-TOL-05` | 2 | 3 | 2 | 18 | `PR-1` | `DraftWriterTool` acepta hoy una confirmación exacta que no autentica a la persona y puede crear un Markdown confinado |
| 2 | `AC-DOS-01` | 1 | 3 | 3 | 18 | `PR-1` | La repetición de procesos está expuesta por CLI y no existe cuota, rate limit ni control de concurrencia |
| 3 | `AC-EX-03` | 1 | 2 | 2 | 8 | `PR-2` | Falta una prueba con marcador señuelo que cubra salida, errores, rutas y traceback de extremo a extremo |
| 4 | `AC-EX-02` | 1 | 2 | 2 | 8 | `PR-2` | La ausencia de API de listado reduce el alcance, pero falta el caso explícito para IDs desconocidos y cero divulgación |
| 5 | `AC-SC-01` | 3 | 2 | 1 | 8 | `PR-2` | Posee el mayor impacto, aunque exige autoridad de mantenimiento; no hay remoto, firma, CI ni revisión independiente |
| 6 | `AC-TOL-03` | 2 | 1 | 2 | 6 | `PR-3` | Huella, campos extra y replay ya tienen cobertura unitaria; el efecto potencial queda confinado a un borrador |
| 7 | `AC-TOL-04` | 2 | 1 | 2 | 6 | `PR-3` | Traversal, symlinks y overwrite ya se rechazan mediante validación de ruta y creación exclusiva |
| 8 | `AC-DOS-02` | 1 | 3 | 1 | 6 | `PR-3` | Un mantenedor puede inutilizar la carga al corromper los datos, pero los controles deben fallar cerrado |
| 9 | `AC-DOS-03` | 1 | 3 | 1 | 6 | `PR-3` | No hay límite global de tamaño, pero solo mantenimiento puede versionar un corpus grande válido |
| 10 | `AC-EX-01` | 1 | 1 | 2 | 4 | `PR-3` | La allowlist por incidente ya rechaza referencias cruzadas en pruebas unitarias |
| 11 | `AC-JB-02` | 0 | 2 | 2 | 4 | `PR-3` | Faltan variantes de múltiples requests y segundo turno no final, sin efecto persistente actual |
| 12 | `AC-TOL-02` | 0 | 2 | 2 | 4 | `PR-3` | Permanecen gaps de cardinalidad y terminación, pero la ruta actual no concede una herramienta adicional |
| 13 | `AC-TOL-01` | 0 | 1 | 2 | 2 | `PR-3` | La allowlist admite solo `knowledge_search`, las pruebas lo cubren y no existe ejecutor de shell |
| 14 | `AC-PI-02` | 1 | 1 | 1 | 2 | `PR-3` | Exige versionar corpus y manifiesto; el adaptador determinista no interpreta las instrucciones insertadas |
| 15 | `AC-PI-03` | 1 | 1 | 1 | 2 | `PR-3` | La recuperación puede transportar texto, pero el modelo actual no lo obedece y el cambio exige mantenimiento |
| 16 | `AC-JB-01` | 1 | 1 | 1 | 2 | `PR-3` | El contenido debe entrar mediante mantenimiento y la respuesta determinista conserva las afirmaciones permitidas |
| 17 | `AC-PI-01` | 0 | 1 | 0 | 0 | `PR-0` | La CLI no acepta prompt libre; `argparse` o la selección de ID detienen el intento antes del modelo |

Distribución: 2 casos `PR-1`, 3 `PR-2`, 11 `PR-3` y 1 `PR-0`.

## Recálculo de PGS-03-M02

La creación de `GSL-PROFILE-VULNERABLE-001` activó la revisión prevista. Las
puntuaciones no cambian todavía:

- `CMP-06` construye una petición débil marcada, pero no llama a `MOD-01`;
- anunciar `knowledge_search` y `draft_create` no crea una ruta de ejecución;
- en el corte PGS-03-M02 no existían corpus adversario, dispatcher, run
  manifest o evidencia de ataque;
- la CLI sigue aceptando únicamente `analyze` y `baseline`;
- el efecto máximo nuevo es `C0`, por lo que no cambia `I`, `L` o `K` de
  ninguno de los 17 casos.

El cambio es arquitectónico y observable, pero no se presenta como una
vulnerabilidad explotada. PGS-03-M03 produce el recálculo siguiente; otra
revisión será necesaria cuando el harness conecte una entrada adversaria a un
target y compare su resultado con el oráculo.

## Recálculo de PGS-03-M03

La incorporación de `GSL-ADVERSARIAL-CORPUS-001` vuelve a activar la revisión,
pero tampoco modifica las puntuaciones:

- `DAT-07` y `DAT-08` son fixtures y oráculos sintéticos inertes;
- `DAT-09` fija 18 entradas, 17 abuse cases, seis familias, cero conexiones y
  cero ejecuciones;
- `AUTH-11` termina al devolver un bundle tipado en memoria;
- no existe arista desde ese bundle hacia `CMP-06`, `MOD-01`, `TOL-01`,
  `TOL-02` o la CLI;
- `AC-DOS-03` continúa `NO AUTORIZADO` y solo se representa mediante un
  descriptor no materializado.

Preparar la entrada y el resultado esperado no cambia `I`, `L` o `K`. El
recalculo siguiente se producirá cuando una microtarea posterior incorpore un
harness o dispatcher capaz de entregar una fixture a un target.

## Backlog inicial de pruebas

Los cinco primeros casos forman el backlog prioritario actual:

1. demostrar de forma controlada el residual `AC-TOL-05` y comprobar que solo
   aparece un Markdown dentro de un sandbox temporal;
2. medir `AC-DOS-01` con límites estrictos de tiempo, memoria, procesos y una
   condición de parada;
3. usar marcadores exclusivamente sintéticos para probar que `AC-EX-03` no
   filtra corpus, peticiones, rutas o traceback;
4. comprobar en `AC-EX-02` que un ID desconocido no enumera ni divulga
   documentos;
5. dividir `AC-SC-01` en cambios controlados de código, lock y evidencia sobre
   copias temporales, sin alterar la baseline autoritativa.

La prioridad no autoriza su ejecución. `GSL-ROE-001` ya fija el marco y el
corpus adversario está preparado, pero el harness y una petición vigente siguen
siendo precondiciones. En particular, `AC-DOS-01` se ejecutará solo con sus
topes conservadores y una parada segura.

## Decisiones derivadas

- `AC-TOL-05` es el primer residual funcional porque ya existe una ruta interna
  aceptada y un efecto `C2`, aunque no esté expuesta por CLI.
- `AC-DOS-01` comparte la puntuación más alta por ser la única superficie
  adversaria ordinaria, pero su impacto se limita al host y proceso locales.
- `AC-SC-01` no se confunde con comportamiento del modelo: su impacto `C3`
  pertenece a la cuenta de mantenimiento.
- Los casos de prompt injection y jailbreak no encabezan el backlog porque el
  sistema no tiene prompt libre ni modelo generativo real. El recálculo de
  PGS-03-M02 conserva sus valores: construir una petición vulnerable sin
  ejecutarla no aumenta su alcanzabilidad.
- La priorización no altera los gaps de evidencia del catálogo ni permite
  afirmar que un control es eficaz antes del futuro harness.

## Disparadores de recálculo

Debe emitirse una nueva versión de esta priorización cuando cambie cualquiera
de estos supuestos:

- incorporación de un modelo o proveedor real;
- entrada libre, API, UI, red o usuario remoto;
- conexión de `TOL-02` al flujo o a la CLI;
- conexión de `CMP-06` a un adaptador, dispatcher o harness ejecutable;
- incorporación de nuevas herramientas, shell, secretos o datos sensibles;
- ejecución desatendida, contenedores, cloud o identidad de servicio;
- controles que cambien la probabilidad condicionada;
- evidencia del harness que contradiga `L1`, `L2` o `L3`.

## Cobertura y siguiente tratamiento

Los 17 abuse cases aparecen exactamente una vez y conservan la alcanzabilidad
de `GSL-ABUSE-CASES-001`. El perfil vulnerable está construido y aislado, pero
ninguna de las 18 fixtures se ha ejecutado ni se ha habilitado una ruta de
ejecución.

[`GSL-THREAT-CROSSWALK-001`](./threat-crosswalk.md) relaciona los casos con
OWASP y MITRE ATLAS sin cambiar sus puntuaciones.
[`GSL-NIST-CONTROLS-001`](./control-responsibility-mapping.md) asigna
responsables y controles previstos sin modificar el orden. Cualquier
corrección de alcance deberá quedar justificada en una nueva versión de este
registro.
