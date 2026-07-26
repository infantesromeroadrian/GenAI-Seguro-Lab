# Política de seguridad de salida

- **ID:** `GSL-OUTPUT-POLICY-001`
- **Versión:** 1.0.0
- **Fecha:** 2026-07-26
- **Microtarea:** PGS-04-M05
- **Ámbito:** resumen final y borradores sintéticos

## Objetivo

Impedir que una respuesta estructuralmente válida salga del control de la
aplicación o se apruebe para persistencia sin una decisión semántica explícita.
La política pertenece a la aplicación: el modelo no puede configurarla,
omitirse ni emitir por sí mismo un resultado aprobado.

La precedencia es:

`reject > redact > allow`

Primero se evalúan todas las reglas de rechazo sobre el original. Solo cuando
ninguna coincide se aplican las redacciones deterministas y se vuelve a
validar el resultado. Un error de política, un canal desconocido o un sello no
emitido por la misma instancia falla cerrado.

## Canales y decisiones

| Canal | Uso | Decisiones |
|---|---|---|
| `final_summary` | Resumen devuelto por `BenignAnalysisFlow` | `allow`, `redact` o rechazo |
| `draft_title` | Título previo a la propuesta de borrador | `allow`, `redact` o rechazo |
| `draft_body` | Cuerpo previo a la propuesta de borrador | `allow`, `redact` o rechazo |

`PolicyCheckedText` es un sello opaco ligado a una instancia y a un canal.
Solo la misma `OutputPolicy` puede desenvolverlo. Su representación y los
errores no incluyen el texto examinado.

## Reglas implementadas

| Categoría | Acción | Alcance exacto |
|---|---|---|
| Literal protegido | Rechazo | Canario sintético registrado por el laboratorio |
| Material de credencial de alta señal | Rechazo | Cabecera Bearer, inicio de clave privada o asignación explícita de credencial |
| Afirmación incompatible | Rechazo | Frases explícitas en español o inglés que afirman compromiso, aislamiento o revocación ya realizados |
| Control oculto o bidireccional | Rechazo | Controles Unicode y caracteres invisibles configurados |
| Contenido activo de borrador | Rechazo | URL externa, enlace o embed externo, HTML activo y esquema `javascript:`; solo en título o cuerpo de borrador |
| Dirección de correo | Redacción | Sustitución fija por `[REDACTED_EMAIL]` |
| Ruta local absoluta | Redacción | Sustitución fija por `[REDACTED_LOCAL_PATH]` |

Las redacciones conservan únicamente categoría y número de coincidencias. No
conservan los valores encontrados.

PGS-04-M07 registra únicamente que hubo una decisión o intervención mediante
`GSL-SECURITY-EVENTS-001`. El esquema de eventos no reutiliza esta política
como sanitizador genérico: impide por contrato que exista un campo para el
texto examinado o sus valores.

## Inserción en los flujos

### Resultado ordinario

```text
ModelResponse bruto
→ BenignFinalOutput
→ consistencia de incidente, conocimiento y efectos
→ CMP-09 OutputPolicy
→ resumen permitido o redactado
→ proyección segura de invocaciones
→ JSON de la CLI
```

`BenignAnalysisResult.invocations` ya no contiene la petición ni la respuesta
bruta del modelo. Solo conserva descriptor, ID y huella de petición,
`finish_reason` y número de solicitudes de herramienta.

### Borrador

```text
argumentos tipados y referencias autorizadas
→ CMP-09 sobre título y cuerpo
→ propuesta saneada y huella
→ challenge, aprobación y grant
→ escritura exacta del contenido aprobado
```

La política actúa antes de calcular la huella y antes de solicitar una
aprobación. Por tanto, lo aprobado es exactamente lo que `TOL-02` puede
escribir; `create()` no transforma el contenido después.

## Evidencia ejecutable

- `tests/test_output_policy.py`: precedencia, redacción, idempotencia,
  opacidad, binding y rechazo genérico.
- `tests/test_benign_flow.py`: salida segura, evidencia sin valores y ausencia
  de respuesta bruta en las invocaciones.
- `tests/test_validation_policy.py`: consistencia estructural previa y rechazo
  semántico de una salida válida por esquema.
- `tests/test_local_tools.py`: redacción anterior a huella y aprobación,
  persistencia exacta y rechazo antes de challenge o I/O.
- `evaluations/benign-baseline-v1.json`: debe permanecer idéntica byte a byte.

## Límites

Esta es una política léxica y deliberadamente acotada. No acredita detección
universal de secretos, PII, desinformación o contenido dañino. En particular,
no cubre secretos codificados u ofuscados, homoglifos, paráfrasis, todos los
formatos de credencial ni todas las formas de contenido activo.

La evidencia actual usa un adaptador determinista. PGS-05-M02 ya fijó la
comparación adversaria inicial; la utilidad se mide en M03. Cualquier modelo o
proveedor real exige revisar estas reglas. `GSL-RESOURCE-POLICY-001` aplica los límites de
tamaño, tiempo cooperativo, iteraciones y consumo sin ampliar la detección
léxica de esta política. Una señal `output_policy_intervention` solo acredita
que esta política actuó; no prueba por sí misma un ataque o una fuga.
