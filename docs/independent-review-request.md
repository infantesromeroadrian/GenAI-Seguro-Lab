# Solicitud de revisión independiente

| Campo | Valor |
|---|---|
| ID | `GSL-REV-PACK-001` |
| Microtarea | `PGS-07-M04` |
| Estado | `READY_AWAITING_HUMAN_REVIEW` |
| Candidato | commit `1508cad250ecdcc3cd7e68de583c2a528e54a183`, tree `3975ab84d14f575281ee484c2fc5085f68e4d490` |
| Revisión realizada | No |
| Rol pendiente | `REV-01` |

## Quién puede realizarla

Debe ser una persona con experiencia práctica revisando seguridad de
aplicaciones o de IA, distinta de quien diseñó e implementó el candidato. Debe
aceptar expresamente la asignación antes de que el proyecto le atribuya el rol
`REV-01`.

Un agente, una segunda ejecución del mismo mantenedor o una comprobación
automática no satisfacen esta condición. La revisión tampoco constituye una
aprobación de producción ni una aceptación de riesgo.

## Alcance fijado

El manifiesto machine-readable
[`GSL-REV-PACK-001`](../reviews/independent-review-pack-v1.json) fija por hash:

1. inventario del sistema y matriz de autoridad;
2. abuse cases, priorización y crosswalk;
3. matriz de controles, pruebas y limitaciones;
4. la prueba seleccionada `ADV-TOL-005` y su implementación.

La persona revisora debe confirmar que ha utilizado el commit y el árbol
indicados. No debe revisar el `HEAD` móvil como sustituto.

## Prueba seleccionada

```bash
git checkout 1508cad250ecdcc3cd7e68de583c2a528e54a183
uv sync --frozen
uv run --frozen pytest -p no:cacheprovider \
  tests/test_tool_abuse_evaluation.py::test_fabricated_confirmation_is_rejected_without_rewriting_old_oracle
```

La prueba usa únicamente datos sintéticos y un temporal de pytest. Comprueba
que una confirmación fabricada se rechaza antes de I/O, no crea archivos, no
hace llamadas externas y no reescribe el oráculo histórico.

No se debe ejecutar `evaluations/run_final_retest.py`, regenerar `DAT-25` ni
activar las cuatro fixtures DOS/SC inertes.

## Respuesta mínima

La revisión debe conservar:

- identidad pública de la persona revisora y un resumen de cualificación;
- declaración de independencia o conflicto;
- commit, ficheros revisados y resultado del comando;
- hallazgos con ID, severidad, ubicación, observación, evidencia y
  recomendación;
- discrepancias expresas, o la declaración de que no se observaron;
- fecha de finalización.

Puede entregarse como review o comentario de GitHub fijado al commit, o como
documento devuelto por la persona y versionado después sin alterar el candidato.
Un hallazgo es evidencia consultiva: cualquier corrección requerirá una
decisión separada y deberá conservar la discrepancia original.

## Estado de la microtarea

El paquete está preparado, pero `PGS-07-M04` sigue abierta. Solo podrá cerrarse
cuando una persona elegible acepte `REV-01` y devuelva la evidencia mínima.
Hasta entonces no se atribuirá revisión independiente.
