Aplica la política preventiva y fail-closed de recursos del producto sin
conceder autoridad de ejecución.

## Responsabilidades

- Implementar `GSL-RESOURCE-POLICY-001` versión `1.0.0`.
- Leer el corpus benigno por descriptor y rechazar antes del parseo o hash más
  de 64 KiB acumulados, 8 KiB por registro o 32+32 registros.
- Limitar a 8 KiB cada petición y respuesta de modelo, a 4 KiB argumentos,
  resultados de búsqueda y resumen final, y a 16 KiB el Markdown de borrador.
- Consumir por adelantado casos, invocaciones, solicitudes, ejecuciones,
  propuestas, challenges, autenticaciones, grants y archivos.
- Aplicar perfiles `analyze`, `baseline` y `draft` con checkpoints observables.
- Mantener un lock exclusivo y no bloqueante sobre el descriptor existente de
  `data/manifest.json` durante cada operación de la CLI.
- Señalar en `CMP-11` el exceso de recursos o conflicto de lock mediante
  códigos cerrados, sin incluir valor, umbral, ruta o excepción.

## Restricciones

- No contiene modelo, herramienta, filesystem de efecto, red o credenciales.
- No crea lockfiles, esperas, reintentos, procesos o servicios.
- El plazo es cooperativo: detecta el retorno tardío, pero no puede cancelar
  una llamada síncrona bloqueada.
- El lock es advisory y solo coordina procesos que usan la CLI oficial; una
  llamada directa a la API Python puede omitirlo.
- No implementa rate limiting persistente, cuota distribuida, límite RSS,
  cgroup o aislamiento del sistema operativo.
- El presupuesto del journal es independiente y no amplía estos límites.

## Evidencia

- `src/genai_seguro_lab/resource_control.py`
- `tests/test_resource_control.py`
- `docs/resource-limits-policy.md`
- Inventario `CMP-10`
- Integración `CMP-11`
