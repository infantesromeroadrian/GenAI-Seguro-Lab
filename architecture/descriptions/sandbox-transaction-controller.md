Controla el único punto de publicación y la reconciliación local del sandbox
de borradores.

## Responsabilidades

- Implementar `GSL-SANDBOX-RECOVERY-001` versión `1.0.0`.
- Validar las primitivas de plataforma y el descriptor de raíz antes de
  registrar autoridad de borrador.
- Coordinar publicación y recuperación mediante un `flock` exclusivo y no
  bloqueante sobre el descriptor.
- Crear marker y staging internos, canónicos, owner-only y modo `0600`.
- Sincronizar el staging y publicar el final mediante un hard link
  create-only como único punto de linealización.
- Preservar un final publicado aunque la limpieza posterior quede pendiente.
- Ejecutar una sola reconciliación de arranque y retirar únicamente
  artefactos internos válidos.
- Devolver un informe estricto con estado y conteos, sin contenido o contexto
  de autoridad.

## Restricciones

- Solo lo invoca `TOL-02`; no tiene ruta desde modelo, CLI o MCP.
- No publica staging durante recuperación.
- No crea, restaura o reutiliza propuestas, challenges, aprobaciones, grants o
  cuotas.
- No modifica, sobrescribe o borra un Markdown final.
- Falla cerrado ante tipo, owner, modo, tamaño, hash, inode, nlinks, esquema o
  lock incompatibles.
- No recorre subdirectorios, espera, reintenta, observa en segundo plano o usa
  red.
- Depende de primitivas POSIX y de procesos cooperantes; no aísla código hostil
  con la autoridad de `IDN-01`.

## Evidencia

- `src/genai_seguro_lab/sandbox_recovery.py`
- `tests/test_sandbox_recovery.py`
- Política `GSL-SANDBOX-RECOVERY-001`
- Inventario `CMP-12`
