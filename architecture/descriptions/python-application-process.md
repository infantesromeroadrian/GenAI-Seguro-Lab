Contiene toda la lógica ejecutable del producto en un único proceso Python
local.

## Responsabilidades

- Resolver la CLI desde el checkout.
- Validar el dataset benigno antes de utilizarlo.
- Aplicar `CMP-10` a corpus, fronteras, operaciones, sesiones de borrador y
  concurrencia cooperativa de la CLI.
- Aplicar `CMP-11` a decisiones y efectos mediante un journal acotado en
  memoria, sin contenido bruto o exportación automática.
- Aplicar `CMP-12` al efecto interno de borrador mediante publicación atómica,
  parada y una reconciliación preautoridad.
- Validar por API interna las entradas y oráculos adversarios.
- Ejecutar el flujo benigno acotado y el adaptador determinista.
- Autorizar la búsqueda de conocimiento fuera del modelo.
- Emitir grants lógicos de una sola herramienta y vistas por incidente.
- Exponer internamente la herramienta de borradores sin conectarla a la CLI.
- Construir, solo por factory interna, una petición vulnerable de evaluación
  ligada a datos sintéticos y un sandbox temporal.
- Ejecutar por API interna 14 fixtures PI/JB/EX/TOL mediante copias y sandboxes
  temporales, dobles deterministas, guardas del flujo, rechazos de búsqueda y
  herramienta, controles de borrador y un subproceso CLI saneado, siempre sin
  red y con un único efecto temporal conocido.
- Ejecutar mediante `CMP-08` la baseline adversaria sobre un commit limpio,
  medir límites y producir evidencia bruta solo bajo `$TMP`.

## Trust boundary

- ID: `TB-02`.
- Aislamiento real: memoria del proceso.
- Límite: salvo el subproceso acotado de `ADV-EX-003`, no existe aislamiento
  interno por proceso, contenedor o identidad.
- El lock y los plazos de `CMP-10` son cooperativos y no cambian ese límite.
- La cadena de `CMP-11` no autentica al emisor ni resiste código hostil dentro
  de este mismo proceso.
- El `flock` de `CMP-12` es cooperativo y su recuperación no sustituye
  aislamiento de sistema operativo ni un runbook.
- `ADV-EX-003` recibe solo tres variables ambientales permitidas; no hereda
  `os.environ`.

## Tecnología

- Python 3.12.8.
- Pydantic 2.13.4.
- Sin framework de agentes o SDK de proveedor.
