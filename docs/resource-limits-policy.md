# Política de límites de recursos

## Identidad y alcance

- **ID:** `GSL-RESOURCE-POLICY-001`
- **Versión:** `1.0.0`
- **Microtarea:** `PGS-04-M06`
- **Propietario:** `ACT-02`, mantenedor del laboratorio
- **Ámbito:** corpus benigno, operaciones `analyze` y `baseline`, fronteras de
  modelo y herramienta, creación interna de borradores y procesos cooperantes
  de la CLI

Esta política es un control preventivo del producto endurecido. No reutiliza ni
amplía `GSL-ROE-001`: las Rules of Engagement autorizan y acotan evaluaciones
adversarias, mientras que esta política limita el comportamiento ordinario de
la aplicación.

PGS-04-M07 conecta sus rechazos con `GSL-SECURITY-EVENTS-001`. El journal
posee límites separados de eventos y bytes: no incorpora contenido observado
ni altera los contadores de esta política.

PGS-04-M08 añade límites independientes a `CMP-12`: como máximo examina 256
entradas de la raíz, 16 artefactos internos y 8 transacciones, con markers de
1 KiB y staging de 16 KiB. Esos límites protegen la reconciliación y no
restauran el archivo ya consumido por `CMP-10`.

## Requisitos

| ID | Requisito verificable |
|---|---|
| `RL-01` | La carga benigna rechaza antes de parsear o calcular hashes más de 64 KiB acumulados, un registro JSONL mayor de 8 KiB, más de 32 incidentes o más de 32 documentos |
| `RL-02` | Cada petición y respuesta serializada del modelo ocupa como máximo 8 KiB |
| `RL-03` | Los argumentos de herramienta y el resultado de búsqueda ocupan como máximo 4 KiB cada uno; el resumen final ocupa como máximo 4 KiB |
| `RL-04` | `analyze` admite un caso, dos invocaciones, una solicitud y una ejecución de herramienta dentro de un segundo cooperativo |
| `RL-05` | `baseline` admite 12 casos, 24 invocaciones y 12 solicitudes y ejecuciones dentro de cinco segundos cooperativos |
| `RL-06` | Una sesión de borrador admite una propuesta, un challenge, tres intentos de autenticación, un grant, un archivo y un Markdown UTF-8 de hasta 16 KiB |
| `RL-07` | La CLI rechaza sin espera un segundo proceso cooperante; no crea lockfiles, reintentos ni procesos en segundo plano |
| `RL-08` | Todo contador se consume antes de la operación protegida y todo plazo se comprueba antes y después de una frontera síncrona |
| `RL-09` | Un exceso falla cerrado, no produce salida parcial y no revela el valor, contenido o límite que provocó el rechazo |

## Umbrales y fundamento

| Recurso | Umbral | Baseline observada antes del control | Margen |
|---|---:|---:|---:|
| Corpus benigno completo | 65.536 B | 21.393 B | 3,0× |
| Registro JSONL | 8.192 B | 1.180 B | 6,9× |
| Incidentes / conocimiento | 32 / 32 | 12 / 8 | 2,7× / 4,0× |
| Petición de modelo | 8.192 B | 2.119 B máximo | 3,9× |
| Argumentos de herramienta | 4.096 B | 68 B máximo | 60,2× |
| Resultado de herramienta | 4.096 B | 667 B máximo | 6,1× |
| Resumen final | 4.096 B | Menor que 1 KiB en los 12 casos | Más de 4× |
| Markdown de borrador | 16.384 B | No conectado a la CLI | Cota explícita por efecto |
| `analyze` | 1 s | Flujo local determinista | Plazo cooperativo |
| `baseline` | 5 s | 12 casos locales deterministas | Plazo cooperativo |

Los límites se expresan en bytes UTF-8 y no en caracteres o tokens. Los bytes
son reproducibles sin depender de un tokenizer o proveedor. Los umbrales se
fijaron con margen respecto del corpus y las fronteras existentes, pero no son
universales: cualquier ampliación del producto exige una decisión versionada y
un retest previo, no un aumento silencioso.

## Orden de aplicación

1. Adquirir el lock de CLI y abrir o reutilizar el presupuesto de la operación;
   `baseline` lo inicia antes de cargar para incluir ese tiempo.
2. Verificar tamaño y cardinalidad antes de parsear o cargar contenido completo.
3. Consumir caso, invocación, solicitud, ejecución o efecto antes de iniciarlo.
4. Comprobar el tiempo antes y después de cada frontera síncrona.
5. Medir la representación UTF-8 antes de parsear, aplicar expresiones
   regulares, autorizar o escribir.
6. Entregar el resultado solo después de que todos los controles terminen.

No existe un modo permisivo del flujo ordinario. Los tests pueden inyectar un
reloj y límites más estrechos para alcanzar los bordes sin esperas reales, pero
no omitir el control.

## Fallo cerrado y evidencia negativa

El rechazo sucede antes del adaptador, la herramienta o el filesystem cuando
el presupuesto ya permite conocer el exceso. Si una respuesta síncrona excede
el tamaño o el plazo al volver, se descarta y no se entrega. La CLI devuelve
estado no cero, `stdout` vacío y un error genérico por `stderr`.

Las pruebas cubren el valor permitido y el inmediatamente superior cuando el
tipo de límite lo permite, consumo acumulado, tiempo con reloj inyectado,
contención del lock cooperativo y ausencia de efectos tras un rechazo.

## Límites y riesgo residual

- El plazo es cooperativo. `ModelAdapter.generate()` es síncrono y no ofrece
  cancelación, por lo que el control detecta un retorno tardío, pero no puede
  interrumpir una dependencia bloqueada.
- Un futuro proveedor real deberá implementar timeout nativo o aislamiento de
  proceso; no puede heredar esta garantía por analogía.
- El lock de CLI es advisory: coordina procesos que usan la entrada oficial,
  pero el mismo usuario puede omitirlo al invocar directamente la API Python.
- El lock de `CMP-12` es también advisory y no bloqueante, pero sí cubre la
  publicación y reconciliación de `TOL-02` entre procesos cooperantes.
- No existe rate limiting persistente por usuario, cuota distribuida, cgroup,
  límite de RSS o aislamiento de sistema operativo.
- El journal de `CMP-11` hace observable un exceso mediante un código cerrado,
  pero no añade cuota persistente, cancelación o respuesta automática.
- La política no materializa los casos DOS inertes ni modifica la evidencia
  histórica. PGS-05 medirá latencia y consumo con el mismo corpus de retest.
