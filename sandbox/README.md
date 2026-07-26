# Sandbox

El sandbox confina los únicos efectos locales permitidos por el producto.

Durante el mínimo viable, la única escritura autorizable es crear un borrador
nuevo dentro de `sandbox/drafts/`. El llamador interno debe autenticar el
principal sintético configurado y presentar una aprobación opaca, efímera y
ligada mediante SHA-256 al contenido exacto. Este mecanismo no acredita
presencia ni identidad de una persona real.

La implementación aplica estos límites:

- el modelo solo prepara la propuesta; no puede confirmarla;
- challenge, aprobación y grant de efecto son opacos, tienen TTL y se consumen
  una sola vez;
- una sesión admite una propuesta, un challenge, tres intentos de
  autenticación, un grant, un archivo y 16 KiB de Markdown;
- el nombre admite un único archivo Markdown, nunca una ruta;
- `sandbox/` y `sandbox/drafts/` deben ser directorios físicos, no enlaces
  simbólicos;
- la apertura es `create-only`: no se modifica ni sobrescribe un destino
  existente;
- no existen herramientas de borrado, shell, red ni acceso al sistema de
  archivos general.

La lectura de conocimiento no utiliza este directorio: opera exclusivamente
sobre el corpus sintético ya validado y cargado en memoria.
