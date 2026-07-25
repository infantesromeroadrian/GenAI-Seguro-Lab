# Sandbox

El sandbox confina los únicos efectos locales permitidos por el producto.

Durante el mínimo viable, la única escritura autorizable es crear un borrador
nuevo dentro de `sandbox/drafts/`, tras una confirmación explícita que el
llamador declara humana y vincula mediante SHA-256 al contenido exacto
propuesto. Esta capa todavía no autentica la identidad de quien confirma.

La implementación aplica estos límites:

- el modelo solo prepara la propuesta; no puede confirmarla;
- la confirmación llega por un parámetro separado y se consume una sola vez
  durante el proceso;
- el nombre admite un único archivo Markdown, nunca una ruta;
- `sandbox/` y `sandbox/drafts/` deben ser directorios físicos, no enlaces
  simbólicos;
- la apertura es `create-only`: no se modifica ni sobrescribe un destino
  existente;
- no existen herramientas de borrado, shell, red ni acceso al sistema de
  archivos general.

La lectura de conocimiento no utiliza este directorio: opera exclusivamente
sobre el corpus sintético ya validado y cargado en memoria.
