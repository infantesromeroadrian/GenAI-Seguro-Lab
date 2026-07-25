Confina el único efecto de producto implementado: crear un borrador Markdown
ficticio.

## Trust boundary

- ID: `TB-05`.
- Destino exacto: `sandbox/drafts/`.
- El directorio y su padre deben ser físicos, no symlinks.
- El nombre admite un único fichero Markdown, nunca una ruta.
- La apertura es exclusiva y nunca sobrescribe o borra.

## Acceso

`TOL-02` exige propuesta y confirmación exacta separadas. Esta ruta existe como
API Python interna, pero no está conectada a `main.py`. `CMP-07` usa una
instancia efímera bajo `$TMP` para las pruebas TOL; el sandbox canónico no se
modifica.

## Persistencia

Los borradores generados se ignoran en Git; el directorio versionado solo
contiene su README.
