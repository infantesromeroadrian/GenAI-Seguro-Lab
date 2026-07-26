Confina el único efecto de producto implementado: crear un borrador Markdown
ficticio.

## Trust boundary

- ID: `TB-05`.
- Destino exacto: `sandbox/drafts/`.
- El directorio y su padre deben ser físicos, no symlinks.
- El nombre admite un único fichero Markdown, nunca una ruta.
- La raíz queda anclada mediante descriptor.
- `CMP-12` crea marker y staging internos `0600` y publica el final mediante
  hard link create-only; nunca sobrescribe o borra el final.

## Acceso

`TOL-02` exige propuesta, autenticación sintética, aprobación y grant de
efecto separados. Esta ruta existe como API Python interna, pero no está
conectada a `main.py`. `CMP-12` solo materializa ese efecto ya autorizado o
retira metadatos internos validados en el siguiente arranque; nunca republica
staging. `CMP-07` usa una instancia efímera bajo `$TMP` para las pruebas TOL;
el sandbox canónico no se modifica.

## Persistencia

Los borradores generados se ignoran en Git; el directorio versionado solo
contiene su README. El namespace `.gsl-txn-*` es interno, acotado y efímero.
