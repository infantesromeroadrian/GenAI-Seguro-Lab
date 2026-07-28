# Registro de dependencias y supply chain — GenAI Seguro Lab

## Ficha

| Campo | Valor |
|---|---|
| Identificador | `GSL-SUPPLY-CHAIN-001` |
| Versión | `1.0.0` |
| Fecha | 2026-07-28 |
| Estado | `VIGENTE_ALCANCE_ACTUAL` |
| Owner | `ACT-02` |
| Microtarea | `PGS-06-M08` |
| Corte observado | commit `299cef7445f0d19e19b71c3d5926d91337f093fb` |

Este registro detalla la fotografía agregada del
[inventario del sistema](./system-inventory.md). Una versión y un hash
permiten detectar drift del artefacto cubierto, pero no demuestran autoría del
publicador, ausencia de código malicioso, licencia compatible, vulnerabilidades
inexistentes ni una instalación hermética.

## Fuentes de verdad

| Fuente | Función | SHA-256 del corte |
|---|---|---|
| `pyproject.toml` | rangos directos y Python admitido | `cb3ca6ea34bda636d4ae4b49a751642a25001287e525bc8b24473d0a1b0fc699` |
| `uv.lock` | resolución exacta, origen, URL y SHA-256 por sdist y wheel | `7a7cb70dac5c0d018cfbd7cea07f8ad3345ac96408a21e635f6c2e84d93617be` |
| `.python-version` | selección local de Python 3.12 | `7b55f8e67b5623c4bef3fa691288da9437d79d3aba156de48d481db32ac7d16d` |
| Git | historia, commits y remoto público | commit del corte y commits posteriores deliberados |

`uv.lock` declara 12 paquetes: el proyecto virtual y 11 distribuciones
externas. Todas las distribuciones externas proceden de
`https://pypi.org/simple`; sus artefactos apuntan a `files.pythonhosted.org` y
conservan SHA-256. `uv sync --frozen` evita cambiar la resolución, pero puede
descargar artefactos: no es una build offline o hermética.

## Dependencias Python

<!-- dependency-register:start -->
| ID | Distribución y versión | Relación | Uso y riesgo principal | Integridad fijada | Owner |
|---|---|---|---|---|---|
| `SC-PKG-01` | `pydantic 2.13.4` | Directa de runtime; rango `>=2.10,<3` | Validación de todos los sobres; un cambio puede alterar fallo cerrado, coerción o serialización | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-02` | `pydantic-core 2.46.4` | Transitiva de runtime | Núcleo nativo de validación; artefacto específico de plataforma y código ejecutable | sdist y wheels por plataforma con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-03` | `annotated-types 0.8.0` | Transitiva de runtime | Metadatos de restricciones utilizados por Pydantic | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-04` | `typing-extensions 4.16.0` | Transitiva de runtime | Compatibilidad de tipos utilizada por el contrato | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-05` | `typing-inspection 0.4.2` | Transitiva de runtime | Inspección de anotaciones utilizada por Pydantic | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-06` | `pytest 9.1.1` | Directa de desarrollo; rango `>=9,<10` | Ejecuta tests y plugins con autoridad del mantenedor; no forma parte del runtime de producto | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-07` | `iniconfig 2.3.0` | Transitiva de desarrollo | Lectura de configuración de pytest | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-08` | `packaging 26.2` | Transitiva de desarrollo | Comparación de versiones y marcadores de pytest | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-09` | `pluggy 1.6.0` | Transitiva de desarrollo | Sistema de plugins de pytest; amplía código ejecutado durante pruebas | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-10` | `pygments 2.20.0` | Transitiva de desarrollo | Formato de salida de pytest | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
| `SC-PKG-11` | `colorama 0.4.6` | Transitiva condicional de desarrollo en Windows | Colores de terminal; no se instala en el host macOS observado | sdist y wheel con SHA-256 en `uv.lock` | `ACT-02` |
<!-- dependency-register:end -->

No hay SDK de proveedor, framework de agentes, servidor web, ORM, base de
datos, vector store, telemetría, Docker o dependencia de modelo real.

## Toolchain e integraciones

<!-- toolchain-register:start -->
| ID | Elemento | Estado observado | Fijación y riesgo |
|---|---|---|---|
| `SC-TOOL-01` | CPython | `3.12.8`; contrato `==3.12.*` en el lock y `>=3.12,<3.13` en el proyecto | Minor fijada, patch no fijado; runtime y librería estándar forman parte de la TCB |
| `SC-TOOL-02` | `uv` | CLI local `0.6.10` | No está fijado por versión o hash dentro del repositorio; distintas versiones pueden resolver o instalar de forma diferente |
| `SC-TOOL-03` | Git | `2.50.1` observado | No está fijado; los commits e hashes aportan integridad, no firma o identidad fuerte |
| `SC-TOOL-04` | PyPI / pythonhosted | Índice y almacenamiento externos usados por el lock | Disponibilidad, cuenta del publicador, compromiso de índice y revocación quedan fuera del control local |
| `SC-TOOL-05` | GitHub | Remoto público y publicación manual de `main` | No hay workflow versionado, firma de commit, release o revisión independiente ejercida |
<!-- toolchain-register:end -->

Las versiones de `uv` y Git son observaciones del host, no requisitos
universales. PGS-07-M01 debe registrar el toolchain efectivo de su
reconstrucción en lugar de asumir que coincide.

## Riesgos y gaps

<!-- supply-chain-gaps:start -->
| ID | Gap o riesgo | Estado | Tratamiento actual o próximo trigger |
|---|---|---|---|
| `SCG-01` | No existe SBOM CycloneDX/SPDX versionada | `ABIERTO` | Este registro es inventario humano, no SBOM estándar; decidir formato antes de distribuir artefactos |
| `SCG-02` | No hay firma de commits, tags, paquetes, lock o evidencia | `ABIERTO` | Los hashes detectan drift cubierto, no autenticidad; revisar antes de release o colaboración |
| `SCG-03` | No existe CI/CD o workflow de GitHub versionado | `ABIERTO` | Reconstrucción y pruebas son manuales; reevaluar al añadir automatización |
| `SCG-04` | No hay política de release, tag o rollback externo | `ABIERTO` | Releases siguen fuera de la autorización actual |
| `SCG-05` | No hay `SECURITY.md`, `CODEOWNERS` ni separación de funciones | `ABIERTO` | `ACT-02` concentra mantenimiento; `REV-01` sigue sin asignar |
| `SCG-06` | Licencias de dependencias y del repositorio no se han evaluado ni documentado | `NO_EVALUADO` | Revisar antes de redistribuir, empaquetar o aceptar contribuciones |
| `SCG-07` | Vulnerabilidades y advisories no se han escaneado en este corte | `NO_EVALUADO` | No equivale a “sin vulnerabilidades”; consultar fuentes y registrar fecha antes de release o ante alerta |
| `SCG-08` | Build no hermética y herramientas de host no fijadas por artefacto | `ABIERTO` | PGS-07-M01 reconstruirá desde limpio y registrará versiones, red usada y límites |
<!-- supply-chain-gaps:end -->

`RR-03` permanece `ABIERTO` y `RDEC-03` continúa
`PENDIENTE_HUMANA`. Crear el inventario no acepta el riesgo, no ejecuta la
fixture `AC-SC-01` y no convierte `CTL-11` en completo.

## Proceso de cambio

Antes de añadir, quitar o actualizar una dependencia:

1. identificar finalidad, owner, superficie runtime o desarrollo y
   alternativas sin nueva dependencia;
2. consultar origen oficial, versión, artefactos, licencia y advisories con
   fecha; no copiar secretos o tokens de índices;
3. cambiar `pyproject.toml` y regenerar `uv.lock` en un commit acotado;
4. revisar el diff de paquete, origen, dependencias transitivas, marcadores,
   URLs y hashes;
5. ejecutar `uv lock --check`, reconstrucción con `uv sync --frozen`, pruebas
   focales y suite proporcional;
6. actualizar este registro, riesgos, AIA, ADR y mapa de cumplimiento si se
   activa un trigger;
7. no borrar o reinterpretar evidencia histórica producida con otra
   resolución.

Ante una alerta, congelar publicación, acotar versiones y superficie
alcanzable y elegir mitigación verificable. No actualizar a ciegas ni declarar
una vulnerabilidad explotable solo por coincidir nombre y versión.

## Relación con Tecture

El registro describe dependencias e integraciones ya inventariadas. No añade
runtime, proveedor, servicio, despliegue, interfaz, almacén o flujo, por lo que
no modifica `architecture/`.
