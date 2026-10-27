# SPDX-License-Identifier: BSD-3-Clause
#
# dpkg emulado.
#
# La lista de paquetes NO va escrita aqui. Se lee de un fichero que exporta
# build-dirtyland-fs.sh desde el MISMO contenedor Debian del que sale el
# pickle, asi que el "dpkg -l" del senuelo y su sistema de ficheros cuentan lo
# mismo por construccion.
#
# Antes era una tabla a mano de 26 paquetes y habia envejecido: 20 de las 26
# versiones no coincidian ya con Debian 13 (apt 2.9.18 cuando el real es
# 3.0.3, nano 8.3-1 cuando es 8.4-1+deb13u1...). Y una de ellas,
# openssh-server, contradecia directamente al banner que anuncia el servicio.
# Ademas 26 paquetes son pocos: una Debian pelada ya trae 78, y con lo que
# instala la leyenda son varios cientos. Un "dpkg -l" corto es tan delator
# como uno con versiones inventadas.
from __future__ import annotations

import os

from cowrie.shell.command import HoneyPotCommand

commands = {}

# Lo monta el docker-compose (apartado 3.4.2.9). Formato TSV, una linea por
# paquete: nombre, version, arquitectura y resumen.
RUTA_PAQUETES = "/opt/dpkg-packages.tsv"

CABECERA = (
    "Desired=Unknown/Install/Remove/Purge/Hold\n"
    "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
    "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
)

# dpkg reserva a la arquitectura el ancho de su propio titulo, no el del
# contenido: con todo en amd64 la columna sigue midiendo 12.
ANCHO_ARCH = len("Architecture")

# Lo que contesta un dpkg de verdad cuando se le llama sin ninguna accion.
SIN_ACCION = (
    "Type dpkg --help for help about installing and deinstalling packages [*];\n"
    "Use 'apt' or 'aptitude' for user-friendly package management;\n"
    "Type dpkg -Dhelp for a list of dpkg debug flag values;\n"
    "Type dpkg --force-help for a list of forcing options;\n"
    "Type dpkg-deb --help for help about manipulating *.deb files;\n\n"
    "Options marked [*] produce a lot of output - pipe it through 'less' or 'more' !\n"
)


def leer_paquetes(ruta=RUTA_PAQUETES):
    """Devuelve [(nombre, version, arquitectura, resumen)] del fichero."""
    if not os.path.isfile(ruta):
        return []
    filas = []
    with open(ruta, encoding="utf-8", errors="replace") as f:
        for linea in f:
            campos = linea.rstrip("\n").split("\t")
            if len(campos) >= 4 and campos[0]:
                filas.append(tuple(campos[:4]))
    return filas


def formatear_lista(filas):
    """Reproduce la salida de "dpkg -l", con sus columnas.

    dpkg no usa anchos fijos: ajusta cada columna al contenido mas largo, y
    la linea de "=" de debajo mide lo mismo. Con anchos fijos, un paquete de
    nombre largo desplazaria la tabla entera y ninguna columna cuadraria con
    su separador.
    """
    if not filas:
        return CABECERA

    ancho_nombre = max([len("Name")] + [len(f[0]) for f in filas])
    ancho_version = max([len("Version")] + [len(f[1]) for f in filas])
    ancho_desc = max([len("Description")] + [len(f[3]) for f in filas])

    lineas = [
        CABECERA.rstrip("\n"),
        "||/ %-*s %-*s %-*s %s"
        % (ancho_nombre, "Name", ancho_version, "Version",
           ANCHO_ARCH, "Architecture", "Description"),
        "+++-%s-%s-%s-%s"
        % ("=" * ancho_nombre, "=" * ancho_version,
           "=" * ANCHO_ARCH, "=" * ancho_desc),
    ]
    for nombre, version, arch, desc in filas:
        lineas.append(
            "ii  %-*s %-*s %-*s %s"
            % (ancho_nombre, nombre, ancho_version, version,
               ANCHO_ARCH, arch, desc)
        )
    return "\n".join(lineas) + "\n"


def datos_de(filas, paquete, por_defecto=("1.22.18", "amd64")):
    """La version y la arquitectura que el propio listado da a un paquete."""
    for nombre, version, arch, _desc in filas:
        if nombre == paquete:
            return version, arch
    return por_defecto


class Command_dpkg(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        filas = leer_paquetes()
        if "-l" in args or "--list" in args:
            self.write(formatear_lista(filas))
        elif "-s" in args or "--status" in args:
            self.errorWrite("dpkg-query: package name is required\n")
        elif "--get-selections" in args:
            for nombre, _v, _a, _d in filas:
                self.write(f"{nombre}\t\t\t\tinstall\n")
        elif "--version" in args:
            self.write(self._version())
        elif not args:
            # Un dpkg de verdad no saca la version cuando se le llama sin
            # nada: protesta y sale con codigo 2.
            self.errorWrite("dpkg: error: need an action option\n\n")
            self.errorWrite(SIN_ACCION)
        else:
            self.write(self._version())

    def _version(self) -> str:
        """La linea que imprime "dpkg --version", entera.

        La version y la arquitectura son las del PROPIO dpkg segun el listado,
        no las del primer paquete: ese suele ser "adduser", que es "all", y un
        dpkg de verdad nunca dice "(all)".
        """
        version, arch = datos_de(leer_paquetes(), "dpkg")
        return (
            f"Debian 'dpkg' package management program version {version} ({arch}).\n"
            "This is free software; see the GNU General Public License version 2 or\n"
            "later for copying conditions. There is NO warranty.\n"
        )


commands["/usr/bin/dpkg"] = Command_dpkg
commands["dpkg"] = Command_dpkg
