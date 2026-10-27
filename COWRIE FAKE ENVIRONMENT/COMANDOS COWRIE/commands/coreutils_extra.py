# SPDX-License-Identifier: BSD-3-Clause
#
# basename, dirname, sort, uniq, rev y xargs.
#
# Los seis los DECLARA el sistema de ficheros del senuelo ---salen del mismo
# Debian del que sale el pickle--- y ninguno estaba emulado, asi que no
# fallaban callando: contestaban
#
#     -bash: /usr/bin/basename: No such file or directory
#
# que es la contradiccion de siempre y la peor de todas, porque un
# "command not found" seria normal y esto significa que la maquina miente:
# "ls -l /usr/bin/basename" lo ensena, "which" lo encuentra y "dpkg -l"
# declara coreutils.
#
# uniq ya estaba, pero ignoraba "-c" y "-d". Todo medido contra los binarios
# de un Debian 13.
from __future__ import annotations

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}


# LA VERSION DE COREUTILS, EN UN SOLO SITIO.
#
# Estaba escrita a mano y distinta en cada comando: "cut --version" decia
# 8.30, "chmod --version" 8.25 y "printenv --version" 9.7, todos en la misma
# maquina y con un "dpkg -l" que declara coreutils 9.7-3. Tres versiones del
# mismo paquete es de las contradicciones mas faciles de mirar.
#
# Sale del listado de dpkg, como en ping, sudo, awk y openssl.
def version_coreutils() -> tuple[str, str]:
    """(numero, version empaquetada) que declara el listado de dpkg."""
    crudo = "9.7-3"
    try:
        from cowrie.commands.dpkg import datos_de, leer_paquetes

        crudo, _arch = datos_de(leer_paquetes(), "coreutils",
                                por_defecto=("9.7-3", "amd64"))
    except Exception:                                          # noqa: BLE001
        pass
    return crudo.split("-")[0].split("+")[0], crudo


def bloque_version(herramienta: str, autores: str) -> str:
    """El "--version" de cualquier coreutils, con el formato de Debian."""
    numero, empaquetado = version_coreutils()
    return (
        f"{herramienta} (GNU coreutils) {numero}\n"
        f"Packaged by Debian ({empaquetado})\n"
        "Copyright (C) 2025 Free Software Foundation, Inc.\n"
        "License GPLv3+: GNU GPL version 3 or later"
        " <https://gnu.org/licenses/gpl.html>.\n"
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n"
        "\n"
        f"Written by {autores}.\n"
    )


def _falta_operando(cmd) -> None:
    cmd.errorWrite("%s: missing operand\n"
                   "Try '%s --help' for more information.\n"
                   % (cmd.NOMBRE, cmd.NOMBRE))
    cmd.exit_code = 1


class Command_basename(FallaAlAvisar, HoneyPotCommand):
    NOMBRE = "basename"

    def call(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        if not args:
            _falta_operando(self)
            return
        # Las barras del final NO cuentan: "basename /a/b/" es "b".
        nombre = args[0].rstrip("/").split("/")[-1] or "/"
        if len(args) > 1 and nombre.endswith(args[1]) and nombre != args[1]:
            nombre = nombre[:-len(args[1])]
        self.write(nombre + "\n")


class Command_dirname(FallaAlAvisar, HoneyPotCommand):
    NOMBRE = "dirname"

    def call(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        if not args:
            _falta_operando(self)
            return
        for ruta in args:
            limpia = ruta.rstrip("/")
            if "/" not in limpia:
                # Sin ninguna barra la respuesta es un punto, no la cadena
                # vacia: "dirname c.txt" dice ".".
                self.write(".\n")
                continue
            cabeza = limpia.rsplit("/", 1)[0]
            self.write((cabeza or "/") + "\n")


class Command_sort(FallaAlAvisar, HoneyPotCommand):
    CODIGO_DE_FALLO = 2
    NOMBRE = "sort"

    def _lineas(self) -> list:
        datos = self.input_data or b""
        for arg in [a for a in self.args if not a.startswith("-")]:
            try:
                datos += self.fs.file_contents(
                    self.fs.resolve_path(arg, self.protocol.cwd))
            except Exception:                                  # noqa: BLE001
                self.errorWrite("sort: cannot read: %s: No such file or "
                                "directory\n" % arg)
                self.exit_code = 2
        texto = datos.decode("utf-8", "replace")
        lineas = texto.split("\n")
        if lineas and lineas[-1] == "":
            lineas.pop()
        return lineas

    def call(self) -> None:
        banderas = "".join(a[1:] for a in self.args if a.startswith("-")
                           and not a.startswith("--"))
        lineas = self._lineas()
        if "n" in banderas:
            def clave(x):
                try:
                    return (0, float(x.strip().split()[0]) if x.strip() else 0)
                except ValueError:
                    return (1, 0)
            lineas.sort(key=clave)
        else:
            lineas.sort()
        if "r" in banderas:
            lineas.reverse()
        if "u" in banderas:
            vistas, unicas = set(), []
            for l in lineas:
                if l not in vistas:
                    vistas.add(l)
                    unicas.append(l)
            lineas = unicas
        if lineas:
            self.write("\n".join(lineas) + "\n")


class Command_rev(FallaAlAvisar, HoneyPotCommand):
    NOMBRE = "rev"

    def call(self) -> None:
        datos = self.input_data or b""
        for arg in [a for a in self.args if not a.startswith("-")]:
            try:
                datos += self.fs.file_contents(
                    self.fs.resolve_path(arg, self.protocol.cwd))
            except Exception:                                  # noqa: BLE001
                self.errorWrite("rev: cannot open %s: No such file or "
                                "directory\n" % arg)
                self.exit_code = 1
        texto = datos.decode("utf-8", "replace")
        lineas = texto.split("\n")
        final = lineas and lineas[-1] == ""
        if final:
            lineas.pop()
        for l in lineas:
            self.write(l[::-1] + "\n")


class Command_xargs(FallaAlAvisar, HoneyPotCommand):
    """xargs. Lanza el comando de verdad, no finge lanzarlo.

    Se hace con la misma maquinaria que usa un parentesis: se compone la
    linea y se ejecuta. Asi un "printf ... | xargs rm" pasa por el rm
    emulado y queda registrado como cualquier otra orden, que es justo lo
    que interesa que se vea en el log.
    """

    NOMBRE = "xargs"

    def call(self) -> None:
        args = list(self.args)
        por_tanda = None
        orden = []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-n" and i + 1 < len(args):
                por_tanda = int(args[i + 1]) if args[i + 1].isdigit() else None
                i += 2
                continue
            if a.startswith("-n") and a[2:].isdigit():
                por_tanda = int(a[2:])
            elif a in ("-0", "--null", "-r", "--no-run-if-empty"):
                pass
            elif a.startswith("-"):
                pass
            else:
                orden = args[i:]
                break
            i += 1
        if not orden:
            orden = ["echo"]

        palabras = (self.input_data or b"").decode("utf-8", "replace").split()
        if not palabras:
            return
        tandas = ([palabras[i:i + por_tanda]
                   for i in range(0, len(palabras), por_tanda)]
                  if por_tanda else [palabras])
        for tanda in tandas:
            linea = " ".join(orden + tanda)
            try:
                salida, estado = (self.protocol.cmdstack[-2]
                                  ._execute_single_command_with_redirect(
                                      linea))
            except Exception:                                  # noqa: BLE001
                return
            if salida:
                self.write(salida)
            self.exit_code = estado


for _clase in (Command_basename, Command_dirname, Command_sort, Command_rev,
               Command_xargs):
    _nombre = _clase.NOMBRE
    commands[_nombre] = _clase
    commands["/usr/bin/" + _nombre] = _clase
    commands["/bin/" + _nombre] = _clase
