# SPDX-FileCopyrightText: 2010 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2018-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
cat command
"""

from __future__ import annotations

import getopt

from twisted.python import log

from cowrie.shell import fs
from cowrie.commands.base import (PID_SESION, con_dueno_de_sesion,
                                  rutas_del_proceso)
from cowrie.shell.command import HoneyPotCommand

# El arranque vive en UN solo sitio, base.py. Ver el comentario de
# uptime.py: declarado dos veces, es cuestion de tiempo que una copia se
# edite y la otra no.
from cowrie.commands.base import FallaAlAvisar, _ignis_uptime
from cowrie.shell.fs import FileNotFound

commands = {}


# --- Enforcement de permisos de lectura (homes privados) --------------------
def _cowrie_perm_ok(node, uid: int, gid: int, want: str) -> bool:
    mode = node[fs.A_MODE]
    if uid == node[fs.A_UID]:
        bit = 0o400 if want == "r" else 0o100
    elif gid == node[fs.A_GID]:
        bit = 0o040 if want == "r" else 0o010
    else:
        bit = 0o004 if want == "r" else 0o001
    return bool(mode & bit)


def _cowrie_access_denied(fsobj, abspath: str, uid: int, gid: int, target_need) -> bool:
    if uid == 0:
        return False
    parts = [p for p in abspath.split("/") if p]
    cur = ""
    for i, part in enumerate(parts):
        cur = cur + "/" + part
        try:
            node = fsobj.getfile(cur, follow_symlinks=True)
        except Exception:
            return False
        if not node:
            return False
        need = target_need if i == len(parts) - 1 else "x"
        if need is None:
            continue
        if not _cowrie_perm_ok(node, uid, gid, need):
            return True
    return False


class Command_cat(FallaAlAvisar, HoneyPotCommand):
    """
    cat command
    """

    number = False
    linenumber = 1

    # -A, -e, -E, -t, -T y -v: SE ACEPTABAN Y NO HACIAN NADA. "cat -A" es de
    # lo que se teclea para ver si un fichero trae retornos de carro de
    # Windows o tabuladores donde no debe, y contestaba el texto pelado, o sea
    # que decia que no hay nada raro pase lo que pase.
    fin_de_linea = False
    marca_tabulador = False
    marca_no_imprimible = False

    def _marcas(self, linea: bytes) -> bytes:
        """Lo que hacen -T y -v: el tabulador como ^I y lo no imprimible como
        ^X o M-X, que es como lo escribe coreutils."""
        if not (self.marca_tabulador or self.marca_no_imprimible):
            return linea
        salida = bytearray()
        for b in linea:
            if b == 0x09 and self.marca_tabulador:
                salida += b"^I"
            elif not self.marca_no_imprimible or 32 <= b < 127:
                salida.append(b)
            elif b < 32:
                salida += b"^" + bytes([b + 64])
            elif b == 127:
                salida += b"^?"
            else:
                salida += b"M-" + bytes([b - 128])
        return bytes(salida)

    def start(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(
                self.args, "AbeEnstTuv", ["help", "number", "version"]
            )
        except getopt.GetoptError as err:
            self.errorWrite(
                f"cat: invalid option -- '{err.opt}'\nTry 'cat --help' for more information.\n"
            )
            self.exit()
            return

        for o, _a in optlist:
            if o in ("--help"):
                self.help()
                self.exit()
                return
            elif o in ("-n", "--number"):
                self.number = True
            elif o == "-A":
                self.fin_de_linea = True
                self.marca_tabulador = True
                self.marca_no_imprimible = True
            elif o == "-e":
                self.fin_de_linea = True
                self.marca_no_imprimible = True
            elif o == "-E":
                self.fin_de_linea = True
            elif o == "-t":
                self.marca_tabulador = True
                self.marca_no_imprimible = True
            elif o == "-T":
                self.marca_tabulador = True
            elif o == "-v":
                self.marca_no_imprimible = True

        if len(args) > 0:
            uid = getattr(self.protocol.user, "uid", 0)
            gid = getattr(self.protocol.user, "gid", 0)
            for arg in args:
                if arg == "-":
                    self.output(self.input_data)
                    continue

                pname = self.fs.resolve_path(arg, self.protocol.cwd)

                # /proc/self/cmdline reflects the argv of the READING process
                # (cat itself), NUL-separated with a trailing NUL and no newline.
                # Emulate it dynamically instead of reading a static file.
                # EL DUENO DEL PROCESO ES EL DE LA SESION, no el del
                # pickle. /proc/<PID>/status se hornea al construir el
                # pickle con los datos de root, y el pickle es el mismo para
                # todas las sesiones, asi que entrando como un usuario normal
                # el senuelo se contradecia en dos ordenes seguidas:
                #
                #     $ id
                #     uid=1004(alyosha) gid=1004(alyosha) ...
                #     $ grep Uid: /proc/self/status
                #     Uid:  0  0  0  0
                #
                # El mismo proceso con dos duenos segun por donde se mire. Se
                # corrigen AQUI las lineas que dependen del usuario, sobre el
                # texto que ya trae el pickle: asi la plantilla sigue siendo
                # una sola y las dos no pueden separarse.
                if pname in rutas_del_proceso():
                    try:
                        texto = self.fs.file_contents(pname).decode(
                            "utf-8", "replace")
                    except Exception:                          # noqa: BLE001
                        texto = ""
                    if texto:
                        self.write(con_dueno_de_sesion(self, pname, texto))
                        continue

                # Y POR SU NUMERO TAMBIEN. /proc/self es un enlace a
                # /proc/<PID_SESION>, o sea EL MISMO FICHERO, y por el nombre
                # largo contestaba "No such file or directory": las dos rutas
                # del mismo sitio decian cosas distintas.
                if pname in ("/proc/self/cmdline",
                             "/proc/%d/cmdline" % PID_SESION):
                    argv = ["cat", *self.args]
                    self.writeBytes(
                        b"\0".join(a.encode("utf-8", "replace") for a in argv) + b"\0"
                    )
                    continue

                # /proc/uptime, y por el mismo motivo que el de arriba: es
                # dinamico. Un valor guardado en el pickle nace correcto y a
                # los cinco minutos ya contradice al comando `uptime`, que
                # cuenta desde IGNIS_BOOT_EPOCH. Congelar aqui un numero seria
                # crear la segunda version de un dato que ya tiene duena.
                #
                # Lo leen los guiones de los bots para saber si la maquina
                # lleva poco encendida ---una recien arrancada es sospechosa
                # de ser un analisis--- y hasta ahora devolvia la cadena
                # vacia, que en un Linux de verdad no pasa nunca.
                #
                # Formato: dos numeros con dos decimales, segundos desde el
                # arranque y segundos de CPU ociosa. El segundo se saca del
                # primero por los 12 procesadores que declara `nproc`, menos
                # un pellizco: una maquina con load average 0.00 esta ociosa
                # casi todo el tiempo, pero no todo.
                if pname == "/proc/uptime":
                    arriba = _ignis_uptime()
                    self.write("%.2f %.2f\n" % (arriba, arriba * 12 * 0.994))
                    continue

                if _cowrie_access_denied(self.fs, pname, uid, gid, "r"):
                    self.errorWrite(f"cat: {arg}: Permission denied\n")
                    continue

                if self.fs.isdir(pname):
                    self.errorWrite(f"cat: {arg}: Is a directory\n")
                    continue

                try:
                    contents = self.fs.file_contents(pname)
                    self.output(contents)
                except FileNotFound:
                    self.errorWrite(f"cat: {arg}: No such file or directory\n")
            self.exit()
        elif self.input_data is not None:
            self.output(self.input_data)
            self.exit()

    def output(self, inb: bytes | None) -> None:
        if inb is None:
            return
        lines = inb.split(b"\n")
        if lines[-1] == b"":
            lines.pop()
        for line in lines:
            if self.number:
                # SEIS HUECOS Y UN TABULADOR, no dos espacios: es lo que
                # separa "cat -n" de verdad, y un guion que corte por
                # tabuladores ---que es lo normal detras de un cat -n--- se
                # lleva la linea entera si ahi hay espacios.
                self.write("%6d\t" % self.linenumber)
                self.linenumber = self.linenumber + 1
            self.writeBytes(self._marcas(line) + b"\n"
                            if not self.fin_de_linea
                            else self._marcas(line) + b"$\n")

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.session.input",
            realm="cat",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )
        self.output(line.encode("utf-8"))

    def eofReceived(self) -> None:
        self.exit()

    def help(self) -> None:
        self.write(
            """Usage: cat [OPTION]... [FILE]...
Concatenate FILE(s) to standard output.

With no FILE, or when FILE is -, read standard input.

    -A, --show-all           equivalent to -vET
    -b, --number-nonblank    number nonempty output lines, overrides -n
    -e                       equivalent to -vE
    -E, --show-ends          display $ at end of each line
    -n, --number             number all output lines
    -s, --squeeze-blank      suppress repeated empty output lines
    -t                       equivalent to -vT
    -T, --show-tabs          display TAB characters as ^I
    -u                       (ignored)
    -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB
        --help     display this help and exit
        --version  output version information and exit

Examples:
    cat f - g  Output f's contents, then standard input, then g's contents.
    cat        Copy standard input to standard output.

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/cat>
or available locally via: info '(coreutils) cat invocation'
"""
        )


commands["/bin/cat"] = Command_cat
commands["cat"] = Command_cat
