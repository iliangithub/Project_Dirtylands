# SPDX-FileCopyrightText: 2020 Peter Šufliarsky
# SPDX-FileCopyrightText: 2020 Peter Sufliarsky <sufliarskyp@gmail.com>
# SPDX-FileCopyrightText: 2021-2024 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
uniq command
"""

from __future__ import annotations

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}

UNIQ_HELP = """Usage: uniq [OPTION]... [INPUT [OUTPUT]]
Filter adjacent matching lines from INPUT (or standard input),
writing to OUTPUT (or standard output).

With no options, matching lines are merged to the first occurrence.

Mandatory arguments to long options are mandatory for short options too.
  -c, --count           prefix lines by the number of occurrences
  -d, --repeated        only print duplicate lines, one for each group
  -D                    print all duplicate lines
      --all-repeated[=METHOD]  like -D, but allow separating groups
                                 with an empty line;
                                 METHOD={none(default),prepend,separate}
  -f, --skip-fields=N   avoid comparing the first N fields
      --group[=METHOD]  show all items, separating groups with an empty line;
                          METHOD={separate(default),prepend,append,both}
  -i, --ignore-case     ignore differences in case when comparing
  -s, --skip-chars=N    avoid comparing the first N characters
  -u, --unique          only print unique lines
  -z, --zero-terminated     line delimiter is NUL, not newline
  -w, --check-chars=N   compare no more than N characters in lines
      --help     display this help and exit
      --version  output version information and exit

A field is a run of blanks (usually spaces and/or TABs), then non-blank
characters.  Fields are skipped before chars.

Note: 'uniq' does not detect repeated lines unless they are adjacent.
You may want to sort the input first, or use 'sort -u' without 'uniq'.
Also, comparisons honor the rules specified by 'LC_COLLATE'.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation at: <https://www.gnu.org/software/coreutils/uniq>
or available locally via: info '(coreutils) uniq invocation'
"""


# ANTES IGNORABA "-c" Y "-d". Contaba lo repetido y no lo decia:
#
#     printf "a\\na\\nb\\n" | uniq -c   ->  daba "a\\nb", no los recuentos
#
# El recuento va alineado a la derecha en siete columnas y con un espacio
# detras ---"      2 a"---, que es lo que escribe coreutils; con otro ancho,
# un guion que corte por columnas saca basura. Medido en un Debian 13.
class Command_uniq(FallaAlAvisar, HoneyPotCommand):
    last_line: bytes | None = None

    def start(self) -> None:
        if "--help" in self.args:
            self.writeBytes(UNIQ_HELP.encode())
            self.exit()
            return
        banderas = "".join(a[1:] for a in self.args
                           if a.startswith("-") and not a.startswith("--"))
        self.contar = "c" in banderas
        self.solo_repetidas = "d" in banderas
        self.solo_unicas = "u" in banderas
        self.sin_mayusculas = "i" in banderas
        self.last_line = None
        self.veces = 0

        # UN FICHERO POR ARGUMENTO NO SE MIRABA. Solo leia de la entrada, asi
        # que "uniq fichero" ---la forma normal de llamarlo--- se quedaba
        # esperando por una entrada que no llegaba nunca y la sesion parecia
        # colgada. Con uno que ni siquiera existe, igual: ni error ni prompt.
        nombres = [a for a in self.args if not a.startswith("-")]
        if len(nombres) > 2:
            self.errorWrite("uniq: extra operand '%s'\n" % nombres[2])
            self.errorWrite("Try 'uniq --help' for more information.\n")
            self.exit()
            return
        datos = self.input_data
        if nombres and nombres[0] != "-":
            ruta = self.fs.resolve_path(nombres[0], self.protocol.cwd)
            try:
                datos = self.fs.file_contents(ruta)
            except Exception:                                  # noqa: BLE001
                self.errorWrite("uniq: %s: No such file or directory\n"
                                % nombres[0])
                self.exit()
                return

        if datos is not None:
            lines = datos.split(b"\n")
            if lines and not lines[-1]:
                lines.pop()
            for line in lines:
                self.grep_input(line)
            self.vacia()
            self.exit()

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="uniq",
            input=line,
        )
        self.grep_input(line.encode())

    def eofReceived(self) -> None:
        self.vacia()
        self.exit()

    def _igual(self, a, b) -> bool:
        if a is None or b is None:
            return False
        if self.sin_mayusculas:
            return a.lower() == b.lower()
        return a == b

    def vacia(self) -> None:
        """Escribe la ultima linea pendiente. Con "-c" no se puede escribir
        hasta saber cuantas veces se repite, asi que siempre va una por
        detras."""
        if self.last_line is None:
            return
        if self.solo_repetidas and self.veces < 2:
            return
        if self.solo_unicas and self.veces > 1:
            return
        if self.contar:
            self.writeBytes(b"%7d " % self.veces + self.last_line + b"\n")
        else:
            self.writeBytes(self.last_line + b"\n")

    def grep_input(self, line: bytes) -> None:
        if self._igual(line, self.last_line):
            self.veces += 1
            return
        self.vacia()
        self.last_line = line
        self.veces = 1


commands["uniq"] = Command_uniq
commands["/usr/bin/uniq"] = Command_uniq
commands["/bin/uniq"] = Command_uniq
