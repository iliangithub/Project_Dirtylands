# SPDX-FileCopyrightText: 2020 Matej Dujava <mdujava@kocurkovo.cz>
# SPDX-FileCopyrightText: 2021-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
"""
tee command

"""

from __future__ import annotations

import getopt
import os

from twisted.logger import Logger

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}


# TEE NO ESCRIBIA NADA EN EL FICHERO. Creaba el nodo con mkfile y le ajustaba
# el tamano, pero nunca dejaba el CONTENIDO: el fichero salia en el listado
# con su tamano y un "cat" posterior lo daba vacio. Peor que no crearlo, que
# eso al menos se ve.
#
# Es el mismo fallo que ya se corrigio en nano y en "sed -i", y se arregla
# igual: el contenido va a un Artifact y el nodo apunta a el con
# update_realfile. Asi el fichero se puede leer luego con cat, ejecutar con
# "./", y ademas queda capturado en disco como cualquier otra muestra --- que
# es justo lo que interesa cuando un dropper hace
# "echo <payload> | tee /tmp/x".
class Command_tee(FallaAlAvisar, HoneyPotCommand):
    """
    tee command
    """

    _log = Logger()

    append = False
    teeFiles: list[str]
    writtenBytes = 0
    ignoreInterupts = False
    datos: bytes = b""

    def start(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(
                self.args, "aip", ["help", "append", "version"]
            )
        except getopt.GetoptError as err:
            self.errorWrite(
                f"tee: invalid option -- '{err.opt}'\nTry 'tee --help' for more information.\n"
            )
            self.exit()
            return

        self.teeFiles = []
        self.datos = b""

        for o, _a in optlist:
            if o in ("--help"):
                self.help()
                self.exit()
                return
            elif o in ("-a", "--append"):
                self.append = True
            elif o in ("-i", "--ignore-interrupts"):
                self.ignoreInterupts = True

        for arg in args:
            pname = self.fs.resolve_path(arg, self.protocol.cwd)
            if self.fs.isdir(pname):
                self.errorWrite(f"tee: {arg}: Is a directory\n")
                continue

            folder_path = os.path.dirname(pname)
            fname = self.fs.resolve_path(folder_path, self.protocol.cwd)
            if not self.fs.isdir(fname):
                self.errorWrite(f"tee: {arg}: No such file or directory\n")
                continue

            # Con "-a" se conserva lo que ya hubiera, que para eso esta.
            if self.append:
                try:
                    self.datos = self.fs.file_contents(pname)
                except Exception:                              # noqa: BLE001
                    pass
            self.teeFiles.append(pname)

        if self.input_data:
            self.output(self.input_data)
            self.exit()

    def _guarda(self) -> None:
        """Deja el contenido de verdad: nodo Y artefacto."""
        from cowrie.core.artifact import Artifact

        for ruta in self.teeFiles:
            try:
                self.fs.mkfile(ruta, self.protocol.user.uid,
                               self.protocol.user.gid, len(self.datos), 33188)
                artefacto = Artifact("tee")
                with artefacto:
                    artefacto.write(self.datos)
                self.fs.update_realfile(self.fs.getfile(ruta),
                                        artefacto.shasumFilename)
            except FileNotFound:
                self.errorWrite("tee: %s: No such file or directory\n" % ruta)
            except Exception:                                  # noqa: BLE001
                pass

    def write_to_file(self, data: bytes) -> None:
        # Se ACUMULA. Antes esto solo ajustaba el tamano del nodo, que es
        # como decir que el fichero mide 40 bytes y dejarlo vacio.
        self.writtenBytes += len(data)
        self.datos += data

    def output(self, inb: bytes | None) -> None:
        """
        This is the tee output, if no file supplied
        """
        if inb:
            inp = inb.decode("utf-8")
        else:
            return

        lines = inp.split("\n")
        if lines[-1] == "":
            lines.pop()
        for line in lines:
            self.write(line + "\n")
            self.write_to_file(line.encode("utf-8") + b"\n")
        self._guarda()

    def lineReceived(self, line: str) -> None:
        """
        This function logs standard input from the user send to tee
        """
        self.protocol.events.dispatch(
            "cowrie.session.input",
            "INPUT (%(realm)s): %(input)s",
            realm="tee",
            input=line,
        )

        self.output(line.encode("utf-8"))

    def handle_CTRL_C(self) -> None:
        if not self.ignoreInterupts:
            self._log.info("Received CTRL-C, exiting..")
            self.write("^C\n")
            self.exit()

    def eofReceived(self) -> None:
        """
        ctrl-d is end-of-file, time to terminate
        """
        self._guarda()
        self.exit()

    def help(self) -> None:
        self.write(
            """Usage: tee [OPTION]... [FILE]...
Copy standard input to each FILE, and also to standard output.

  -a, --append              append to the given FILEs, do not overwrite
  -i, --ignore-interrupts   ignore interrupt signals
  -p                        diagnose errors writing to non pipes
      --output-error[=MODE]   set behavior on write error.  See MODE below
      --help     display this help and exit
      --version  output version information and exit

MODE determines behavior with write errors on the outputs:
  'warn'         diagnose errors writing to any output
  'warn-nopipe'  diagnose errors writing to any output not a pipe
  'exit'         exit on error writing to any output
  'exit-nopipe'  exit on error writing to any output not a pipe
The default MODE for the -p option is 'warn-nopipe'.
The default operation when --output-error is not specified, is to
exit immediately on error writing to a pipe, and diagnose errors
writing to non pipe outputs.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation <https://www.gnu.org/software/coreutils/tee>
or available locally via: info '(coreutils) tee invocation'
"""
        )


commands["/bin/tee"] = Command_tee
commands["tee"] = Command_tee
