# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import hashlib

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_md5sum(FallaAlAvisar, HoneyPotCommand):
    def call(self) -> None:
        paths = [a for a in self.args if not a.startswith("-")]
        if not paths:
            # SIN FICHEROS SE LEE DE LA ENTRADA, que es la mitad de las veces
            # que se teclea esto: "cat binario | md5sum", o el "| sha256sum"
            # detras de una descarga. Antes se devolvia sin escribir nada, asi
            # que el atacante veia una linea en blanco donde esperaba su hash
            # ---y un hash vacio no se parece a un error, se parece a que el
            # fichero no tiene nada---.
            #
            # El nombre que escribe coreutils cuando lee de la entrada es un
            # guion: "0bee...  -". Medido.
            if self.input_data is not None:
                digest = hashlib.md5(self.input_data).hexdigest()
                self.write("%s  -\n" % digest)
            return
        for arg in paths:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if not self.fs.exists(path):
                self.errorWrite(
                    f"md5sum: {arg}: No such file or directory\n"
                )
                continue
            if self.fs.isdir(path):
                self.errorWrite(f"md5sum: {arg}: Is a directory\n")
                continue
            try:
                data = self.fs.file_contents(path)
            except Exception:
                data = b""
            digest = hashlib.md5(data).hexdigest()
            self.write(f"{digest}  {arg}\n")


commands["md5sum"] = Command_md5sum
commands["/usr/bin/md5sum"] = Command_md5sum
