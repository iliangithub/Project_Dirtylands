# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_TARGET, A_TYPE, T_LINK

commands = {}


class Command_readlink(FallaAlAvisar, HoneyPotCommand):
    def call(self) -> None:
        canon = False
        paths = []
        for a in self.args:
            if a in ("-f", "-e", "-m", "--canonicalize"):
                canon = True
            elif a.startswith("-"):
                continue
            else:
                paths.append(a)
        if not paths:
            self.errorWrite("readlink: missing operand\n")
            return
        for arg in paths:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if canon:
                self.write(f"{path}\n")
                continue
            f = self.fs.getfile(path, follow_symlinks=False)
            if f and f[A_TYPE] == T_LINK:
                self.write(f"{f[A_TARGET]}\n")
            else:
                # Sin enlace no escribe NADA, pero devuelve 1. Como no pasa
                # por errorWrite, hay que ponerlo a mano: un readlink que
                # calla y devuelve 0 hace que un
                # "readlink /proc/PID/exe || otra-cosa" no pruebe el respaldo.
                self.exit_code = 1


commands["readlink"] = Command_readlink
commands["/usr/bin/readlink"] = Command_readlink
commands["/bin/readlink"] = Command_readlink
