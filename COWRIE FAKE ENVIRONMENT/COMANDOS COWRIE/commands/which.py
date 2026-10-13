# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause
#
# which. Viene del de Cowrie con un fallo que estaba a la vista en su propio
# comentario: decia "print each (first) result" y luego no cortaba, asi que
# recorria el PATH entero y escribia TODAS las coincidencias:
#
#     which sh   ->  /usr/bin/sh
#                    /bin/sh
#
# Un which de verdad escribe solo la primera; para ver todas hay que pedir
# "-a", que es justamente lo que hace un atacante cuando quiere saber si hay
# mas de un interprete. Medido en un Debian 13.
#
# Y no encontrar nada NO es silencio y ya: sale con 1, que es lo que mira un
# "which curl || which wget".
from __future__ import annotations

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_which(FallaAlAvisar, HoneyPotCommand):
    # Do not resolve args
    resolve_args = False

    def call(self) -> None:
        todas = any(a == "-a" or a == "--all" for a in self.args)
        nombres = [a for a in self.args if not a.startswith("-")]
        if not nombres or "PATH" not in self.environ:
            self.exit_code = 1 if nombres else 0
            return

        faltan = 0
        for f in nombres:
            encontrado = False
            for path in self.environ["PATH"].split(":"):
                resolved = self.fs.resolve_path(f, path)
                if self.fs.exists(resolved):
                    self.write(f"{path}/{f}\n")
                    encontrado = True
                    if not todas:
                        break
            if not encontrado:
                faltan += 1
        # which sale con 1 si le falta ALGUNO de los nombres, y no dice nada
        # por la salida de error: se calla y lo cuenta en el codigo.
        self.exit_code = 1 if faltan else 0


commands["which"] = Command_which
commands["/usr/bin/which"] = Command_which
commands["/bin/which"] = Command_which
