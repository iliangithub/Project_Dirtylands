# SPDX-License-Identifier: BSD-3-Clause
"""
printenv para el senuelo.

Cowrie implementa "env" pero NO "printenv", y /usr/bin/printenv si existe en el
pickle (viene con coreutils). Resultado: caia al ultimo recurso del shell y
contestaba "cannot execute binary file: Exec format error", el mismo fallo que
tenian df y mount. Y "printenv" es de lo primero que ejecuta cualquiera que
quiera saber donde ha entrado.

No es un alias de "env": "env VAR" trata VAR como una orden que ejecutar,
mientras que "printenv VAR" imprime su valor. Y printenv sale con 1 cuando la
variable no existe, sin escribir nada.

Como "env", solo ensena las variables EXPORTADAS. Las de shell ---UID, COLUMNS,
BASH_VERSION...--- existen pero no salen aqui, igual que en un Linux real.
"""

from __future__ import annotations

from cowrie.commands.coreutils_extra import bloque_version
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_printenv(HoneyPotCommand):
    def call(self) -> None:
        separador = "\n"
        nombres = []
        for arg in self.args:
            if arg in ("-0", "--null"):
                separador = "\0"
            elif arg == "--version":
                self.write(bloque_version(
                    "printenv",
                    "David MacKenzie and Richard Mlynarik"))
                return
            elif not arg.startswith("-"):
                nombres.append(arg)

        if not nombres:
            for nombre in self.environ:
                if nombre in self.exported:
                    self.write(f"{nombre}={self.environ[nombre]}{separador}")
            return

        # Con nombres, printenv imprime solo los que existen. Si no existe
        # ninguno, no escribe nada y sale con 1.
        encontrado = False
        for nombre in nombres:
            if nombre in self.exported and nombre in self.environ:
                self.write(f"{self.environ[nombre]}{separador}")
                encontrado = True
        if not encontrado:
            self.exit(1)


commands["printenv"] = Command_printenv
commands["/usr/bin/printenv"] = Command_printenv
commands["/bin/printenv"] = Command_printenv
