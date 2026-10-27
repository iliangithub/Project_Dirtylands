# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: env de coreutils: lista el entorno, o EJECUTA algo con otro entorno.
# ABOUTME: El de la imagen solo sabia listar, y se tragaba todo lo demas.
#
# El de la imagen ignoraba los argumentos: "env -i echo hola" volcaba el
# entorno entero en vez de imprimir "hola", y "env A=1 cmd" hacia lo mismo. Es
# la forma normal de arrancar algo con el entorno limpio ---la usa cualquier
# guion de instalacion, y tambien quien quiere que su binario no herede
# variables--- asi que la orden se perdia y el guion seguia creyendo que la
# habia ejecutado.
from __future__ import annotations

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}

AYUDA = """Usage: env [OPTION]... [-] [NAME=VALUE]... [COMMAND [ARG]...]
Set each NAME to VALUE in the environment and run COMMAND.

Mandatory arguments to long options are mandatory for short options too.
  -i, --ignore-environment  start with an empty environment
  -0, --null           end each output line with NUL, not newline
  -u, --unset=NAME     remove variable from the environment
  -C, --chdir=DIR      change working directory to DIR
      --help        display this help and exit
      --version     output version information and exit

A mere - implies -i.  If no COMMAND, print the resulting environment.
"""


class Command_env(FallaAlAvisar, HoneyPotCommand):
    CODIGO_DE_FALLO = 125

    def call(self) -> None:
        from cowrie.commands.bashbuiltins import _relanzar
        from cowrie.commands.coreutils_extra import bloque_version

        limpio = False
        quitar: list[str] = []
        asignaciones: list[tuple[str, str]] = []
        orden: list[str] = []
        i = 0
        args = list(self.args)
        while i < len(args):
            a = args[i]
            if orden:
                orden.append(a)
            elif a == "--help":
                self.write(AYUDA)
                return
            elif a == "--version":
                self.write(bloque_version(
                    "env", "Richard Mlynarik, David MacKenzie, and Assaf Gordon"))
                return
            elif a in ("-i", "--ignore-environment", "-"):
                limpio = True
            elif a == "-u":
                i += 1
                if i < len(args):
                    quitar.append(args[i])
            elif a.startswith("--unset="):
                quitar.append(a.split("=", 1)[1])
            elif a.startswith("--"):
                self.errorWrite("env: unrecognized option '%s'\n" % a)
                self.errorWrite("Try 'env --help' for more information.\n")
                return
            elif "=" in a and not a.startswith("-"):
                nombre, valor = a.split("=", 1)
                asignaciones.append((nombre, valor))
            else:
                orden.append(a)
            i += 1

        entorno = {} if limpio else {
            n: v for n, v in self.environ.items() if n in self.exported}
        for nombre in quitar:
            entorno.pop(nombre, None)
        for nombre, valor in asignaciones:
            entorno[nombre] = valor

        if not orden:
            for nombre, valor in entorno.items():
                self.write(f"{nombre}={valor}\n")
            return

        # CON ORDEN, env EJECUTA. El entorno se cambia solo mientras dura, que
        # es lo que promete: al volver se deja como estaba.
        antes = dict(self.environ)
        try:
            self.environ.clear()
            self.environ.update(entorno)
            _relanzar(self, " ".join(orden))
        finally:
            self.environ.clear()
            self.environ.update(antes)


commands["/usr/bin/env"] = Command_env
commands["env"] = Command_env
