# SPDX-License-Identifier: BSD-3-Clause
"""
getconf para el senuelo.

El enlatado de Cowrie es un fichero con "32" dentro, y como un enlatado no ve
los argumentos, responde 32 a todo. En una maquina que dice x86_64 en uname, en
/proc/cpuinfo ("address sizes: 46 bits physical, 48 bits virtual") y en lscpu,
un LONG_BIT de 32 es una contradiccion directa. Y no es una curiosidad
academica: varios droppers de la familia Mirai/Gafgyt ejecutan
"getconf LONG_BIT" para elegir que binario descargar.
"""

from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}

# Valores de un Debian 13 amd64 con glibc 2.41.
VARIABLES = {
    "LONG_BIT": "64",
    "WORD_BIT": "32",
    "INT_MAX": "2147483647",
    "LONG_MAX": "9223372036854775807",
    "CHAR_BIT": "8",
    "PAGESIZE": "4096",
    "PAGE_SIZE": "4096",
    "_NPROCESSORS_CONF": "12",
    "_NPROCESSORS_ONLN": "12",
    "GNU_LIBC_VERSION": "glibc 2.41",
    "GNU_LIBPTHREAD_VERSION": "NPTL 2.41",
    "LFS_CFLAGS": "",
    "LFS_LDFLAGS": "",
    "LFS_LIBS": "",
    "POSIX_V7_ILP32_OFF32_CFLAGS": "undefined",
    "POSIX_V7_LP64_OFF64_CFLAGS": "-m64",
    "ARG_MAX": "2097152",
    "NAME_MAX": "255",
    "PATH_MAX": "4096",
    "OPEN_MAX": "1024",
    "CLK_TCK": "100",
    "PATH": "/bin:/usr/bin",
}


class Command_getconf(HoneyPotCommand):
    def call(self) -> None:
        args = [a for a in self.args if a not in ("-a", "--all")]
        todo = len(args) != len(self.args)

        if todo:
            for nombre, valor in VARIABLES.items():
                self.write(f"{nombre}{' ' * max(1, 32 - len(nombre))}{valor}\n")
            return

        if not args:
            # getconf a secas imprime su uso y sale con 1.
            self.errorWrite(
                "Usage: getconf [-v specification] variable_name [pathname]\n"
                "       getconf -a [pathname]\n"
            )
            return

        nombre = args[0]
        if nombre in VARIABLES:
            self.write(f"{VARIABLES[nombre]}\n")
        else:
            self.errorWrite(f"getconf: unrecognized variable '{nombre}'\n")


commands["getconf"] = Command_getconf
commands["/usr/bin/getconf"] = Command_getconf
commands["/bin/getconf"] = Command_getconf
