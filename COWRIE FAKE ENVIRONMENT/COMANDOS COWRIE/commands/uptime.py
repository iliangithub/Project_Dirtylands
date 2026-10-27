# SPDX-FileCopyrightText: 2009 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2016-2023 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import time

from cowrie.core import utils
from cowrie.shell.command import HoneyPotCommand

# The boot time lives in ONE place, base.py, and is imported here. Declared
# twice it is only a matter of time before one copy is edited and the other is
# not: uptime would then contradict `w`, `ps` and everything else that dates
# from boot, and nothing would flag it.
from cowrie.commands.base import IGNIS_BOOT_EPOCH as BOOT_EPOCH
from cowrie.commands.base import formato_uptime

commands = {}


UPTIME_USO = """
Usage:
 uptime [options]

Options:
 -p, --pretty   show uptime in pretty format
 -h, --help     display this help and exit
 -s, --since    system up since
 -V, --version  output version information and exit

For more details see uptime(1).
"""


def _bonito(segundos: float) -> str:
    """El "-p" de procps: "up 5 hours, 54 minutes"."""
    total = int(segundos // 60)
    semanas, resto = divmod(total, 60 * 24 * 7)
    dias, resto = divmod(resto, 60 * 24)
    horas, minutos = divmod(resto, 60)
    trozos = []
    for cuantos, singular in ((semanas, "week"), (dias, "day"),
                              (horas, "hour"), (minutos, "minute")):
        if cuantos:
            trozos.append("%d %s%s" % (cuantos, singular,
                                       "" if cuantos == 1 else "s"))
    return "up " + (", ".join(trozos) if trozos else "0 minutes")


class Command_uptime(HoneyPotCommand):
    def call(self) -> None:
        up = time.time() - BOOT_EPOCH

        # LAS BANDERAS NO SE MIRABAN: "uptime -p" y "uptime -s" contestaban la
        # linea larga de siempre. La primera es de las que mas se teclean para
        # saber cuanto lleva viva una maquina, y una que conteste otra cosa se
        # nota a la primera.
        for a in self.args:
            if a in ("-p", "--pretty"):
                self.write(_bonito(up) + "\n")
                return
            if a in ("-s", "--since"):
                self.write(time.strftime("%Y-%m-%d %H:%M:%S",
                                         time.localtime(BOOT_EPOCH)) + "\n")
                return
            if a in ("-h", "--help"):
                self.write(UPTIME_USO)
                return
            if a in ("-V", "--version"):
                self.write("uptime from procps-ng 4.0.4\n")
                return
            if a.startswith("--"):
                self.errorWrite("uptime: unrecognized option '%s'\n" % a)
                self.errorWrite(UPTIME_USO)
                self.exit_code = 1
                return
            if a.startswith("-") and len(a) > 1:
                self.errorWrite("uptime: invalid option -- '%s'\n" % a[1])
                self.errorWrite(UPTIME_USO)
                self.exit_code = 1
                return
        # UN ESPACIO DELANTE DE LA HORA Y UNO SOLO ANTES DEL "up". Habia dos
        # antes del "up" y ninguno al principio, asi que esta misma linea NO
        # coincidia con la que saca "w" ---que si los tenia--- ni con la de
        # "top". Medido: " 10:54:24 up  2:39,  0 users,  load average: ...".
        self.write(
            " {} up {},  1 user,  load average: 0.00, 0.01, 0.00\n".format(
                time.strftime("%H:%M:%S"), formato_uptime(up)
            )
        )


commands["/usr/bin/uptime"] = Command_uptime
commands["uptime"] = Command_uptime
