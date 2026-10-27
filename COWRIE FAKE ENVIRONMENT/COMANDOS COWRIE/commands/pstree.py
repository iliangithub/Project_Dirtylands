# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

# EL DIBUJO VA EN ASCII, y no es una limitacion: es lo que saca el de verdad.
# pstree elige los caracteres segun el LOCALE, y la sesion del senuelo no
# exporta LANG ni ningun LC_* ---se comprobo midiendo un login real de Debian
# 13--- asi que corre en POSIX. Medido en un trixie 13.6:
#
#     LC_ALL=C        pstree(1829)-+-sleep(1835)
#                                  `-sleep(1836)
#     LC_ALL=C.UTF-8  pstree───2*[sleep]
#
# Si algun dia el entorno del login pasa a exportar un LANG UTF-8, esto hay
# que rehacerlo ---y hay una prueba que ata las dos cosas para que no se
# separen en silencio---.
commands = {}

TREE = """systemd-+-NetworkManager
        |-PM2 v5.3.0: God---12*[{PM2 v5.3.0: G}]
        |-agetty
        |-cron
        |-dbus-daemon
        |-node---11*[{node}]
        |-rsyslogd---3*[{rsyslogd}]
        |-sshd---sshd---sshd---bash---pstree
        |-systemd---(sd-pam)
        |-systemd-journal
        |-systemd-logind
        |-systemd-resolve
        |-systemd-timesyn
        `-systemd-udevd
"""


class Command_pstree(HoneyPotCommand):
    def call(self) -> None:
        self.write(TREE)


commands["pstree"] = Command_pstree
commands["/usr/bin/pstree"] = Command_pstree
