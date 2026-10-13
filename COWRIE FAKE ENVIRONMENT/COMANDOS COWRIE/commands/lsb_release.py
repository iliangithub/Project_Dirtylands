# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}

DISTRIB_ID = "Debian"
DESCRIPTION = "Debian GNU/Linux 13 (trixie)"
RELEASE = "13"
CODENAME = "trixie"


class Command_lsb_release(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        short = "-s" in args or "--short" in args
        want = {"i": False, "d": False, "r": False, "c": False}
        show_all = False
        for a in args:
            if a in ("-a", "--all"):
                show_all = True
            elif a in ("-i", "--id"):
                want["i"] = True
            elif a in ("-d", "--description"):
                want["d"] = True
            elif a in ("-r", "--release"):
                want["r"] = True
            elif a in ("-c", "--codename"):
                want["c"] = True

        if show_all:
            for k in want:
                want[k] = True
        if not any(want.values()) and not show_all:
            # bare `lsb_release` prints nothing but a hint on stderr
            self.errorWrite("No LSB modules are available.\n")
            return

        def emit(label: str, value: str) -> None:
            if short:
                self.write(f"{value}\n")
            else:
                self.write(f"{label}\t{value}\n")

        if want["i"]:
            emit("Distributor ID:", DISTRIB_ID)
        if want["d"]:
            emit("Description:", DESCRIPTION)
        if want["r"]:
            emit("Release:", RELEASE)
        if want["c"]:
            emit("Codename:", CODENAME)


commands["lsb_release"] = Command_lsb_release
commands["/usr/bin/lsb_release"] = Command_lsb_release
