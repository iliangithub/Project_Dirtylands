# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_systemd_detect_virt(HoneyPotCommand):
    def call(self) -> None:
        # bare-metal: prints "none" and exits with status 1
        args = self.args
        if "-c" in args or "--container" in args:
            self.write("none\n")
        elif "-v" in args or "--vm" in args:
            self.write("none\n")
        else:
            self.write("none\n")


commands["systemd-detect-virt"] = Command_systemd_detect_virt
commands["/usr/bin/systemd-detect-virt"] = Command_systemd_detect_virt
