# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_nproc(HoneyPotCommand):
    def call(self) -> None:
        # 6 cores / 12 threads -> 12 online processors
        self.write("12\n")


commands["nproc"] = Command_nproc
commands["/usr/bin/nproc"] = Command_nproc
