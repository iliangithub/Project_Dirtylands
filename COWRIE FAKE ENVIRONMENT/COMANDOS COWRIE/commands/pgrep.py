# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import os

from cowrie.shell.command import HoneyPotCommand

commands = {}


def _procs(self):
    try:
        return list(self.protocol.user.server.process or [])
    except Exception:
        return []


def _basename(cmd: str) -> str:
    c = cmd.strip()
    if c.startswith("["):
        return c.strip("[]").split("/")[0]
    first = c.split()[0] if c.split() else c
    return os.path.basename(first)


class Command_pgrep(HoneyPotCommand):
    def call(self) -> None:
        pats = [a for a in self.args if not a.startswith("-")]
        list_name = "-l" in self.args
        full = "-f" in self.args
        if not pats:
            self.errorWrite("pgrep: no matching criteria specified\nTry `pgrep --help' for more information.\n")
            return
        pat = pats[0]
        found = False
        for p in _procs(self):
            hay = str(p["COMMAND"]) if full else _basename(str(p["COMMAND"]))
            if pat in hay:
                found = True
                if list_name:
                    self.write(f"{p['PID']} {_basename(str(p['COMMAND']))}\n")
                else:
                    self.write(f"{p['PID']}\n")
        if not found:
            self.exit()


class Command_pidof(HoneyPotCommand):
    def call(self) -> None:
        names = [a for a in self.args if not a.startswith("-")]
        if not names:
            return
        target = os.path.basename(names[0])
        pids = []
        for p in _procs(self):
            if _basename(str(p["COMMAND"])) == target:
                pids.append(str(p["PID"]))
        if pids:
            self.write(" ".join(reversed(pids)) + "\n")


commands["pgrep"] = Command_pgrep
commands["/usr/bin/pgrep"] = Command_pgrep
commands["pidof"] = Command_pidof
commands["/bin/pidof"] = Command_pidof
commands["/usr/bin/pidof"] = Command_pidof
