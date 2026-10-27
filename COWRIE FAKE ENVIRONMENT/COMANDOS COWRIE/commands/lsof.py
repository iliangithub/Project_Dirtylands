# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_lsof(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        user = self.protocol.user.username
        client = self.protocol.clientIP
        # network view
        if any(a.startswith("-i") for a in args):
            self.write(
                "COMMAND   PID    USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            )
            self.write(
                "sshd      682    root    3u  IPv4  15243      0t0  TCP *:ssh (LISTEN)\n"
            )
            self.write(
                "sshd      682    root    4u  IPv6  15245      0t0  TCP *:ssh (LISTEN)\n"
            )
            self.write(
                f"sshd    48219 {user:>7}   4u  IPv4  92831      0t0  TCP 198.51.100.146:ssh->{client}:54122 (ESTABLISHED)\n"
            )
            return
        # default: as a non-root user, lsof is largely restricted
        self.write("COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF     NODE NAME\n")
        self.write(f"bash    48230 {user:>6}  cwd    DIR    8,1     4096   {abs(hash(user)) % 500000 + 100000} /home/{user}\n")
        self.write(f"bash    48230 {user:>6}  rtd    DIR    8,1     4096        2 /\n")
        self.write(f"bash    48230 {user:>6}  txt    REG    8,1  1265648   131079 /usr/bin/bash\n")
        self.write(f"bash    48230 {user:>6}    0u   CHR  136,0      0t0        3 /dev/pts/0\n")
        self.write(f"bash    48230 {user:>6}    1u   CHR  136,0      0t0        3 /dev/pts/0\n")
        self.write(f"bash    48230 {user:>6}    2u   CHR  136,0      0t0        3 /dev/pts/0\n")


commands["lsof"] = Command_lsof
commands["/usr/bin/lsof"] = Command_lsof
