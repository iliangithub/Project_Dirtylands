# SPDX-FileCopyrightText: 2016 davegermiquet <davegermiquet@trulycanadian.net>
# SPDX-FileCopyrightText: 2016-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
python3 interpreter emulation, coherent with Debian 13 (trixie): Python 3.13.5
built with GCC 14.2.0. Debian ships no bare `python` binary, so only python3 /
python3.13 are registered here.
"""

from __future__ import annotations

import getopt

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand

commands = {}

PY_VERSION = "3.13.5"
PY_BUILD = "main, Jun 13 2026, 14:18:01"
PY_GCC = "GCC 14.2.0"
BANNER = (
    f"Python {PY_VERSION} ({PY_BUILD}) [{PY_GCC}] on linux\n"
    'Type "help", "copyright", "credits" or "license" for more information.\n'
)


class Command_python(HoneyPotCommand):
    interactive: bool = False

    def version(self) -> None:
        self.write(f"Python {PY_VERSION}\n")

    def help(self) -> None:
        output = (
            "usage: python3 [option] ... [-c cmd | -m mod | file | -] [arg] ...",
            "Options (and corresponding environment variables):",
            "-b     : issue warnings about converting bytes/bytearray to str",
            "-B     : don't write .pyc files on import; also PYTHONDONTWRITEBYTECODE=x",
            "-c cmd : program passed in as string (terminates option list)",
            "-E     : ignore PYTHON* environment variables (such as PYTHONPATH)",
            "-h     : print this help message and exit (also --help)",
            "-i     : inspect interactively after running script; forces a prompt even",
            "-m mod : run library module as a script (terminates option list)",
            "-O     : remove assert and __debug__-dependent statements",
            "-q     : don't print version and copyright messages on interactive startup",
            "-s     : don't add user site directory to sys.path",
            "-S     : don't imply 'import site' on initialization",
            "-u     : force the stdout and stderr streams to be unbuffered",
            "-v     : verbose (trace import statements); also PYTHONVERBOSE=x",
            "-V     : print the Python version number and exit (also --version)",
            "         when given twice, print more information about the build",
            "file   : program read from script file",
            "-      : program read from stdin (default; interactive mode if a tty)",
            "arg ...: arguments passed to program in sys.argv[1:]",
        )
        for line in output:
            self.write(line + "\n")

    def start(self) -> None:
        try:
            opts, args = getopt.gnu_getopt(
                self.args, "bBcdEhiIm:OqRsStuvVWx", ["help", "version"]
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"Unknown option: -{err.opt}\n")
            self.errorWrite(
                "usage: python3 [option] ... [-c cmd | -m mod | file | -] [arg] ...\n"
            )
            self.errorWrite("Try `python3 -h' for more information.\n")
            self.exit()
            return

        for o, _a in opts:
            if o in ("-V", "--version"):
                self.version()
                self.exit()
                return
            if o in ("-h", "--help"):
                self.help()
                self.exit()
                return

        # -c / -m consume the rest as a program; we cannot evaluate it, exit clean
        if any(o in ("-c", "-m") for o, _a in opts):
            self.exit()
            return

        for value in args:
            sourcefile = self.fs.resolve_path(value, self.protocol.cwd)
            if self.fs.exists(sourcefile) or value == "-":
                self.exit()
                return
            self.errorWrite(
                f"python3: can't open file '{self.protocol.cwd}/{value}': "
                "[Errno 2] No such file or directory\n"
            )
            self.exit()
            return

        # No file, no -c/-m: interactive REPL
        self.interactive = True
        self.write(BANNER)
        self.write(">>> ")

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="python",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )
        if not self.interactive:
            return
        stripped = line.strip()
        if stripped in ("exit()", "quit()", "exit", "quit"):
            self.exit()
            return
        # We do not evaluate code; present a fresh prompt like a live REPL.
        self.write(">>> ")

    def handle_CTRL_D(self) -> None:
        self.write("\n")
        self.exit()

    def eofReceived(self) -> None:
        self.exit()


commands["python3"] = Command_python
commands["/usr/bin/python3"] = Command_python
commands["python3.13"] = Command_python
commands["/usr/bin/python3.13"] = Command_python
