# SPDX-FileCopyrightText: 2020 Peter Šufliarsky
# SPDX-FileCopyrightText: 2020 Peter Sufliarsky <sufliarskyp@gmail.com>
# SPDX-FileCopyrightText: 2021-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import re

from cowrie.shell import fs
from cowrie.commands.coreutils_extra import bloque_version
from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}

CHMOD_HELP = """Usage: chmod [OPTION]... MODE[,MODE]... FILE...
  or:  chmod [OPTION]... OCTAL-MODE FILE...
  or:  chmod [OPTION]... --reference=RFILE FILE...
Change the mode of each FILE to MODE.
With --reference, change the mode of each FILE to that of RFILE.

  -c, --changes          like verbose but report only when a change is made
  -f, --silent, --quiet  suppress most error messages
  -v, --verbose          output a diagnostic for every file processed
      --no-preserve-root  do not treat '/' specially (the default)
      --preserve-root    fail to operate recursively on '/'
      --reference=RFILE  use RFILE's mode instead of MODE values
  -R, --recursive        change files and directories recursively
      --help     display this help and exit
      --version  output version information and exit

Each MODE is of the form '[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation at: <https://www.gnu.org/software/coreutils/chmod>
or available locally via: info '(coreutils) chmod invocation'
"""

CHMOD_AUTORES = "David MacKenzie and Jim Meyering"

MODE_REGEX = "^[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=]?[0-7]+$"
TRY_CHMOD_HELP_MSG = "Try 'chmod --help' for more information.\n"

NO_PERM_BITS_MASK = 0o000


# --- El modo SIMBOLICO ------------------------------------------------------
#
# "chmod u+x fichero" no hacia nada. El propio codigo lo decia en un
# comentario ---"this works for `chmod 0600 ./file`, but not for
# `chmod u+rwx ./file`"--- y el int(mode, 8) lanzaba ValueError que se
# tragaba un "pass". O sea que el permiso NO cambiaba y chmod no protestaba:
# el atacante creia haber hecho ejecutable su binario y "ls -l" seguia
# diciendo que no. Es de lo que mas se teclea despues de una descarga.
_QUIEN = {"u": 6, "g": 3, "o": 0}
_QUE = {"r": 4, "w": 2, "x": 1}


def aplica_simbolico(actual: int, mode: str, es_dir: bool) -> int:
    """El modo resultante de aplicar "u+x", "a-w", "go=r"... al que ya hay."""
    for trozo in mode.split(","):
        m = re.fullmatch(r"([ugoa]*)([-+=])([rwxXst]*)", trozo)
        if not m:
            continue
        quienes, op, letras = m.group(1) or "a", m.group(2), m.group(3)
        if "a" in quienes:
            quienes = "ugo"
        # La X mayuscula solo pone la x si ya la tiene alguien, o si es un
        # directorio: es lo que hace util el "chmod -R a+rX".
        letras = letras.replace("X", "x" if (es_dir or actual & 0o111) else "")
        bits = sum(_QUE[c] for c in letras if c in _QUE)
        for quien in quienes:
            desplaza = _QUIEN[quien]
            if op == "+":
                actual |= bits << desplaza
            elif op == "-":
                actual &= ~(bits << desplaza)
            else:
                actual = (actual & ~(0o7 << desplaza)) | (bits << desplaza)
        if "s" in letras:
            actual |= (0o4000 if "u" in quienes else 0) | \
                      (0o2000 if "g" in quienes else 0)
        if "t" in letras:
            actual |= 0o1000
    return actual


class Command_chmod(FallaAlAvisar, HoneyPotCommand):
    """chmod, con el CODIGO DE SALIDA que le faltaba.

    El original escribe el error y vuelve, pero nunca toca `exit_code`, asi
    que un `chmod` que ha fallado sale con 0. Eso rompe en silencio el patron
    mas repetido de los guiones de Mirai:

        chmod 777 i ||(cp /bin/ls ii;cat i>ii &&rm i;cp ii i;rm ii);./i

    Ahi el `||` es el plan B para cuando la maquina no tiene chmod: se copia
    /bin/ls, que YA es ejecutable, y se le vuelca el binario encima para
    heredar sus permisos. Con el codigo de salida siempre a 0 esa rama no se
    ejecutaba nunca, y el senuelo se comportaba como una maquina donde chmod
    siempre funciona, incluso sobre un fichero que no existe.

    Los codigos son los de chmod(1): 0 si se pudo con todos, 1 si fallo
    alguno. --help y --version salen con 0.
    """

    def call(self) -> None:
        # parse the command line arguments
        opts, mode, files, getopt_err = self.parse_args()
        if getopt_err:
            self.exit_code = 1
            return

        # if --help or --version is present, we don't care about the rest
        for o, _ in opts:
            if o == "--help":
                # Por la SALIDA, no por el error: "chmod --help >/dev/null" no
                # ensena nada en un Debian de verdad, y con errorWrite lo
                # ensenaba entero.
                self.write(CHMOD_HELP)
                return
            if o == "--version":
                self.write(bloque_version("chmod", CHMOD_AUTORES))
                return

        # check for presence of mode and files in arguments
        if (not mode or mode.startswith("-")) and not files:
            self.errorWrite("chmod: missing operand\n" + TRY_CHMOD_HELP_MSG)
            self.exit_code = 1
            return
        if mode and not files:
            self.errorWrite(f"chmod: missing operand after ‘{mode}’\n" + TRY_CHMOD_HELP_MSG)
            self.exit_code = 1
            return

        # mode has to match the regex
        if not re.fullmatch(MODE_REGEX, mode):
            self.errorWrite(f"chmod: invalid mode: ‘{mode}’\n" + TRY_CHMOD_HELP_MSG)
            self.exit_code = 1
            return

        # go through the list of files and check whether they exist
        for file in files:
            if file == "*":
                # if the current directory is empty, return 'No such file or directory'
                files = self.fs.get_path(self.protocol.cwd)[:]
                if not files:
                    self.errorWrite("chmod: cannot access '*': No such file or directory\n")
                    self.exit_code = 1
            else:
                path = self.fs.resolve_path(file, self.protocol.cwd)
                if not self.fs.exists(path):
                    self.errorWrite(
                        f"chmod: cannot access '{file}': No such file or directory\n"
                    )
                    self.exit_code = 1
                else:
                    f = self.fs.getfile(path)
                    file_mode_no_perm = f[fs.A_MODE] & NO_PERM_BITS_MASK
                    try:
                        f[fs.A_MODE] = file_mode_no_perm | int(mode, 8)
                    except ValueError:
                        # No era octal: es simbolico, y ese SI se aplica ahora.
                        # Se parte de los permisos que ya tiene, que es de lo
                        # que habla un "+x".
                        f[fs.A_MODE] = file_mode_no_perm | aplica_simbolico(
                            f[fs.A_MODE] & 0o7777, mode,
                            f[fs.A_TYPE] == fs.T_DIR)

    def parse_args(self):
        mode = None

        # a mode specification starting with '-' would cause the getopt parser to throw an error
        # therefore, remove the first such argument self.args before parsing with getopt
        args_new = []
        for arg in self.args:
            if not mode and arg.startswith("-") and re.fullmatch(MODE_REGEX, arg):
                mode = arg
            else:
                args_new.append(arg)

        # parse the command line options with getopt
        try:
            opts, args = getopt.gnu_getopt(
                args_new,
                "cfvR",
                [
                    "changes",
                    "silent",
                    "quiet",
                    "verbose",
                    "no-preserve-root",
                    "preserve-root",
                    "reference=",
                    "recursive",
                    "help",
                    "version",
                ],
            )
        except getopt.GetoptError as err:
            failed_opt = err.msg.split(" ")[1]
            if failed_opt.startswith("--"):
                self.errorWrite(
                    f"chmod: unrecognized option '--{err.opt}'\n" + TRY_CHMOD_HELP_MSG
                )
            else:
                self.errorWrite(
                    f"chmod: invalid option -- '{err.opt}'\n" + TRY_CHMOD_HELP_MSG
                )
            return [], None, [], True

        # if mode was not found before, use the first arg as mode
        if not mode and len(args) > 0:
            mode = args.pop(0)

        # the rest of args should be files
        files = args

        return opts, mode, files, False


commands["/bin/chmod"] = Command_chmod
commands["chmod"] = Command_chmod
