# SPDX-FileCopyrightText: 2009 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2024-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Implements bash/sh shell command for cowrie honeypot.
# ABOUTME: Handles -c flags, piped input, script file execution, and interactive shells.

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from twisted.internet import error
from twisted.python import failure

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound
from cowrie.shell.honeypot import HoneyPotShell

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}

MAX_SCRIPT_DEPTH = 5
_SHEBANG_RE = re.compile(r"^#!\s*/bin/(ba)?sh")


def _su_pop_restore(protocol) -> bool:
    """Si hay identidad apilada por 'su', la restaura y devuelve True (no cerrar)."""
    stack = getattr(protocol, "_su_stack", None)
    if not stack:
        return False
    username, uid, gid, home, cwd = stack.pop()
    for obj in (protocol.user, getattr(protocol.user, "avatar", None)):
        if obj is None:
            continue
        for attr, val in (("username", username), ("uid", uid), ("gid", gid), ("home", home)):
            try:
                setattr(obj, attr, val)
            except Exception:
                pass
    protocol.cwd = cwd
    return True


class Command_sh(HoneyPotCommand):
    # /bin/sh EN DEBIAN NO ES BASH, ES dash. Cowrie registraba las cuatro
    # rutas ---sh, bash, /bin/sh, /bin/bash--- en esta misma clase, asi que
    # `sh` abria una shell identica a la de la sesion: mismo prompt, mismos
    # mensajes de error. Desde fuera parecia que la orden no hacia NADA, y de
    # hecho eso es lo que se veia: el prompt no cambiaba. Un `sh` de verdad
    # baja a "$ " a secas. Ver Command_dash, aqui abajo.
    DASH = False

    def start(self) -> None:
        if self.args and self.args[0].strip() == "-c":
            line = " ".join(self.args[1:])

            # it might be sh -c 'echo "sometext"', so don't use line.strip('\'\"')
            if (line[0] == "'" and line[-1] == "'") or (
                line[0] == '"' and line[-1] == '"'
            ):
                line = line[1:-1]

            self.execute_commands(line)
            self.exit()

        elif self.input_data:
            self.execute_commands(self.input_data.decode("utf8"))
            self.exit()

        elif self.args and not self.args[0].startswith("-"):
            self.execute_script_file(self.args[0])
            self.exit()

        else:
            self.interactive_shell()

    def execute_script_file(self, filename: str) -> None:
        depth = getattr(self.protocol, "_script_depth", 0)
        if depth >= MAX_SCRIPT_DEPTH:
            self.errorWrite(f"-bash: {filename}: too many levels of recursion\n")
            return

        path = self.fs.resolve_path(filename, self.protocol.cwd)
        try:
            contents = self.fs.file_contents(path)
        except (FileNotFound, FileNotFoundError):
            self.errorWrite(f"bash: {filename}: No such file or directory\n")
            return

        lines = contents.decode("utf-8", errors="replace").splitlines()
        # Strip shebang line
        if lines and _SHEBANG_RE.match(lines[0]):
            lines = lines[1:]
        # Strip comment-only lines and blank lines
        lines = [line for line in lines if line.strip() and not line.strip().startswith("#")]

        if not lines:
            return

        self.protocol._script_depth = depth + 1
        try:
            # SE UNEN CON SALTO DE LINEA, NO CON ';'. Un `for ... done` solo se
            # expande si el `for` esta al principio de su linea, y juntandolas
            # con ';' se quedaba en medio y salia "for: command not found".
            # shell/honeypot.py las ejecuta de una en una. Ver alli.
            self.execute_commands("\n".join(lines))
        finally:
            self.protocol._script_depth = depth

    def execute_commands(self, cmds: str) -> None:
        # self.input_data holds commands passed via PIPE
        # create new HoneyPotShell for our a new 'sh' shell
        shell = HoneyPotShell(self.protocol, interactive=False,
                              dash=self.DASH)
        self.protocol.cmdstack.append(shell)

        # call lineReceived method that indicates that we have some commands to parse
        shell.lineReceived(cmds)

        # Se quita POR IDENTIDAD, y solo si sigue ahi. Antes habia un pop() a
        # ciegas: ahora el shell se saca solo en _finish() al vaciar su cola,
        # asi que el pop() se llevaria lo que hubiera encima ---este mismo
        # comando bash, o un wget aun en vuelo--- y el exit() de despues
        # petaba con "list.remove(x): x not in list".
        if shell in self.protocol.cmdstack:
            self.protocol.cmdstack.remove(shell)

    def interactive_shell(self) -> None:
        parentshell = self.protocol.cmdstack[-2]
        # A sub-shell launched from a non-interactive parent (pipe, redirect, or
        # command substitution) will never have a terminal feeding its stdin, so
        # spawning an interactive shell would leak it on the cmdstack and write a
        # prompt into captured output via showPrompt(). Behave like EOF instead.
        if not getattr(parentshell, "interactive", True):
            self.exit()
            return
        shell = HoneyPotShell(self.protocol, interactive=True, dash=self.DASH)
        # TODO: copy more variables, but only exported variables
        try:
            shell.environ["SHLVL"] = str(int(parentshell.environ["SHLVL"]) + 1)
        except KeyError:
            shell.environ["SHLVL"] = "1"
        self.protocol.cmdstack.append(shell)
        self.protocol.cmdstack.remove(self)
        # El primer prompt lo pinta quien crea la shell, no su constructor:
        # asi lo hace Cowrie con la shell de la sesion, y hacerlo en los dos
        # sitios es lo que provocaba el prompt duplicado al entrar.
        shell.showPrompt()


commands["/bin/bash"] = Command_sh
commands["bash"] = Command_sh


class Command_dash(Command_sh):
    """/bin/sh, que en Debian es un enlace a dash.

    Lo que cambia respecto de bash esta MEDIDO contra dash 0.5.12 ---el de
    trixie--- en un pseudo-terminal, no recordado:

        $ echo $PS1        ->  $            (y "# " siendo root)
        $ echo hola        ->  hola         (esta es la linea 1)
        $ asd              ->  sh: 2: asd: not found

    El numero de linea INCREMENTA y cuenta tambien las ordenes que funcionan;
    de ahi que un fallo detras de un `echo` correcto salga como la 2.

    QUE SIGUE SIN SER IGUAL, y esta medido pero no emulado: dash no tiene
    edicion de linea. La flecha arriba no trae el historial, escribe "^[[A" en
    pantalla y esos bytes acaban en la orden. Aqui las flechas simplemente no
    hacen nada, que se parece mas a dash que traer el historial de bash, pero
    no es lo mismo. Esta anotado en el 3.4.2.8 del README.
    """

    DASH = True


commands["/bin/sh"] = Command_dash
commands["sh"] = Command_dash
commands["/bin/dash"] = Command_dash
commands["/usr/bin/dash"] = Command_dash
commands["dash"] = Command_dash


class Command_exit(HoneyPotCommand):
    def call(self) -> None:
        # si venimos de un 'su', volver al usuario anterior en vez de cerrar
        if _su_pop_restore(self.protocol):
            return

        # EL NUMERO DE "exit N" CUENTA, y aqui se tiraba. Se veia dentro de un
        # parentesis, que es donde el shell no se muere y alguien puede
        # preguntar:
        #
        #     (exit 7); echo $?    -> decia 0, bash dice 7
        #
        # El estado se le pone al shell de DEBAJO ---el que lanzo este
        # comando--- antes de sacarlo de la pila, porque es de quien lo lee
        # despues _execute_single_command_with_redirect().
        estado = None
        if self.args:
            crudo = self.args[0]
            try:
                # Sale por una puerta de ocho bits: "exit 300" da 44 y
                # "exit -1" da 255. Medido en bash.
                estado = int(crudo, 10) % 256
            except ValueError:
                self.errorWrite("-bash: exit: %s: numeric argument required\n"
                                % crudo)
                estado = 2
        # El estado viaja por exit_code, que es el puente que ya existe:
        # command.exit() se lo pasa al shell como last_exit_code y resume() lo
        # copia a last_status, que es lo que leen "$?" y el corto de && y ||.
        # Ponerlo a mano en last_status no sirve: resume() lo pisa despues.
        padre = (self.protocol.cmdstack[-2]
                 if len(self.protocol.cmdstack) >= 2 else None)
        if estado is None and padre is not None:
            # "exit" a secas se lleva el estado del ultimo comando, que es por
            # lo que "(false; exit)" da 1 y no 0. Medido en bash.
            #
            # Dentro de un parentesis NO vale mirar el shell de al lado: cada
            # orden de un "(a; b)" corre en el suyo, asi que el de "exit" no
            # ha visto lo que hizo "a". Lo lleva el bucle que los lanza.
            if not getattr(padre, "interactive", True):
                estado = getattr(self.protocol, "_estado_en_curso", 0)
            else:
                estado = getattr(padre, "last_status", 0)
        if estado is not None:
            self.exit_code = estado

        # DENTRO DE UN PARENTESIS, "exit" CIERRA EL PARENTESIS Y NADA MAS.
        #
        # Sacar el shell de la pila aqui, como se hacia siempre, tiene un
        # efecto que no se ve leyendo esto: al terminar el comando, Cowrie
        # reanuda al que quede ENCIMA de la pila. Si le hemos quitado el
        # subshell, el que queda es el shell de la sesion, y se pone a
        # ejecutar lo que venia detras del parentesis ANTES de que el
        # parentesis haya devuelto su estado. Por eso "(exit 7); echo $?"
        # imprimia 0: el echo corria primero.
        #
        # Se le vacia la cola y se deja que termine solo, que es como acaba
        # cualquier subshell: _finish() lo saca de la pila cuando no le queda
        # nada, y el estado ya esta puesto para quien lo lea.
        if padre is not None and not getattr(padre, "interactive", True):
            padre.cmdpending = []
            padre.lineas_de_guion = []
            # Y que no siga lo que venga detras DENTRO del parentesis: cada
            # orden de un "(a; b; c)" corre en su propio shell, asi que
            # vaciarle la cola a este no para a los siguientes. La bandera la
            # mira el bucle que los lanza.
            self.protocol._salir_subshell = True
            return

        # this removes the second last command, which is the shell
        self.protocol.cmdstack.pop(-2)
        if len(self.protocol.cmdstack) < 2:
            stat = failure.Failure(error.ProcessDone(status=""))
            self.protocol.terminal.transport.processEnded(stat)


commands["exit"] = Command_exit
commands["logout"] = Command_exit
