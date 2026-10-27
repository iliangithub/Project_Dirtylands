# SPDX-License-Identifier: BSD-3-Clause
"""
Emulation of GNU bash 5.x shell builtins for Debian 13, so they behave like a
real shell instead of returning "command not found". Messages are in English
(locale C), matching a datacenter Debian install.
"""
from __future__ import annotations

import os

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

commands = {}

# Builtins listed by `enable` (alphabetical), i.e. real bash 5.2 enabled builtins
ENABLED_BUILTINS = [
    ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd",
    "command", "compgen", "complete", "compopt", "continue", "declare", "dirs",
    "disown", "echo", "enable", "eval", "exec", "exit", "export", "false", "fc",
    "fg", "getopts", "hash", "help", "history", "jobs", "kill", "let", "local",
    "logout", "mapfile", "popd", "printf", "pushd", "pwd", "read", "readarray",
    "readonly", "return", "set", "shift", "shopt", "source", "suspend", "test",
    "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias",
    "unset", "wait",
]
BUILTINS = set(ENABLED_BUILTINS)
KEYWORDS = {
    "if", "then", "else", "elif", "fi", "case", "esac", "for", "select",
    "while", "until", "do", "done", "in", "function", "time", "{", "}", "!",
    "[[", "]]", "coproc",
}


def _path_lookup(cmd, environ, fs):
    """Return the first PATH directory hit for cmd, or None."""
    for p in environ.get("PATH", "/usr/bin:/bin").split(":"):
        if not p:
            continue
        candidate = fs.resolve_path(cmd, p)
        try:
            if fs.exists(candidate) and not fs.isdir(candidate):
                return f"{p.rstrip('/')}/{cmd}"
        except Exception:
            pass
    return None


class Command_type(HoneyPotCommand):
    resolve_args = False

    def call(self) -> None:
        args = [a for a in self.args if a]
        only_type = "-t" in args
        path_only = "-p" in args
        names = [a for a in args if not a.startswith("-")]
        if not names:
            return
        aliases = getattr(self.protocol, "aliases", {}) or {}
        for name in names:
            # El alias gana sobre todo lo demas, que es el orden de bash.
            if name in aliases:
                if only_type:
                    self.write("alias\n")
                elif not path_only:
                    self.write("%s is aliased to `%s'\n" % (name, aliases[name]))
            elif name in KEYWORDS:
                if only_type:
                    self.write("keyword\n")
                elif not path_only:
                    self.write(f"{name} is a shell keyword\n")
            elif name in BUILTINS:
                if only_type:
                    self.write("builtin\n")
                elif not path_only:
                    self.write(f"{name} is a shell builtin\n")
            else:
                hit = _path_lookup(name, self.environ, self.fs)
                if hit:
                    if only_type:
                        self.write("file\n")
                    else:
                        self.write(f"{name} is {hit}\n")
                else:
                    if not only_type:
                        self.errorWrite(f"-bash: type: {name}: not found\n")


commands["type"] = Command_type


class Command_enable(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        names = [a for a in args if not a.startswith("-")]
        if not names:
            for b in ENABLED_BUILTINS:
                self.write(f"enable {b}\n")
            return
        # enable/disable a specific builtin: silently accept known builtins
        for n in names:
            if n not in BUILTINS:
                self.errorWrite(f"-bash: enable: {n}: not a shell builtin\n")


commands["enable"] = Command_enable


class Command_hash(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        if "-r" in args or "-d" in args or "-p" in args:
            return
        names = [a for a in args if not a.startswith("-")]
        if names:
            # hashing a command name: silent unless not found
            for n in names:
                if not _path_lookup(n, self.environ, self.fs) and n not in BUILTINS:
                    self.errorWrite(f"-bash: hash: {n}: not found\n")
            return
        self.write("hash: hash table empty\n")


commands["hash"] = Command_hash


# --- test / [ ---------------------------------------------------------------
#
# ANTES NO EVALUABA NADA: devolvia 0 siempre. El comentario que habia lo daba
# por bueno diciendo que "el codigo de salida no se observa", y eso dejo de
# ser cierto cuando resume() empezo a llevar el codigo de cada comando a
# last_status. Con esto:
#
#     [ -f /noexiste ] && rm -rf /   ->  la rama se cumplia SIEMPRE
#     if [ -d /tmp ]; then ...       ->  daba igual lo que hubiera
#
# O sea que cualquier guion que preguntara algo tomaba siempre la rama del
# "si". Todo lo de aqui esta medido contra el "[" de bash 5.2 en Debian 13.
_UNARIOS_FICHERO = {"-e", "-f", "-d", "-r", "-w", "-x", "-s", "-L", "-h",
                    "-b", "-c", "-p", "-S", "-g", "-u", "-k"}
_COMPARA_NUM = {
    "-eq": lambda a, b: a == b, "-ne": lambda a, b: a != b,
    "-lt": lambda a, b: a < b, "-le": lambda a, b: a <= b,
    "-gt": lambda a, b: a > b, "-ge": lambda a, b: a >= b,
}


class Command_test(HoneyPotCommand):
    """test / [ : evalua de verdad y deja el codigo de salida."""

    NOMBRE = "test"

    def _nodo(self, ruta: str):
        entera = self.fs.resolve_path(ruta, self.protocol.cwd)
        try:
            return self.fs.getfile(entera)
        except Exception:                                      # noqa: BLE001
            return None

    def _unario(self, op: str, valor: str) -> bool:
        if op == "-z":
            return valor == ""
        if op == "-n":
            return valor != ""
        if op not in _UNARIOS_FICHERO:
            return bool(valor)
        entera = self.fs.resolve_path(valor, self.protocol.cwd)
        if op in ("-L", "-h"):
            try:
                return bool(self.fs.islink(entera))
            except Exception:                                  # noqa: BLE001
                return False
        try:
            existe = self.fs.exists(entera)
        except Exception:                                      # noqa: BLE001
            existe = False
        if not existe:
            return False
        if op == "-e":
            return True
        if op == "-d":
            return bool(self.fs.isdir(entera))
        if op == "-f":
            return bool(self.fs.isfile(entera))
        if op == "-s":
            nodo = self._nodo(valor)
            return bool(nodo and nodo[fs.A_SIZE] > 0)
        if op in ("-r", "-w", "-x"):
            # Los permisos se miran de verdad, con el uid de la sesion. Un
            # "-x" que dijera que si sobre cualquier cosa haria que un
            # "[ -x /tmp/lo-que-sea ] && ./eso" se lanzara siempre.
            nodo = self._nodo(valor)
            if nodo is None:
                return False
            # El comprobador de permisos vive en fs.py, que es quien ya lo
            # usa para cat, less y compania: se importa aqui dentro para no
            # cruzar los dos modulos al cargarse.
            from cowrie.commands.fs import _cowrie_access_denied
            return not _cowrie_access_denied(
                self.fs, self.fs.resolve_path(valor, self.protocol.cwd),
                getattr(self.protocol.user, "uid", 0),
                getattr(self.protocol.user, "gid", 0),
                {"-r": "r", "-w": "w", "-x": "x"}[op])
        # -b -c -p -S -g -u -k: el senuelo no distingue esos tipos ni esos
        # bits, y decir que si seria peor que decir que no.
        return False

    def _binario(self, izq: str, op: str, der: str) -> bool:
        if op in ("=", "=="):
            return izq == der
        if op == "!=":
            return izq != der
        if op == "<":
            return izq < der
        if op == ">":
            return izq > der
        if op in _COMPARA_NUM:
            try:
                return _COMPARA_NUM[op](int(izq), int(der))
            except ValueError:
                self.errorWrite("-bash: %s: integer expression expected\n"
                                % (izq if not izq.lstrip("-").isdigit()
                                   else der))
                raise _ErrorTest from None
        if op in ("-ef", "-nt", "-ot"):
            return False
        raise _ErrorTest

    def _evalua(self, args: list) -> bool:
        if not args:
            return False
        if args[0] == "!":
            return not self._evalua(args[1:])
        # -a y -o: estan obsoletos pero se siguen tecleando.
        for marca, junta in (("-o", any), ("-a", all)):
            if marca in args:
                i = args.index(marca)
                return junta([self._evalua(args[:i]),
                              self._evalua(args[i + 1:])])
        if len(args) == 1:
            return args[0] != ""
        if len(args) == 2:
            return self._unario(args[0], args[1])
        if len(args) == 3:
            return self._binario(args[0], args[1], args[2])
        raise _ErrorTest

    def call(self) -> None:
        args = list(self.args)
        if self.NOMBRE == "[":
            if not args or args[-1] != "]":
                self.errorWrite("-bash: [: missing `]\'\n")
                self.exit_code = 2
                return
            args = args[:-1]
        try:
            self.exit_code = 0 if self._evalua(args) else 1
        except _ErrorTest:
            self.errorWrite("-bash: %s: too many arguments\n" % self.NOMBRE)
            self.exit_code = 2


class _ErrorTest(Exception):
    """Lo que test llama un error de uso: sale con 2, no con 1."""


class Command_bracket(Command_test):
    NOMBRE = "["


class Command_dobles(Command_test):
    """[[ ... ]], que es una PALABRA CLAVE de bash y no un comando.

    Contestaba "-bash: [[: command not found", que es lo que diria un shell
    que no es bash ---y el senuelo dice ser bash en el prompt, en los errores
    y en dpkg---. Dentro se admiten "&&" y "||", que en el "[" de toda la
    vida son otra cosa.
    """

    NOMBRE = "[["

    def call(self) -> None:
        args = list(self.args)
        if not args or args[-1] != "]]":
            self.errorWrite("-bash: syntax error near unexpected token "
                            "`;'\n")
            self.exit_code = 2
            return
        args = args[:-1]
        try:
            for marca, junta in (("||", any), ("&&", all)):
                if marca in args:
                    i = args.index(marca)
                    self.exit_code = 0 if junta(
                        [self._evalua(args[:i]),
                         self._evalua(args[i + 1:])]) else 1
                    return
            self.exit_code = 0 if self._evalua(args) else 1
        except _ErrorTest:
            self.errorWrite("-bash: [[: too many arguments\n")
            self.exit_code = 2


commands["test"] = Command_test
commands["/usr/bin/test"] = Command_test
commands["["] = Command_bracket
commands["/usr/bin/["] = Command_bracket
commands["[["] = Command_dobles


class Command_umask(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        if not args:
            self.write("0022\n")
        elif args[0] in ("-S",):
            self.write("u=rwx,g=rx,o=rx\n")
        # setting a mask: silent


commands["umask"] = Command_umask


class Command_times(HoneyPotCommand):
    def call(self) -> None:
        self.write("0m0.002s 0m0.001s\n0m0.000s 0m0.000s\n")


commands["times"] = Command_times


class Command_let(HoneyPotCommand):
    """Evalua aritmetica Y ASIGNA. Era un no-op que solo decia no imprimir.

    Aqui llega tambien lo que se escribio como "((i++))": el shell lo
    reescribe a "let" porque son lo mismo en bash, y asi la cuenta pasa por
    un comando de verdad en vez de por un caso especial del troceador.

    El codigo de salida es al reves de lo que parece: 0 si el ultimo valor NO
    es cero, y 1 si lo es. Por eso "let k=0" devuelve 1.
    """

    def call(self) -> None:
        from cowrie.shell.honeypot import ErrorAritmetico, evalua_sentencia

        if not self.args:
            self.errorWrite("-bash: let: expression expected\n")
            self.exit_code = 1
            return
        valor = 0
        for expresion in self.args:
            try:
                valor = evalua_sentencia(expresion, self.environ)
            except ErrorAritmetico as fallo:
                from cowrie.shell.honeypot import error_de_sintaxis

                mensaje = fallo.mensaje or error_de_sintaxis(expresion)
                # El nombre del que se queja es "((" cuando la orden se
                # escribio asi, no "let": el shell la reescribe, pero el
                # atacante no ha tecleado ningun let.
                quien = "((" if getattr(
                    self.protocol, "_arit_parentesis", False) else "let"
                self.errorWrite("-bash: %s: %s: %s\n"
                                % (quien, expresion, mensaje))
                self.exit_code = 1
                return
        self.exit_code = 0 if valor else 1


commands["let"] = Command_let


class Command_declare(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        # -p with no name, or no args: dump variables (approximate via environ)
        if not args or (len(args) == 1 and args[0] in ("-p", "-x")):
            for k, v in sorted(self.environ.items()):
                self.write(f'declare -x {k}="{v}"\n')
            return
        if "-f" in args or "-F" in args:
            return
        # assignments / attribute setting: silent
        return


commands["declare"] = Command_declare
commands["typeset"] = Command_declare
commands["readonly"] = Command_declare


def _relanzar(cmd, linea: str) -> None:
    """Ejecuta `linea` como si la hubiera tecleado el atacante.

    Se usa para "eval", "command" y "builtin", que son las tres formas de
    decir "ejecuta esto otro". Antes las tres se quedaban CALLADAS ---el
    comentario del codigo lo daba por bueno diciendo que los bots casi no las
    usan--- y "eval echo hola" no imprimia nada, que es peor que un error:
    el guion sigue creyendo que hizo algo.

    Va por la misma maquinaria que un parentesis, asi que cada orden de
    dentro pasa por su comando emulado y queda registrada en el log.
    """
    if not linea.strip():
        return
    # LA RANURA SE GUARDA Y SE DEVUELVE. protocol.pp es una sola, y ejecutar
    # algo por dentro la deja apuntando al comando de DENTRO. Al volver, la
    # tuberia de fuera ya no encontraba la suya y se perdia la salida entera:
    #
    #     eval echo hola | cat      -> no imprimia nada
    #
    # Pasaba igual con nice, timeout, setarch, env y time, que relanzan por
    # aqui. Es el mismo fallo de reentrada que ya se corrigio una vez en
    # resume(), y por el mismo motivo: una ranura compartida.
    pp_de_fuera = getattr(cmd.protocol, "pp", None)
    try:
        shell = cmd.protocol.cmdstack[-2]
        salida = shell._execute_subshell_with_full_output(linea)
    except Exception:                                          # noqa: BLE001
        cmd.protocol.pp = pp_de_fuera
        return
    finally:
        cmd.protocol.pp = pp_de_fuera
    if salida:
        cmd.write(salida)
    cmd.exit_code = getattr(shell, "_estado_subshell", 0)


class Command_eval(HoneyPotCommand):
    """eval: junta sus argumentos y los ejecuta."""

    resolve_args = False

    def call(self) -> None:
        _relanzar(self, " ".join(self.args))


commands["eval"] = Command_eval


class Command_command(HoneyPotCommand):
    resolve_args = False

    def call(self) -> None:
        args = list(self.args)
        verbose = False
        find = False
        rest = []
        for a in args:
            if a == "-v":
                find = True
            elif a == "-V":
                verbose = True
            elif a.startswith("-") and a != "-":
                continue
            else:
                rest.append(a)
        if not rest:
            return
        name = rest[0]
        if find or verbose:
            if name in BUILTINS:
                self.write(f"{name}\n" if find else f"{name} is a shell builtin\n")
            else:
                hit = _path_lookup(name, self.environ, self.fs)
                if hit:
                    self.write(f"{hit}\n" if find else f"{name} is {hit}\n")
                elif verbose:
                    self.errorWrite(f"-bash: command: {name}: not found\n")
            return
        # Y si no se pide "-v" ni "-V", "command X args" EJECUTA X. Antes no
        # hacia nada: el comentario decia que los bots casi no lo usan, pero
        # callarse no es no hacer nada ---el guion cree que lo hizo---.
        _relanzar(self, " ".join(rest))


commands["command"] = Command_command


class Command_builtin(HoneyPotCommand):
    def call(self) -> None:
        names = [a for a in self.args if not a.startswith("-")]
        if names and names[0] not in BUILTINS:
            self.errorWrite(f"-bash: builtin: {names[0]}: not a shell builtin\n")
            self.exit_code = 1
            return
        _relanzar(self, " ".join(names))


commands["builtin"] = Command_builtin


SHOPT_OPTS = [
    ("autocd", "off"), ("assoc_expand_once", "off"), ("cdable_vars", "off"),
    ("cdspell", "off"), ("checkhash", "off"), ("checkjobs", "off"),
    ("checkwinsize", "on"), ("cmdhist", "on"), ("compat31", "off"),
    ("compat32", "off"), ("compat40", "off"), ("compat41", "off"),
    ("compat42", "off"), ("compat43", "off"), ("compat44", "off"),
    ("complete_fullquote", "on"), ("direxpand", "off"), ("dirspell", "off"),
    ("dotglob", "off"), ("execfail", "off"), ("expand_aliases", "on"),
    ("extdebug", "off"), ("extglob", "off"), ("extquote", "on"),
    ("failglob", "off"), ("force_fignore", "on"), ("globasciiranges", "on"),
    ("globskipdots", "on"), ("globstar", "off"), ("gnu_errfmt", "off"),
    ("histappend", "on"), ("histreedit", "off"), ("histverify", "off"),
    ("hostcomplete", "on"), ("huponexit", "off"), ("inherit_errexit", "off"),
    ("interactive_comments", "on"), ("lastpipe", "off"), ("lithist", "off"),
    ("localvar_inherit", "off"), ("localvar_unset", "off"),
    ("login_shell", "on"), ("mailwarn", "off"), ("no_empty_cmd_completion", "off"),
    ("nocaseglob", "off"), ("nocasematch", "off"), ("noexpand_translation", "off"),
    ("nullglob", "off"), ("patsub_replacement", "on"), ("progcomp", "on"),
    ("progcomp_alias", "off"), ("promptvars", "on"), ("restricted_shell", "off"),
    ("shift_verbose", "off"), ("sourcepath", "on"), ("varredir_close", "off"),
    ("xpg_echo", "off"),
]


class Command_shopt(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        if "-s" in args and len([a for a in args if not a.startswith("-")]) == 0:
            for name, state in SHOPT_OPTS:
                if state == "on":
                    self.write(f"{name:<28}\ton\n")
            return
        if "-u" in args and len([a for a in args if not a.startswith("-")]) == 0:
            for name, state in SHOPT_OPTS:
                if state == "off":
                    self.write(f"{name:<28}\toff\n")
            return
        names = [a for a in args if not a.startswith("-")]
        if names:
            table = dict(SHOPT_OPTS)
            for n in names:
                if n in table:
                    self.write(f"{n:<28}\t{table[n]}\n")
                else:
                    self.errorWrite(f"-bash: shopt: {n}: invalid shell option name\n")
            return
        for name, state in SHOPT_OPTS:
            self.write(f"{name:<28}\t{state}\n")


commands["shopt"] = Command_shopt


class Command_read(HoneyPotCommand):
    """Lee UNA linea de la entrada y la reparte en variables.

    Antes se rendia siempre ---"non-interactive read hits EOF immediately"---
    y devolvia sin tocar nada. Eso vale cuando de verdad no hay entrada, pero
    no cuando la hay: un "read L < /etc/hostname" o un "cmd | read x" dejaban
    la variable vacia sin decir nada, y el guion seguia con un dato en blanco.

    El reparto es el mismo que usa el shell para "while read": el ultimo
    nombre se queda con lo que sobre, y con IFS vacio no se recorta nada.
    """

    def call(self) -> None:
        from cowrie.shell.honeypot import reparte_campos

        nombres, saltar = [], 0
        for i, arg in enumerate(self.args):
            if saltar:
                saltar -= 1
                continue
            if arg.startswith("-") and len(arg) > 1:
                # -p, -n, -t, -u, -d y -a llevan argumento; -r, -s y -e no.
                if arg[1] in "pntuda" and len(arg) == 2:
                    saltar = 1
                continue
            nombres.append(arg)

        datos = self.input_data
        if not datos:
            # Sin entrada: es el EOF de siempre, y ahi read devuelve 1.
            self.exit_code = 1
            return
        texto = datos.decode("utf-8", "replace")
        linea, sep, _resto = texto.partition("\n")
        ifs_vacio = self.environ.get("IFS") == ""
        for nombre, valor in reparte_campos(linea, nombres, ifs_vacio):
            self.environ[nombre] = valor
        if not sep:
            # La entrada se acabo sin salto de linea: read asigna igual pero
            # devuelve 1. Es lo que distingue el ultimo trozo de un fichero
            # sin salto final.
            self.exit_code = 1


commands["read"] = Command_read


class Command_noop(HoneyPotCommand):
    """Builtins that, invoked bare in this context, simply produce no output."""

    def call(self) -> None:
        return


# "history" NO va aqui. Estaba, y este modulo se carga DESPUES de base.py, asi
# que el no-op pisaba al Command_history de verdad ---que existe y funciona--- y
# "history" contestaba en blanco. Un shell que no recuerda ni una orden despues
# de veinte no lo hay, y es de lo primero que se mira al entrar en una maquina
# ajena, precisamente para ver que hacia el dueno.
#
# Es el mismo tropiezo que ya paso con "eval": dos registros del mismo nombre y
# gana el ultimo. Una prueba comprueba ahora que ningun no-op tape a un comando
# que si esta implementado.
for _b in ("disown", "wait", "compopt", "bind"):
    commands[_b] = Command_noop


class Command_jobs(HoneyPotCommand):
    def call(self) -> None:
        return  # no background jobs


commands["jobs"] = Command_jobs


class Command_fgbg(HoneyPotCommand):
    def call(self) -> None:
        self.errorWrite("-bash: fg: no job control\n")


commands["fg"] = Command_fgbg
commands["bg"] = Command_fgbg


class Command_dirs(HoneyPotCommand):
    def call(self) -> None:
        cwd = self.protocol.cwd
        home = "/home/" + self.protocol.user.username
        if cwd == home:
            cwd = "~"
        elif cwd.startswith(home + "/"):
            cwd = "~" + cwd[len(home):]
        self.write(f"{cwd}\n")


commands["dirs"] = Command_dirs


class Command_trap(HoneyPotCommand):
    def call(self) -> None:
        # `trap` / `trap -p` with no traps set: no output
        return


commands["trap"] = Command_trap


class Command_caller(HoneyPotCommand):
    def call(self) -> None:
        # `caller` outside a function/sourced file: exit 1, no output
        return


commands["caller"] = Command_caller


class Command_return(HoneyPotCommand):
    """Sale de la funcion con el codigo que se le diga.

    Se apoya en la misma bandera que "exit" dentro de un parentesis: vacia la
    cola del shell del grupo y avisa al bucle que lanza las ordenes de que no
    siga con las siguientes. Sin esto, un "f(){ [ -z \"$1\" ] && return 1;
    ...; }" seguia ejecutando el cuerpo entero despues de haber vuelto.
    """

    def call(self) -> None:
        if not getattr(self.protocol, "_en_funcion", 0):
            self.errorWrite(
                "-bash: return: can only `return' from a function or sourced script\n"
            )
            self.exit_code = 1
            return
        if self.args:
            try:
                self.exit_code = int(self.args[0]) & 0xFF
            except ValueError:
                self.errorWrite(
                    f"-bash: return: {self.args[0]}: numeric argument required\n")
                self.exit_code = 2
        else:
            padre = (self.protocol.cmdstack[-2]
                     if len(self.protocol.cmdstack) >= 2 else None)
            self.exit_code = getattr(self.protocol, "_estado_en_curso", 0) \
                if padre is not None else 0
        padre = (self.protocol.cmdstack[-2]
                 if len(self.protocol.cmdstack) >= 2 else None)
        if padre is not None:
            padre.cmdpending = []
            padre.lineas_de_guion = []
        self.protocol._salir_subshell = True


commands["return"] = Command_return


class Command_suspend(HoneyPotCommand):
    def call(self) -> None:
        self.errorWrite("-bash: suspend: cannot suspend a login shell\n")


commands["suspend"] = Command_suspend


class Command_mapfile(HoneyPotCommand):
    def call(self) -> None:
        # reads stdin into an array; at EOF nothing to do
        return


commands["mapfile"] = Command_mapfile
commands["readarray"] = Command_mapfile


class Command_compgen(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        if "-b" in args:
            for b in ENABLED_BUILTINS:
                self.write(f"{b}\n")
        elif "-k" in args:
            for k in sorted(KEYWORDS):
                self.write(f"{k}\n")


commands["compgen"] = Command_compgen


class Command_complete(HoneyPotCommand):
    def call(self) -> None:
        return  # no completions registered


commands["complete"] = Command_complete


class Command_getopts(HoneyPotCommand):
    def call(self) -> None:
        return


commands["getopts"] = Command_getopts


class Command_fc(HoneyPotCommand):
    def call(self) -> None:
        self.errorWrite("-bash: fc: history specification out of range\n")


commands["fc"] = Command_fc


def _su_pop_restore(protocol) -> bool:
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


class Command_logout(HoneyPotCommand):
    def call(self) -> None:
        if _su_pop_restore(self.protocol):
            return
        # logout terminates the login shell/session
        self.protocol.terminal.loseConnection()


commands["logout"] = Command_logout


class Command_source(HoneyPotCommand):
    def call(self) -> None:
        names = [a for a in self.args if not a.startswith("-")]
        if not names:
            self.errorWrite("-bash: source: filename argument required\n")
            self.errorWrite(
                "source: usage: source filename [arguments]\n"
            )
            return
        target = self.fs.resolve_path(names[0], self.protocol.cwd)
        if not self.fs.exists(target):
            self.errorWrite(
                f"-bash: source: {names[0]}: No such file or directory\n"
            )
            self.exit_code = 1
            return
        # Y SE EJECUTA. Antes el fichero se "sourceaba" en silencio, o sea que
        # no se ejecutaba nada: un guion que se parte en dos y hace
        # ". /tmp/comun.sh" perdia la mitad sin decirlo. Va por la misma
        # maquinaria que un parentesis, asi que cada orden de dentro pasa por
        # su comando emulado y queda registrada.
        try:
            texto = self.fs.file_contents(target).decode("utf-8", "replace")
        except Exception:                                      # noqa: BLE001
            return
        lineas = [l.strip() for l in texto.split("\n")]
        lineas = [l for l in lineas if l and not l.startswith("#")]
        _relanzar(self, "; ".join(lineas))


commands["source"] = Command_source
commands["."] = Command_source


class Command_exec(HoneyPotCommand):
    def call(self) -> None:
        names = [a for a in self.args if not a.startswith("-")]
        if not names:
            return
        if names[0] not in BUILTINS and not _path_lookup(
            names[0], self.environ, self.fs
        ):
            self.errorWrite(f"-bash: exec: {names[0]}: not found\n")


commands["exec"] = Command_exec


class _Salto(HoneyPotCommand):
    """La parte comun de "break" y "continue".

    Los dos contestaban "command not found", y eso dentro de un bucle que por
    lo demas funcionaba: el atacante veia su guion correr y quejarse a la vez.
    El bucle se ejecuta desenrollado ---una fila plana de ordenes---, asi que
    saltar es tirar de la cola hasta la marca que separa las vueltas, y esa
    marca la pone el desenrollador.

    Fuera de un bucle bash avisa y devuelve CERO, no uno: medido.
    """

    NOMBRE = ""

    def call(self) -> None:
        from cowrie.shell.honeypot import MARCA_FIN_BUCLE, MARCA_VUELTA

        # "break" solo para en el final del bucle; "continue" para tambien en
        # la vuelta siguiente, la que venga antes.
        marcas = MARCA_FIN_BUCLE if self.NOMBRE == "break" \
            else MARCA_VUELTA + MARCA_FIN_BUCLE
        shell = (self.protocol.cmdstack[-2]
                 if len(self.protocol.cmdstack) >= 2 else None)
        # Un "while" con la condicion evaluada no deja marcas por delante: se
        # reemite el solo en cada vuelta. Se pregunta aparte.
        if shell is not None and hasattr(shell, "en_while_evaluado") \
                and shell.en_while_evaluado():
            shell.corta_while(self.NOMBRE == "break")
            return
        if shell is None or not hasattr(shell, "salta_hasta") \
                or not shell.hay_bucle_pendiente(
                    MARCA_VUELTA + MARCA_FIN_BUCLE):
            # Fuera de un bucle bash avisa y devuelve CERO, no uno: medido.
            self.errorWrite(
                "-bash: %s: only meaningful in a `for', `while',"
                " or `until' loop\n" % self.NOMBRE)
            return
        shell.salta_hasta(marcas)


class Command_break(_Salto):
    NOMBRE = "break"


class Command_continue(_Salto):
    NOMBRE = "continue"


commands["break"] = Command_break
commands["continue"] = Command_continue


class Command_time(HoneyPotCommand):
    """La palabra clave "time" de bash.

    Contestaba "time: command not found", y eso no pasa en ningun bash: "time"
    no es un binario ---el de /usr/bin/time va en su propio paquete y aqui no
    esta instalado--- sino una PALABRA CLAVE del lenguaje, asi que funciona
    siempre, en cualquier shell, sin que haya nada en el disco. Decir que no
    se encuentra delata al interprete de una forma que no admite otra
    explicacion.

    El bloque va por la SALIDA DE ERROR, como en bash: por eso en
    "time algo | grep x" los tiempos se ven en pantalla y no se cuelan por la
    tuberia. Y lleva una linea en blanco delante. Medido con pseudo-terminal
    en configuracion regional C, que es la que ve una sesion del senuelo: con
    otra, los decimales van con coma.

    El tiempo es el que se tarda de verdad en ejecutar la orden emulada. Sale
    del orden de milisegundos, que es lo que sale en una maquina de verdad
    para lo que se suele cronometrar aqui.
    """

    resolve_args = False

    @staticmethod
    def _reloj(segundos: float) -> str:
        minutos, resto = divmod(segundos, 60)
        return "%dm%.3fs" % (int(minutos), resto)

    def call(self) -> None:
        import time as _t

        if not self.args:
            # "time" a secas cronometra una orden vacia: solo el bloque.
            self.errorWrite("\nreal\t0m0.000s\nuser\t0m0.000s\n"
                            "sys\t0m0.000s\n")
            return
        empezo = _t.monotonic()
        _relanzar(self, " ".join(self.args))
        tardo = _t.monotonic() - empezo
        self.errorWrite("\nreal\t%s\nuser\t%s\nsys\t0m0.000s\n"
                        % (self._reloj(tardo), self._reloj(tardo * 0.6)))


commands["time"] = Command_time


class Command_shift(HoneyPotCommand):
    """Corre los parametros posicionales N sitios a la izquierda.

    Era un no-op silencioso junto a disown y wait. Con "set --" funcionando,
    un "while [ $# -gt 0 ]; do ...; shift; done" ---el bucle de argumentos que
    lleva cualquier guion--- daria vueltas para siempre.
    """

    def call(self) -> None:
        cuantos = 1
        if self.args:
            try:
                cuantos = int(self.args[0])
            except ValueError:
                self.errorWrite(
                    f"-bash: shift: {self.args[0]}: numeric argument required\n")
                return
        posicionales = list(getattr(self.protocol, "posicionales", None) or [])
        if cuantos < 0 or cuantos > len(posicionales):
            # bash devuelve 1 y NO toca nada.
            self.exit_code = 1
            return
        self.protocol.posicionales = posicionales[cuantos:]


commands["shift"] = Command_shift


class Command_local(HoneyPotCommand):
    """Declara una variable que muere con la funcion.

    Contestaba SIEMPRE "can only be used in a function", tambien dentro de
    una, y ahi no se quedaba en el aviso: el cuerpo entero dejaba de servir
    para nada, porque la variable no llegaba a existir. Una funcion que
    empiece por "local" ---la mitad de las de cualquier guion--- no hacia
    nada.

    Los nombres se apuntan en el protocolo: quien lanzo la funcion los
    devuelve a su valor de antes al terminar, que es la parte que hace que
    sean locales de verdad.
    """

    def call(self) -> None:
        if not getattr(self.protocol, "_en_funcion", 0):
            self.errorWrite("-bash: local: can only be used in a function\n")
            self.exit_code = 1
            return
        locales = getattr(self.protocol, "_locales", None)
        if locales is None:
            locales = self.protocol._locales = []
        for arg in self.args:
            if arg.startswith("-"):
                continue
            nombre, sep, valor = arg.partition("=")
            if not nombre:
                continue
            locales.append(nombre)
            # "local x" sin valor deja la variable SIN DEFINIR, no vacia: un
            # ${x:-por_defecto} despues tiene que dar el por defecto.
            if sep:
                self.environ[nombre] = valor
            else:
                self.environ.pop(nombre, None)


commands["local"] = Command_local


class Command_pushd(HoneyPotCommand):
    def call(self) -> None:
        self.errorWrite("-bash: pushd: no other directory\n")


commands["pushd"] = Command_pushd


class Command_popd(HoneyPotCommand):
    def call(self) -> None:
        self.errorWrite("-bash: popd: directory stack empty\n")


commands["popd"] = Command_popd


class Command_alias(HoneyPotCommand):
    """alias.

    No existia: escribir "alias" no devolvia nada. Pero el ~/.bashrc que
    cualquiera puede abrir con un "cat" declara

        alias ls='ls --color=auto'

    dentro de su bloque de dircolors, asi que un "alias" vacio contradice al
    fichero. Comprobado con un bash -i leyendo ese mismo .bashrc.

    La tabla vive en el protocolo, o sea POR SESION, y la siembra el shell
    segun quien haya entrado: root no tiene ninguno, porque su /root/.bashrc
    de Debian trae esa parte comentada.
    """

    resolve_args = False

    def call(self) -> None:
        aliases = getattr(self.protocol, "aliases", None)
        if aliases is None:
            aliases = self.protocol.aliases = {}

        nombres = [a for a in self.args if a and not a.startswith("-")]
        if not nombres:
            for nombre in sorted(aliases):
                self.write("alias %s='%s'\n" % (nombre, aliases[nombre]))
            return

        for arg in nombres:
            if "=" in arg:
                nombre, valor = arg.split("=", 1)
                aliases[nombre] = valor.strip("'\"")
            elif arg in aliases:
                self.write("alias %s='%s'\n" % (arg, aliases[arg]))
            else:
                self.errorWrite("-bash: alias: %s: not found\n" % arg)


commands["alias"] = Command_alias


class Command_unalias(HoneyPotCommand):
    def call(self) -> None:
        names = [a for a in self.args if not a.startswith("-")]
        if "-a" in self.args:
            return
        if not names:
            self.errorWrite("unalias: usage: unalias [-a] name [name ...]\n")
            return
        for n in names:
            self.errorWrite(f"-bash: unalias: {n}: not found\n")


commands["unalias"] = Command_unalias


class Command_kill(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        if not args or "-l" in args:
            if "-l" in args:
                self.write(
                    " 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\t 5) SIGTRAP\n"
                    " 6) SIGABRT\t 7) SIGBUS\t 8) SIGFPE\t 9) SIGKILL\t10) SIGUSR1\n"
                    "11) SIGSEGV\t12) SIGUSR2\t13) SIGPIPE\t14) SIGALRM\t15) SIGTERM\n"
                )
                return
            self.errorWrite(
                "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n"
            )
            return
        # LA TABLA DE PROCESOS EXISTE, y hasta ahora kill no la miraba: decia
        # "No such process" de CUALQUIER pid, incluido el 1 y los que el "ps"
        # de al lado esta listando. Un "kill -0 682" que dice que sshd no
        # existe mientras "ps aux" lo ensena es una contradiccion de las que
        # se ven sin buscarlas.
        # La lista sale de DONDE LA SACA "ps", incluida su lista de reserva:
        # si kill y ps leyeran de sitios distintos podrian discrepar el dia
        # que falte el ps_command_output.json, que es justo el dia en que
        # nadie estaria mirando.
        vivos = set()
        try:
            from cowrie.commands.base import Command_ps
            procesos = getattr(self.protocol.user.server, "process", None)
            if procesos:
                vivos = {str(p.get("PID")) for p in procesos}
            else:
                vivos = {fila[1] for fila in Command_ps.RESERVA}
        except Exception:                                      # noqa: BLE001
            pass
        for a in args:
            if not a.lstrip("-").isdigit() or a.startswith("-"):
                continue
            if a in vivos:
                # Existe: kill no dice nada. Y no se mata de verdad, que la
                # tabla es la misma para toda la sesion y para la siguiente.
                continue
            self.errorWrite(f"-bash: kill: ({a}) - No such process\n")
            self.exit_code = 1


commands["kill"] = Command_kill
