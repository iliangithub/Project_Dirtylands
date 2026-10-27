# SPDX-FileCopyrightText: 2009-2011 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


"""
Filesystem related commands
"""

from __future__ import annotations

import copy
import getopt
import os.path
import re
from typing import TYPE_CHECKING

from twisted.python import log

from cowrie.shell import fs
from cowrie.commands.base import FallaAlAvisar, con_dueno_de_sesion
from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


# --- Enforcement de permisos de lectura (homes privados) --------------------
def _cowrie_perm_ok(node, uid: int, gid: int, want: str) -> bool:
    mode = node[fs.A_MODE]
    if uid == node[fs.A_UID]:
        bit = 0o400 if want == "r" else 0o100
    elif gid == node[fs.A_GID]:
        bit = 0o040 if want == "r" else 0o010
    else:
        bit = 0o004 if want == "r" else 0o001
    return bool(mode & bit)


def _cowrie_access_denied(fsobj, abspath: str, uid: int, gid: int, target_need) -> bool:
    if uid == 0:
        return False
    parts = [p for p in abspath.split("/") if p]
    cur = ""
    for i, part in enumerate(parts):
        cur = cur + "/" + part
        try:
            node = fsobj.getfile(cur, follow_symlinks=True)
        except Exception:
            return False
        if not node:
            return False
        need = target_need if i == len(parts) - 1 else "x"
        if need is None:
            continue
        if not _cowrie_perm_ok(node, uid, gid, need):
            return True
    return False


class Command_grep(FallaAlAvisar, HoneyPotCommand):
    """
    grep command.

    Dos cosas que faltaban y que un bot SI mira, porque el patron
    `grep -q X fichero && hacer-algo` es como averigua la arquitectura de la
    maquina antes de elegir que binario descargar:

      - `-q` no callaba: estaba en la lista de opciones que getopt acepta,
        pero luego no se miraba, asi que grep escupia las lineas que
        encontraba. Un `grep -q lm /proc/cpuinfo` soltaba el volcado entero de
        los flags de la CPU donde no debia salir ni un caracter.

      - el CODIGO DE SALIDA era siempre 0, encontrara o no. Con eso, el `&&`
        se cumple siempre y el `||` no se cumple nunca, asi que las dos ramas
        del bot van al sitio equivocado. Ahora es el de verdad: 0 si hubo
        alguna linea, 1 si no hubo ninguna, 2 si algun fichero no se pudo
        leer.
    """

    # grep no falla con 1 sino con 2 cuando el fallo es de fichero o de uso.
    CODIGO_DE_FALLO = 2

    def grep_get_contents(self, filename: str, match: str) -> None:
        if _cowrie_access_denied(
            self.fs, filename,
            getattr(self.protocol.user, "uid", 0),
            getattr(self.protocol.user, "gid", 0), "r",
        ):
            # -s calla los errores de fichero, no los resultados. Son dos
            # opciones distintas y se confunden con facilidad.
            if "s" not in getattr(self, "grep_flags", set()):
                self.errorWrite(f"grep: {filename}: Permission denied\n")
            self.grep_error = True
            return
        # UN DIRECTORIO SE DICE, y no se intenta leer. Sin esto caia por el
        # "except" de abajo y salia "No such file or directory" sobre algo que
        # existe y que el propio "ls" acababa de listar. Medido:
        #   grep: /tmp: Is a directory     (y sale con 2)
        if self.fs.isdir(filename):
            if "s" not in getattr(self, "grep_flags", set()):
                self.errorWrite(f"grep: {filename}: Is a directory\n")
            self.grep_error = True
            return
        try:
            contents = con_dueno_de_sesion(
                self, filename, self.fs.file_contents(filename))
            self.grep_application(contents, match, filename)
        except Exception:
            if "s" not in getattr(self, "grep_flags", set()):
                self.errorWrite(f"grep: {filename}: No such file or directory\n")
            self.grep_error = True

    def grep_application(self, contents: bytes, match: str, filename: str = "") -> None:
        flags = getattr(self, "grep_flags", set())
        pat = os.path.basename(match).replace('"', "")
        reflags = re.IGNORECASE if "i" in flags else 0
        if "w" in flags:
            pat = r"\b(?:%s)\b" % pat
        try:
            matches = re.compile(pat.encode("utf8"), reflags)
        except re.error:
            matches = re.compile(re.escape(pat.encode("utf8")), reflags)
        invert = "v" in flags
        contentsplit = contents.split(b"\n")
        if contentsplit and contentsplit[-1] == b"":
            contentsplit = contentsplit[:-1]
        prefix = (
            (filename + ":").encode("utf8")
            if filename and getattr(self, "grep_multi", False)
            else b""
        )
        count = 0
        out: list[bytes] = []
        # "-o" escribe CADA COINCIDENCIA en su linea, no la linea entera.
        # Antes se aceptaba la opcion y se escribia la linea igual, asi que un
        # "grep -o patron | wc -l" contaba lineas donde tenia que contar
        # coincidencias: dos apariciones en la misma linea salian como una.
        solo = "o" in flags and not invert
        for idx, line in enumerate(contentsplit, 1):
            if solo:
                hallados = list(matches.finditer(line))
                if not hallados:
                    continue
                # "-c" sigue contando LINEAS aunque haya "-o": un "grep -oc a"
                # sobre "aa" dice 1, no 2. Medido.
                count += 1
                if "l" in flags:
                    continue
                for m in hallados:
                    nprefix = ((str(idx) + ":").encode("utf8")
                               if "n" in flags else b"")
                    out.append(prefix + nprefix + m.group(0) + b"\n")
                continue
            if bool(matches.search(line)) != invert:
                count += 1
                if "l" in flags:
                    continue
                nprefix = (str(idx) + ":").encode("utf8") if "n" in flags else b""
                out.append(prefix + nprefix + line + b"\n")
        if count:
            self.grep_encontrado = True
        # -q: solo importa el codigo de salida. Se sale ANTES de cualquier
        # escritura, incluida la de -c y la de -l: en grep de verdad, -q gana
        # a todas y no imprime nada.
        if "q" in flags:
            return
        if "l" in flags:
            if count:
                self.writeBytes((filename + "\n").encode("utf8"))
            return
        if "c" in flags:
            self.writeBytes(prefix + str(count).encode("utf8") + b"\n")
            return
        for o in out:
            self.writeBytes(o)

    def help(self) -> None:
        """El uso de GNU grep, no el de BSD.

        Lo que habia ---"usage: grep [-abcDEFGHhIiJLlmnOoPqRSsUVvwxZ]..."---
        es el de macOS y los BSD, con sus tabuladores y su lista de letras. El
        de Debian son dos lineas y ninguna se parece. Medido en un trixie 13.6
        con grep 3.11, que es el que declara nuestro dpkg.
        """
        self.errorWrite("Usage: grep [OPTION]... PATTERNS [FILE]...\n")
        self.errorWrite("Try 'grep --help' for more information.\n")
        self.exit_code = 2

    def start(self) -> None:
        if not self.args:
            self.help()
            self.exit()
            return

        self.n = 10
        optlist: list[tuple[str, str]] = []
        args = self.args
        if self.args[0] == ">":
            pass
        else:
            try:
                optlist, args = getopt.getopt(
                    self.args,
                    "abcDEFGHhIiJLlmnOoPqRSsUVvwxZA:B:C:e:f:",
                    [
                        "binary-files=",
                        "color=",
                        "color",
                        "context=",
                        "directories=",
                        "label",
                        "line-buffered",
                    ],
                )
            except getopt.GetoptError as err:
                self.errorWrite(f"grep: invalid option -- {err.opt}\n")
                self.help()
                self.exit()
                return

            grep_opts = {"-c", "-n", "-v", "-i", "-w", "-l", "-q", "-s",
                         "-o"}
            self.grep_flags = {o.lstrip("-") for o, _ in optlist if o in grep_opts}
            for opt, _arg in optlist:
                if opt == "-h":
                    self.help()

        self.grep_encontrado = False
        self.grep_error = False
        if not self.input_data:
            files = self.check_arguments("grep", args[1:])
            self.grep_multi = len(files) > 1
            for pname in files:
                self.grep_get_contents(pname, args[0])
        else:
            self.grep_multi = False
            self.grep_application(self.input_data, args[0])

        # El mismo criterio que grep(1): 0 hubo linea, 1 no hubo ninguna,
        # 2 algo no se pudo leer. El 2 manda sobre el 1.
        if self.grep_error:
            self.exit(2)
        else:
            self.exit(0 if self.grep_encontrado else 1)

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="grep",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def eofReceived(self) -> None:
        self.exit()


commands["/bin/grep"] = Command_grep
commands["grep"] = Command_grep
commands["/bin/egrep"] = Command_grep
commands["/bin/fgrep"] = Command_grep


class Command_tail(FallaAlAvisar, HoneyPotCommand):
    """
    tail command
    """

    n: int = 10

    def tail_get_contents(self, filename: str) -> None:
        if _cowrie_access_denied(
            self.fs, filename,
            getattr(self.protocol.user, "uid", 0),
            getattr(self.protocol.user, "gid", 0), "r",
        ):
            self.errorWrite(
                f"tail: cannot open '{filename}' for reading: Permission denied\n"
            )
            return
        try:
            contents = con_dueno_de_sesion(
                self, filename, self.fs.file_contents(filename))
            self.tail_application(contents)
        except Exception:
            self.errorWrite(
                f"tail: cannot open '{filename}' for reading: No such file or directory\n"
            )

    def tail_application(self, contents: bytes) -> None:
        contentsplit = contents.split(b"\n")
        lines = len(contentsplit)
        if lines < self.n:
            self.n = lines - 1
        i = 0
        for j in range((lines - self.n - 1), lines):
            self.writeBytes(contentsplit[j])
            if i < self.n:
                self.write("\n")
            i += 1

    def start(self) -> None:
        if not self.args or self.args[0] == ">":
            return
        else:
            try:
                pre_args: list[str] = []
                for a in self.args:
                    m = re.fullmatch(r"-(\d+)", a)
                    if m:
                        pre_args += ["-n", m.group(1)]
                    else:
                        pre_args.append(a)
                optlist, args = getopt.getopt(pre_args, "n:")
            except getopt.GetoptError as err:
                self.errorWrite(f"tail: invalid option -- '{err.opt}'\n")
                self.exit()
                return

            for opt in optlist:
                if opt[0] == "-n":
                    if not opt[1].isdigit():
                        # "illegal offset" es de otro tail. El de coreutils
                        # dice lo mismo que head ---"invalid number of
                        # lines"--- y ADEMAS no imprime nada; este avisaba y
                        # volcaba el fichero entero detras.
                        self.errorWrite(
                            f"tail: invalid number of lines: '{opt[1]}'\n")
                        self.exit()
                        return
                    self.n = int(opt[1])
        if not self.input_data:
            files = self.check_arguments("tail", args)
            for pname in files:
                self.tail_get_contents(pname)
        else:
            self.tail_application(self.input_data)

        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="tail",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def eofReceived(self) -> None:
        self.exit()


commands["/bin/tail"] = Command_tail
commands["/usr/bin/tail"] = Command_tail
commands["tail"] = Command_tail


class Command_head(FallaAlAvisar, HoneyPotCommand):
    """
    head command
    """

    linecount: int = 10
    bytecount: int = 0

    def head_application(self, contents: bytes) -> None:
        if self.bytecount:
            self.writeBytes(contents[: self.bytecount])
            return
        if not self.linecount:
            return
        # EL SALTO FINAL NO ABRE UNA LINEA MAS. Se partia por "\n" y se
        # escribia un "\n" detras de cada trozo, incluido el trozo VACIO que
        # deja el salto del final: cada salida de head llevaba una linea en
        # blanco de mas, y un "head -2 fichero | wc -l" sobre un fichero de
        # una linea contestaba 2.
        lineas = contents.split(b"\n")
        acaba_sin_salto = bool(lineas) and lineas[-1] != b""
        if not acaba_sin_salto:
            lineas.pop()
        elegidas = lineas[: self.linecount]
        for i, linea in enumerate(elegidas):
            # Solo la ULTIMA linea del fichero puede ir sin salto, y solo si
            # el fichero no acababa en uno.
            ultima_del_fichero = (acaba_sin_salto
                                  and i == len(elegidas) - 1
                                  and len(lineas) <= self.linecount)
            self.writeBytes(linea if ultima_del_fichero else linea + b"\n")

    def head_get_file_contents(self, filename: str) -> None:
        if _cowrie_access_denied(
            self.fs, filename,
            getattr(self.protocol.user, "uid", 0),
            getattr(self.protocol.user, "gid", 0), "r",
        ):
            self.errorWrite(
                f"head: cannot open '{filename}' for reading: Permission denied\n"
            )
            return
        try:
            contents = con_dueno_de_sesion(
                self, filename, self.fs.file_contents(filename))
            self.head_application(contents)
        except fs.FileNotFound:
            self.errorWrite(
                f"head: cannot open '{filename}' for reading: No such file or directory\n"
            )

    def start(self) -> None:
        self.lines: int = 10
        self.bytecount: int = 0
        if not self.args or self.args[0] == ">":
            return
        else:
            # Accept GNU legacy `head -N` (== `head -n N`)
            pre_args: list[str] = []
            for a in self.args:
                m = re.fullmatch(r"-(\d+)", a)
                if m:
                    pre_args += ["-n", m.group(1)]
                else:
                    pre_args.append(a)
            try:
                optlist, args = getopt.getopt(pre_args, "c:n:")
            except getopt.GetoptError as err:
                self.errorWrite(f"head: invalid option -- '{err.opt}'\n")
                self.exit()
                return

            for opt in optlist:
                if opt[0] == "-n":
                    if not opt[1].isdigit():
                        # AVISABA Y SEGUIA. Escribia el error y a continuacion
                        # VOLCABA EL FICHERO ENTERO, que es justo lo que el de
                        # verdad no hace: con un numero que no es un numero,
                        # head no imprime nada.
                        self.errorWrite(f"head: invalid number of lines: '{opt[1]}'\n")
                        self.exit()
                        return
                    self.linecount = int(opt[1])
                    self.bytecount = 0
                elif opt[0] == "-c":
                    if not opt[1].isdigit():
                        self.errorWrite(f"head: invalid number of bytes: '{opt[1]}'\n")
                        self.exit()
                        return
                    self.bytecount = int(opt[1])
                    self.linecount = 0

        if not self.input_data:
            files = self.check_arguments("head", args)
            for pname in files:
                self.head_get_file_contents(pname)
        else:
            self.head_application(self.input_data)
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="head",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def eofReceived(self) -> None:
        self.exit()


commands["/bin/head"] = Command_head
commands["/usr/bin/head"] = Command_head
commands["head"] = Command_head


class Command_cd(FallaAlAvisar, HoneyPotCommand):
    """
    cd command
    """

    def call(self) -> None:
        # "cd -L" y "cd -P" son opciones, no destinos. Sin esto un
        # "cd -P /etc" se iba a buscar un directorio llamado "-P".
        args = list(self.args)
        while args and args[0] in ("-L", "-P", "-e", "-@"):
            args.pop(0)
        # Y DOS DESTINOS SON UN ERROR DE USO. bash no hace la sustitucion de
        # ksh ---"cd viejo nuevo"---: se planta. Aqui se cogia el primero y
        # se tiraba el resto, asi que un "cd ignis api" ---lo que deja un
        # tabulador que no escapa el espacio--- contestaba "cd: ignis: No
        # such file or directory" en vez de lo que contesta bash, y el
        # atacante se queda pensando que el directorio no existe.
        if len(args) > 1:
            self.errorWrite("-bash: cd: too many arguments\n")
            return
        if not args or args[0] == "~":
            pname = self.protocol.user.avatar.home
        else:
            pname = args[0]
        newpath = ""
        try:
            newpath = self.fs.resolve_path(pname, self.protocol.cwd)
            inode = self.fs.getfile(newpath)
        except Exception:
            inode = None
        if pname == "-":
            self.errorWrite("-bash: cd: OLDPWD not set\n")
            return
        if inode is None or inode is False:
            self.errorWrite(f"-bash: cd: {pname}: No such file or directory\n")
            return
        if inode[fs.A_TYPE] != fs.T_DIR:
            self.errorWrite(f"-bash: cd: {pname}: Not a directory\n")
            return
        if _cowrie_access_denied(
            self.fs, newpath,
            getattr(self.protocol.user, "uid", 0),
            getattr(self.protocol.user, "gid", 0), "x",
        ):
            self.errorWrite(f"-bash: cd: {pname}: Permission denied\n")
            return
        self.protocol.cwd = newpath


commands["cd"] = Command_cd


class Command_rm(FallaAlAvisar, HoneyPotCommand):
    """
    rm command
    """

    def help(self) -> None:
        self.write(
            """Usage: rm [OPTION]... [FILE]...
Remove (unlink) the FILE(s).

 -f, --force           ignore nonexistent files and arguments, never prompt
 -i                    prompt before every removal
 -I                    prompt once before removing more than three files, or
                         when removing recursively; less intrusive than -i,
                         while still giving protection against most mistakes
      --interactive[=WHEN]  prompt according to WHEN: never, once (-I), or
                         always (-i); without WHEN, prompt always
      --one-file-system  when removing a hierarchy recursively, skip any
                         directory that is on a file system different from
                         that of the corresponding command line argument
      --no-preserve-root  do not treat '/' specially
      --preserve-root   do not remove '/' (default)
 -r, -R, --recursive   remove directories and their contents recursively
 -d, --dir             remove empty directories
 -v, --verbose         explain what is being done
     --help     display this help and exit
     --version  output version information and exit

By default, rm does not remove directories.  Use the --recursive (-r or -R)
option to remove each listed directory, too, along with all of its contents.

To remove a file whose name starts with a '-', for example '-foo',
use one of these commands:
 rm -- -foo

 rm ./-foo

Note that if you use rm to remove a file, it might be possible to recover
some of its contents, given sufficient expertise and/or time.  For greater
assurance that the contents are truly unrecoverable, consider using shred.

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/rm>
or available locally via: info '(coreutils) rm invocation'\n"""
        )

    def paramError(self) -> None:
        self.errorWrite("Try 'rm --help' for more information\n")

    def call(self) -> None:
        recursive = False
        force = False
        verbose = False
        if not self.args:
            self.errorWrite("rm: missing operand\n")
            self.paramError()
            return

        try:
            optlist, args = getopt.gnu_getopt(
                self.args, "rTfvh", ["help", "recursive", "force", "verbose"]
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"rm: invalid option -- '{err.opt}'\n")
            self.paramError()
            self.exit()
            return

        for o, _a in optlist:
            if o in ("--recursive", "-r", "-R"):
                recursive = True
            elif o in ("--force", "-f"):
                force = True
            elif o in ("--verbose", "-v"):
                verbose = True
            elif o in ("--help", "-h"):
                self.help()
                return

        for f in args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                # verify path to file exists
                directory = self.fs.get_path("/".join(pname.split("/")[:-1]))
                # verify that the file itself exists
                self.fs.get_path(pname)
            except (IndexError, fs.FileNotFound):
                if not force:
                    self.errorWrite(
                        f"rm: cannot remove '{f}': No such file or directory\n"
                    )
                continue
            basename = pname.split("/")[-1]
            for i in directory[:]:
                if i[fs.A_NAME] == basename:
                    if i[fs.A_TYPE] == fs.T_DIR and not recursive:
                        self.errorWrite(
                            f"rm: cannot remove '{i[fs.A_NAME]}': Is a directory\n"
                        )
                    else:
                        directory.remove(i)
                        if verbose:
                            if i[fs.A_TYPE] == fs.T_DIR:
                                self.write(f"removed directory '{i[fs.A_NAME]}'\n")
                            else:
                                self.write(f"removed '{i[fs.A_NAME]}'\n")


commands["/bin/rm"] = Command_rm
commands["rm"] = Command_rm


class Command_cp(FallaAlAvisar, HoneyPotCommand):
    """
    cp command
    """

    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("cp: missing file operand\n")
            self.errorWrite("Try 'cp --help' for more information.\n")
            return
        try:
            optlist, args = getopt.gnu_getopt(self.args, "-abdfiHlLPpRrsStTuvx")
        except getopt.GetoptError:
            self.errorWrite("Unrecognized option\n")
            return
        recursive = False
        for opt in optlist:
            if opt[0] in ("-r", "-a", "-R"):
                recursive = True

        def resolv(pname: str) -> str:
            rsv: str = self.fs.resolve_path(pname, self.protocol.cwd)
            return rsv

        if len(args) < 2:
            self.errorWrite(
                f"cp: missing destination file operand after '{self.args[0]}'\n"
            )
            self.errorWrite("Try 'cp --help' for more information.\n")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.errorWrite(f"cp: target '{dest}' is not a directory\n")
            return

        if dest[-1] == "/" and not self.fs.exists(resolv(dest)) and not recursive:
            self.errorWrite(
                f"cp: cannot create regular file '{dest}': Is a directory\n"
            )
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.errorWrite(
                    "cp: cannot create regular file "
                    + f"'{dest}': No such file or directory\n"
                )
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.errorWrite(f"cp: cannot stat '{src}': No such file or directory\n")
                continue
            if not recursive and self.fs.isdir(resolv(src)):
                # Texto y comillas de coreutils en Debian 13.
                self.errorWrite(
                    f"cp: -r not specified; omitting directory '{src}'\n")
                continue
            s = copy.deepcopy(self.fs.getfile(resolv(src)))
            if isdir:
                directory = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                directory = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest.rstrip("/"))
            if outfile in [x[fs.A_NAME] for x in directory]:
                directory.remove(next(x for x in directory if x[fs.A_NAME] == outfile))
            s[fs.A_NAME] = outfile
            directory.append(s)


commands["/bin/cp"] = Command_cp
commands["cp"] = Command_cp


class Command_mv(FallaAlAvisar, HoneyPotCommand):
    """
    mv command
    """

    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("mv: missing file operand\n")
            self.errorWrite("Try 'mv --help' for more information.\n")
            return

        try:
            _optlist, args = getopt.gnu_getopt(self.args, "-bfiStTuv")
        except getopt.GetoptError:
            self.errorWrite("Unrecognized option\n")
            return

        def resolv(pname: str) -> str:
            rsv: str = self.fs.resolve_path(pname, self.protocol.cwd)
            return rsv

        if len(args) < 2:
            self.errorWrite(
                f"mv: missing destination file operand after '{self.args[0]}'\n"
            )
            self.errorWrite("Try 'mv --help' for more information.\n")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.errorWrite(f"mv: target '{dest}' is not a directory\n")
            return

        if dest[-1] == "/" and not self.fs.exists(resolv(dest)) and len(sources) != 1:
            self.errorWrite(
                f"mv: cannot create regular file '{dest}': Is a directory\n"
            )
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.errorWrite(
                    "mv: cannot create regular file "
                    + f"'{dest}': No such file or directory\n"
                )
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.errorWrite(f"mv: cannot stat '{src}': No such file or directory\n")
                continue
            s = self.fs.getfile(resolv(src))
            if isdir:
                directory = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                directory = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest)
            if directory != os.path.dirname(resolv(src)):
                s[fs.A_NAME] = outfile
                directory.append(s)
                sdir = self.fs.get_path(os.path.dirname(resolv(src)))
                sdir.remove(s)
            else:
                s[fs.A_NAME] = outfile


commands["/bin/mv"] = Command_mv
commands["mv"] = Command_mv


class Command_mkdir(FallaAlAvisar, HoneyPotCommand):
    """mkdir.

    Tenia tres fallos, y el primero se nota en casi cualquier dropper:

      1. "-p" no se leia: entraba en el bucle como si fuera un nombre de
         directorio. Y como el "return" estaba DENTRO del bucle, la primera
         vuelta se lo comia y el directorio de verdad no se creaba nunca.
         O sea que "mkdir -p .oculto" no creaba nada y no decia nada, y el
         "echo x > .oculto/bin" de la linea siguiente fallaba sin explicacion.
      2. Por ese mismo "return", "mkdir a b c" solo creaba "a".
      3. El mensaje llevaba comilla invertida ---`x'--- que es de coreutils
         antiguo. Desde hace anos son dos comillas rectas: 'x'.

    Comprobado contra coreutils en Debian 13.
    """

    def call(self) -> None:
        crear_padres = False
        nombres = []
        for a in self.args:
            if a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                if "p" in a[1:]:
                    crear_padres = True
            elif a == "--parents":
                crear_padres = True
            elif not a.startswith("-"):
                nombres.append(a)

        if not nombres:
            self.errorWrite("mkdir: missing operand\n")
            self.errorWrite("Try 'mkdir --help' for more information.\n")
            return

        for f in nombres:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            if self.fs.exists(pname):
                # Con -p, que ya exista NO es un error: es justamente lo que
                # -p promete.
                if not crear_padres:
                    self.errorWrite(
                        "mkdir: cannot create directory '%s': File exists\n" % f)
                continue

            if crear_padres:
                # Se crea la cadena entera, de arriba abajo.
                acumulado = "" if pname.startswith("/") else self.protocol.cwd
                for parte in [p for p in pname.split("/") if p]:
                    acumulado = acumulado.rstrip("/") + "/" + parte
                    if self.fs.exists(acumulado):
                        continue
                    try:
                        self.fs.mkdir(acumulado, self.protocol.user.uid,
                                      self.protocol.user.gid, 4096, 16877)
                    except (fs.FileNotFound, OSError):
                        # TAMBIEN LA DE PYTHON. El sistema de ficheros de
                        # Cowrie deja escapar un FileNotFoundError cuando
                        # falta el padre, y ese no lo cazaba nadie: un
                        # "mkdir /noexiste/x" no daba error, TUMBABA LA SESION.
                        self.errorWrite(
                            "mkdir: cannot create directory '%s': "
                            "No such file or directory\n" % f)
                        break
                continue

            try:
                self.fs.mkdir(
                    pname, self.protocol.user.uid, self.protocol.user.gid, 4096, 16877
                )
            except (fs.FileNotFound, OSError):
                self.errorWrite(
                    "mkdir: cannot create directory '%s': "
                    "No such file or directory\n" % f)


commands["/bin/mkdir"] = Command_mkdir
commands["mkdir"] = Command_mkdir


class Command_rmdir(FallaAlAvisar, HoneyPotCommand):
    """
    rmdir command
    """

    def call(self) -> None:
        for f in self.args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                if len(self.fs.get_path(pname)):
                    self.errorWrite(
                        f"rmdir: failed to remove '{f}': Directory not empty\n"
                    )
                    continue
                directory = self.fs.get_path("/".join(pname.split("/")[:-1]))
            except (IndexError, fs.FileNotFound):
                directory = None
            fname = os.path.basename(f)
            if not directory or fname not in [x[fs.A_NAME] for x in directory]:
                self.errorWrite(
                    f"rmdir: failed to remove '{f}': No such file or directory\n"
                )
                continue
            for i in directory[:]:
                if i[fs.A_NAME] == fname:
                    if i[fs.A_TYPE] != fs.T_DIR:
                        self.errorWrite(
                            f"rmdir: failed to remove '{f}': Not a directory\n"
                        )
                        return
                    directory.remove(i)
                    break


commands["/bin/rmdir"] = Command_rmdir
commands["rmdir"] = Command_rmdir


class Command_pwd(HoneyPotCommand):
    """
    pwd command
    """

    def call(self) -> None:
        self.write(self.protocol.cwd + "\n")


commands["/bin/pwd"] = Command_pwd
commands["pwd"] = Command_pwd


class Command_touch(FallaAlAvisar, HoneyPotCommand):
    """
    touch command
    """

    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("touch: missing file operand\n")
            self.errorWrite("Try 'touch --help' for more information.\n")
            return
        for f in self.args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            if not self.fs.exists(os.path.dirname(pname)):
                self.errorWrite(
                    f"touch: cannot touch '{pname}': No such file or directory\n"
                )
                return
            if self.fs.exists(pname):
                # FIXME: modify the timestamp here
                continue
            # can't touch in special directories
            if any([pname.startswith(_p) for _p in fs.SPECIAL_PATHS]):
                self.errorWrite(f"touch: cannot touch '{pname}': Permission denied\n")
                return

            self.fs.mkfile(
                pname, self.protocol.user.uid, self.protocol.user.gid, 0, 33188
            )


commands["/bin/touch"] = Command_touch
commands["touch"] = Command_touch
commands[">"] = Command_touch


class Command_less(FallaAlAvisar, HoneyPotCommand):
    """less (pager): vuelca el contenido del fichero; respeta permisos."""

    def _vuelca(self, paginador, texto, nombre):
        return paginador.vuelca_less(self, texto, nombre)

    paginando = False

    def _pagina(self, trozos, nombre):
        """Devuelve True si el paginador se ha quedado con el terminal.

        Se junta todo y se pagina UNA vez. Con varios ficheros el de verdad
        los ensena de uno en uno; aqui van seguidos, que es lo que ya hacia
        antes de que esto existiera y no contradice a nada.
        """
        crudo = b"".join(trozos)
        if not crudo:
            return False
        try:
            from cowrie.commands import paginador
        except ImportError:                                    # noqa: BLE001
            paginador = None
        if paginador is not None and self._vuelca(
                paginador, crudo.decode("utf-8", "replace"), nombre):
            self.paginando = True
            return True
        # Sin paginar se escriben los BYTES, no el texto: decodificar aqui
        # estropearia un fichero binario, que es justo lo que se abre con
        # less para ver si una descarga trajo un ELF.
        self.writeBytes(crudo)
        return True

    def start(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        if not args:
            if self.input_data:
                self._pagina([self.input_data], "")
                if self.paginando:
                    return
            self.exit()
            return
        uid = getattr(self.protocol.user, "uid", 0)
        gid = getattr(self.protocol.user, "gid", 0)
        trozos = []
        for arg in args:
            pname = self.fs.resolve_path(arg, self.protocol.cwd)
            if _cowrie_access_denied(self.fs, pname, uid, gid, "r"):
                self.errorWrite(f"{arg}: Permission denied\n")
                continue
            if self.fs.isdir(pname):
                self.errorWrite(f"{arg} is a directory\n")
                continue
            try:
                trozos.append(con_dueno_de_sesion(
                    self, pname, self.fs.file_contents(pname)))
            except Exception:
                self.errorWrite(f"{arg}: No such file or directory\n")
        if self._pagina(trozos, args[0]) and self.paginando:
            return
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input", realm="less", input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def eofReceived(self) -> None:
        self.exit()


commands["less"] = Command_less
commands["/bin/less"] = Command_less
commands["/usr/bin/less"] = Command_less
commands["/usr/bin/pager"] = Command_less


class Command_more(HoneyPotCommand):
    """more (pager): igual que less, con los mensajes de error de util-linux more."""

    def _vuelca(self, paginador, texto, nombre):
        return paginador.vuelca_more(self, texto)

    paginando = False

    def _pagina(self, trozos, nombre):
        """Devuelve True si el paginador se ha quedado con el terminal.

        Se junta todo y se pagina UNA vez. Con varios ficheros el de verdad
        los ensena de uno en uno; aqui van seguidos, que es lo que ya hacia
        antes de que esto existiera y no contradice a nada.
        """
        crudo = b"".join(trozos)
        if not crudo:
            return False
        try:
            from cowrie.commands import paginador
        except ImportError:                                    # noqa: BLE001
            paginador = None
        if paginador is not None and self._vuelca(
                paginador, crudo.decode("utf-8", "replace"), nombre):
            self.paginando = True
            return True
        # Sin paginar se escriben los BYTES, no el texto: decodificar aqui
        # estropearia un fichero binario, que es justo lo que se abre con
        # less para ver si una descarga trajo un ELF.
        self.writeBytes(crudo)
        return True

    def start(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        if not args:
            if self.input_data:
                self._pagina([self.input_data], "")
                if self.paginando:
                    return
            self.exit()
            return
        uid = getattr(self.protocol.user, "uid", 0)
        gid = getattr(self.protocol.user, "gid", 0)
        trozos = []
        for arg in args:
            pname = self.fs.resolve_path(arg, self.protocol.cwd)
            if _cowrie_access_denied(self.fs, pname, uid, gid, "r"):
                self.errorWrite(f"more: cannot open {arg}: Permission denied\n")
                continue
            if self.fs.isdir(pname):
                self.errorWrite(f"more: {arg}: is a directory\n")
                continue
            try:
                trozos.append(con_dueno_de_sesion(
                    self, pname, self.fs.file_contents(pname)))
            except Exception:
                self.errorWrite(f"more: cannot open {arg}: No such file or directory\n")
        if self._pagina(trozos, args[0]) and self.paginando:
            return
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input", realm="more", input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def eofReceived(self) -> None:
        self.exit()


commands["more"] = Command_more
commands["/bin/more"] = Command_more
commands["/usr/bin/more"] = Command_more
